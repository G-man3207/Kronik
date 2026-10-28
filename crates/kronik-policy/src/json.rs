//! The diff as CEL values: a view of the `serde_json::Value` that borrows its
//! strings and objects rather than copying them.
//!
//! JSON integers become `int` (`uint` above `i64::MAX`), other numbers
//! `double`, strings `string`, booleans `bool`, `null` `null`, arrays `list`
//! and objects `map`. An object iterates its keys in the order of the JSON
//! object, `serde_json::Map`, so comprehensions over it are deterministic:
//! CEL's own maps iterate in hash order, which changes from one evaluation to
//! the next (ADR 0007).

use cel::ExecutionError;
use cel::common::traits::{self, Container, Indexer, Iterable, Sizer, Zeroer};
use cel::common::types::{
    self, CelBool, CelDouble, CelInt, CelList, CelNull, CelString, CelUInt, Kind, Type,
};
use cel::common::value::{CowVal, Val};
use serde_json::{Map, Number, Value};
use std::sync::OnceLock;

/// `value` as a CEL value that borrows from it.
pub(crate) fn to_val<'v>(value: &'v Value) -> Box<dyn Val + 'v> {
    match value {
        Value::Null => Box::new(CelNull),
        Value::Bool(b) => Box::new(CelBool::from(*b)),
        Value::Number(n) => number(n),
        Value::String(s) => Box::new(CelString::from(s.as_str())),
        Value::Array(items) => {
            Box::new(CelList::from(items.iter().map(to_val).collect::<Vec<_>>()))
        }
        Value::Object(map) => Box::new(JsonMap::new(map)),
    }
}

fn number(n: &Number) -> Box<dyn Val> {
    if let Some(i) = n.as_i64() {
        Box::new(CelInt::from(i))
    } else if let Some(u) = n.as_u64() {
        Box::new(CelUInt::from(u))
    } else {
        // Every other number is an f64 unless serde_json's
        // `arbitrary_precision` is enabled; a NaN fails every comparison.
        Box::new(CelDouble::from(n.as_f64().unwrap_or(f64::NAN)))
    }
}

/// A JSON object as a CEL `map` with string keys.
#[derive(Debug)]
struct JsonMap<'v> {
    map: &'v Map<String, Value>,
    /// The keys as CEL strings, made the first time the map is iterated.
    keys: OnceLock<Vec<CelString<'v>>>,
}

/// What looking a key up in a [`JsonMap`] finds.
enum Lookup<'v> {
    Found(&'v Value),
    Missing,
    /// A value of a type no map key can have.
    NotAKey,
}

impl<'v> JsonMap<'v> {
    fn new(map: &'v Map<String, Value>) -> Self {
        Self {
            map,
            keys: OnceLock::new(),
        }
    }

    fn keys(&self) -> &[CelString<'v>] {
        self.keys.get_or_init(|| {
            self.map
                .keys()
                .map(|k| CelString::from(k.as_str()))
                .collect()
        })
    }

    /// As for CEL's maps, `bool`, `int`, `uint` and `double` are key types
    /// too; a JSON object just never has such a key.
    fn lookup(&self, key: &dyn Val) -> Lookup<'v> {
        if let Some(key) = key.downcast_ref::<CelString>() {
            match self.map.get(key.inner()) {
                Some(value) => Lookup::Found(value),
                None => Lookup::Missing,
            }
        } else if key.downcast_ref::<CelInt>().is_some()
            || key.downcast_ref::<CelUInt>().is_some()
            || key.downcast_ref::<CelDouble>().is_some()
            || key.downcast_ref::<CelBool>().is_some()
        {
            Lookup::Missing
        } else {
            Lookup::NotAKey
        }
    }
}

/// The key as `no such key` errors name it.
fn key_name(key: &dyn Val) -> String {
    if let Some(s) = key.downcast_ref::<CelString>() {
        s.inner().to_owned()
    } else if let Some(i) = key.downcast_ref::<CelInt>() {
        i.inner().to_string()
    } else if let Some(u) = key.downcast_ref::<CelUInt>() {
        u.inner().to_string()
    } else if let Some(d) = key.downcast_ref::<CelDouble>() {
        d.inner().to_string()
    } else if let Some(b) = key.downcast_ref::<CelBool>() {
        b.inner().to_string()
    } else {
        String::new()
    }
}

impl<'v> Val for JsonMap<'v> {
    fn get_type(&self) -> &Type {
        &types::MAP_TYPE
    }

    fn cel_type() -> &'static Type {
        &types::MAP_TYPE
    }

    fn as_container(&self) -> Option<&dyn Container> {
        Some(self)
    }

    fn as_indexer<'b, 'w>(&'b self) -> Option<&'b (dyn Indexer + 'w)>
    where
        Self: 'w,
    {
        Some(self)
    }

    fn as_iterable<'b, 'w>(&'b self) -> Option<&'b (dyn Iterable + 'w)>
    where
        Self: 'w,
    {
        Some(self)
    }

    fn as_sizer(&self) -> Option<&dyn Sizer> {
        Some(self)
    }

    fn as_zeroer(&self) -> Option<&dyn Zeroer> {
        Some(self)
    }

    /// CEL map equality: the same keys, with equal values. `other` is reached
    /// through its capabilities only, as a borrowing type can't be downcast.
    fn equals(&self, other: &dyn Val) -> bool {
        if other.get_type().kind() != Kind::Map {
            return false;
        }
        let (Some(sizer), Some(indexer)) = (other.as_sizer(), other.as_indexer()) else {
            return false;
        };
        i64::try_from(self.map.len()).is_ok_and(|len| *sizer.size().inner() == len)
            && self.map.iter().all(|(key, value)| {
                indexer
                    .get(&CelString::from(key.as_str()))
                    .is_ok_and(|other| to_val(value).equals(other.as_ref()))
            })
    }

    fn clone_as_boxed<'w>(&self) -> Box<dyn Val + 'w>
    where
        Self: 'w,
    {
        Box::new(JsonMap::new(self.map))
    }
}

impl Container for JsonMap<'_> {
    fn contains(&self, key: &dyn Val) -> Result<bool, ExecutionError> {
        match self.lookup(key) {
            Lookup::Found(_) => Ok(true),
            Lookup::Missing => Ok(false),
            Lookup::NotAKey => Err(ExecutionError::unsupported_key_type(
                cel::Value::try_from(key).unwrap_or(cel::Value::Null),
            )),
        }
    }
}

impl<'v> Indexer for JsonMap<'v> {
    fn get<'b, 'w>(&'b self, key: &dyn Val) -> Result<CowVal<'b, 'w>, ExecutionError>
    where
        Self: 'w,
    {
        match self.lookup(key) {
            Lookup::Found(value) => Ok(CowVal::Owned(to_val(value))),
            Lookup::Missing => Err(ExecutionError::no_such_key(&key_name(key))),
            Lookup::NotAKey => Err(ExecutionError::UnexpectedType {
                got: key.get_type().name().to_owned(),
                want: "map key".to_owned(),
            }),
        }
    }

    fn steal<'w>(self: Box<Self>, key: &dyn Val) -> Result<Box<dyn Val + 'w>, ExecutionError>
    where
        Self: 'w,
    {
        self.get(key).map(CowVal::into_owned)
    }
}

impl<'v> Iterable for JsonMap<'v> {
    fn iter<'b, 'w>(&'b self) -> Box<dyn traits::Iterator<'b, 'w> + 'b>
    where
        Self: 'w,
    {
        Box::new(Keys(self.keys().iter()))
    }
}

/// The keys of a [`JsonMap`], in the JSON object's order.
struct Keys<'b, 'v>(std::slice::Iter<'b, CelString<'v>>);

impl<'b, 'v: 'w, 'w> traits::Iterator<'b, 'w> for Keys<'b, 'v> {
    fn next(&mut self) -> Option<&'b (dyn Val + 'w)> {
        self.0.next().map(|key| key as &(dyn Val + 'w))
    }
}

impl Sizer for JsonMap<'_> {
    fn size(&self) -> CelInt {
        CelInt::from(i64::try_from(self.map.len()).unwrap_or(i64::MAX))
    }
}

impl Zeroer for JsonMap<'_> {
    fn is_zero_value(&self) -> bool {
        self.map.is_empty()
    }
}
