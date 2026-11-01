use super::*;

fn attributes() -> Vec<Attribute> {
    vec![
        Attribute::Class(ObjectClass::SECRET_KEY), Attribute::KeyType(KeyType::AES),
        Attribute::Id(vec![0xaa]), Attribute::ValueLen(32.into()),
        Attribute::Sensitive(true), Attribute::Extractable(false), Attribute::Modifiable(false),
        Attribute::Encrypt(true), Attribute::Decrypt(true), Attribute::Token(true),
        Attribute::AllowedMechanisms(vec![MechanismType::AES_GCM]),
    ]
}

#[test]
fn provisioned_aes256_gcm_attributes_are_required_individually() {
    let valid = attributes();
    assert_eq!(validate_attributes(&valid, "aa"), Ok(()));
    for missing in 0..valid.len() {
        let mut incomplete = valid.clone();
        incomplete.remove(missing);
        assert_eq!(validate_attributes(&incomplete, "aa"), Err(Error::Attributes), "missing {missing}");
    }
}

#[test]
fn immutable_nonexportable_key_gate_rejects_insecure_or_wrong_objects() {
    for invalid in [
        Attribute::Class(ObjectClass::PUBLIC_KEY), Attribute::KeyType(KeyType::GENERIC_SECRET),
        Attribute::Id(vec![0xbb]), Attribute::ValueLen(16.into()),
        Attribute::Sensitive(false), Attribute::Extractable(true), Attribute::Modifiable(true),
        Attribute::Encrypt(false), Attribute::Decrypt(false), Attribute::Token(false),
        Attribute::AllowedMechanisms(vec![MechanismType::AES_CBC]),
    ] {
        let mut changed = attributes();
        let index = changed.iter().position(|a| a.attribute_type() == invalid.attribute_type()).unwrap();
        changed[index] = invalid;
        assert_eq!(validate_attributes(&changed, "aa"), Err(Error::Attributes));
    }
}
