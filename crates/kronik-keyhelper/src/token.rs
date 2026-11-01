//! AES-GCM byte envelopes, never PKCS#11 key-object wrapping.
use std::os::fd::AsRawFd;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::{Mechanism, MechanismType, aead::GcmParams};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::types::RawAuthPin;
use zeroize::{Zeroize, Zeroizing};

use crate::protocol::{self, Error, Request};

pub struct ResultBytes {
    pub nonce: Zeroizing<String>,
    pub data: Zeroizing<String>,
}

pub fn execute(request: &Request<'_>, pin: Zeroizing<Vec<u8>>) -> Result<ResultBytes, Error> {
    let module = crate::platform::module(request)?;
    let path = format!("/proc/self/fd/{}", module.as_raw_fd());
    let context = Pkcs11::new(path).map_err(|_| Error::Module)?;
    context
        .initialize(CInitializeArgs::new(
            CInitializeFlags::OS_LOCKING_OK | CInitializeFlags::LIBRARY_CANT_CREATE_OS_THREADS,
        ))
        .map_err(|_| Error::Provider)?;
    let result = with_context(&context, request, pin);
    let finalized = context.finalize().map_err(|_| Error::Provider);
    // Even successful plaintext is withheld if finalization fails.
    match (result, finalized) {
        (Ok(bytes), Ok(())) => Ok(bytes),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}

fn with_context(
    context: &Pkcs11,
    request: &Request<'_>,
    mut pin: Zeroizing<Vec<u8>>,
) -> Result<ResultBytes, Error> {
    let mut selected = None;
    let slots = context.get_slots_with_token().map_err(|_| Error::Token)?;
    if slots.len() > 256 {
        return Err(Error::Token);
    }
    for slot in slots {
        let info = context.get_token_info(slot).map_err(|_| Error::Token)?;
        if info.manufacturer_id() == request.manufacturer.as_ref()
            && info.model() == request.model.as_ref()
            && info.serial_number() == request.serial.as_ref()
        {
            if selected.replace(slot).is_some() {
                return Err(Error::Token);
            }
        }
    }
    let slot = selected.ok_or(Error::Token)?;
    let mechanism = context
        .get_mechanism_info(slot, MechanismType::AES_GCM)
        .map_err(|_| Error::Attributes)?;
    if !mechanism.encrypt() || !mechanism.decrypt() {
        return Err(Error::Attributes);
    }
    let session = context.open_ro_session(slot).map_err(|_| Error::Provider)?;
    let secret = RawAuthPin::new(Box::new(std::mem::take(&mut *pin)));
    let login = session
        .login_with_raw(UserType::User, &secret)
        .map_err(|_| Error::Pin);
    drop(secret);
    drop(pin);
    let result = login.and_then(|()| operate(&session, request));
    let closed = session.close().map_err(|_| Error::Provider);
    match (result, closed) {
        (Ok(bytes), Ok(())) => Ok(bytes),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}

fn find_key(session: &Session, request: &Request<'_>) -> Result<ObjectHandle, Error> {
    let mut id = protocol::decode(request.key_id)?;
    let template = [
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::Id(std::mem::take(&mut *id)),
    ];
    let mut objects = session.iter_objects(&template).map_err(|_| Error::Key)?;
    let key = objects.next().ok_or(Error::Key)?.map_err(|_| Error::Key)?;
    if objects
        .next()
        .transpose()
        .map_err(|_| Error::Key)?
        .is_some()
    {
        return Err(Error::Key);
    }
    drop(objects);
    let attributes = session
        .get_attributes(
            key,
            &[
                AttributeType::Class,
                AttributeType::KeyType,
                AttributeType::Id,
                AttributeType::ValueLen,
                AttributeType::Sensitive,
                AttributeType::Extractable,
                AttributeType::Modifiable,
                AttributeType::Encrypt,
                AttributeType::Decrypt,
                AttributeType::Token,
                AttributeType::AllowedMechanisms,
            ],
        )
        .map_err(|_| Error::Attributes)?;
    validate_attributes(&attributes, request.key_id)?;
    Ok(key)
}

fn validate_attributes(attributes: &[Attribute], key_id: &str) -> Result<(), Error> {
    let id = protocol::decode(key_id)?;
    let required = [
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::ValueLen(32.into()),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Modifiable(false),
        Attribute::Encrypt(true),
        Attribute::Decrypt(true),
        Attribute::Token(true),
    ];
    if !required.iter().all(|expected| attributes.contains(expected))
        || !attributes.iter().any(|a| matches!(a, Attribute::Id(value) if value.as_slice() == id.as_slice()))
        || !attributes.iter().any(|a| matches!(a, Attribute::AllowedMechanisms(value) if value.contains(&MechanismType::AES_GCM)))
    {
        return Err(Error::Attributes);
    }
    Ok(())
}

fn decrypt(
    session: &Session,
    key: ObjectHandle,
    nonce: &mut [u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let params = GcmParams::new(nonce, aad, 128.into()).map_err(|_| Error::Provider)?;
    // cryptoki's internal failed-decrypt Vec is not ours to scrub; do not claim otherwise.
    let plaintext = Zeroizing::new(
        session
            .decrypt(&Mechanism::AesGcm(params), key, ciphertext)
            .map_err(|_| Error::Authentication)?,
    );
    if plaintext.len() != 32 {
        return Err(Error::Authentication);
    }
    Ok(plaintext)
}

fn operate(session: &Session, request: &Request<'_>) -> Result<ResultBytes, Error> {
    let key = find_key(session, request)?;
    match request.op {
        "enroll" => encrypt(session, key, request, &protocol::PROBE_PLAINTEXT, true),
        "wrap" => {
            let probe = request.probe.as_ref().ok_or(Error::Protocol)?;
            let mut nonce = protocol::decode(probe.nonce)?;
            let ciphertext = protocol::decode(probe.ciphertext)?;
            let aad = protocol::aad(request, true);
            let mut expected = decrypt(session, key, &mut nonce, &aad, &ciphertext)?;
            if expected.as_slice() != protocol::PROBE_PLAINTEXT {
                return Err(Error::Authentication);
            }
            expected.zeroize();
            drop(expected);
            let plaintext = protocol::decode(request.plaintext.ok_or(Error::Protocol)?)?;
            encrypt(session, key, request, &plaintext, false)
        }
        "unwrap" => {
            let mut nonce = protocol::decode(request.nonce.ok_or(Error::Protocol)?)?;
            let ciphertext = protocol::decode(request.ciphertext.ok_or(Error::Protocol)?)?;
            let aad = protocol::aad(request, false);
            let plaintext = decrypt(session, key, &mut nonce, &aad, &ciphertext)?;
            Ok(ResultBytes {
                nonce: Zeroizing::new(String::new()),
                data: protocol::encode(&plaintext),
            })
        }
        _ => Err(Error::Protocol),
    }
}

fn encrypt(
    session: &Session,
    key: ObjectHandle,
    request: &Request<'_>,
    plaintext: &[u8],
    enrollment: bool,
) -> Result<ResultBytes, Error> {
    let mut nonce = Zeroizing::new([0u8; 12]);
    getrandom::fill(nonce.as_mut_slice()).map_err(|_| Error::Resource)?;
    let aad = protocol::aad(request, enrollment);
    let params =
        GcmParams::new(nonce.as_mut_slice(), &aad, 128.into()).map_err(|_| Error::Provider)?;
    let ciphertext = Zeroizing::new(
        session
            .encrypt(&Mechanism::AesGcm(params), key, plaintext)
            .map_err(|_| Error::Provider)?,
    );
    if ciphertext.len() != 48 {
        return Err(Error::Provider);
    }
    Ok(ResultBytes {
        nonce: protocol::encode(nonce.as_slice()),
        data: protocol::encode(&ciphertext),
    })
}

#[cfg(test)]
mod tests;
