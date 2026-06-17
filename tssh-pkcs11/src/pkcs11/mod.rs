#![allow(
// Copyright (C) 2026 Stephan Naumann
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

    non_snake_case,
    clippy::missing_safety_doc,
    clippy::missing_transmute_annotations
)]

use std::{
    ptr::copy_nonoverlapping,
    sync::{Mutex, MutexGuard, Once, OnceLock},
};

use anyhow::{Result, bail};
use function_name::named;
use pkcs11_sys::{
    CK_ATTRIBUTE_PTR, CK_BBOOL, CK_BYTE_PTR, CK_FALSE, CK_FLAGS, CK_FUNCTION_LIST,
    CK_FUNCTION_LIST_PTR_PTR, CK_INFO, CK_KEY_TYPE, CK_MECHANISM_INFO, CK_MECHANISM_INFO_PTR,
    CK_MECHANISM_PTR, CK_MECHANISM_TYPE, CK_MECHANISM_TYPE_PTR, CK_NOTIFY, CK_OBJECT_HANDLE,
    CK_OBJECT_HANDLE_PTR, CK_RV, CK_SESSION_HANDLE, CK_SESSION_HANDLE_PTR, CK_SESSION_INFO_PTR,
    CK_SLOT_ID, CK_SLOT_ID_PTR, CK_SLOT_INFO, CK_TOKEN_INFO, CK_ULONG, CK_ULONG_PTR,
    CK_UNAVAILABLE_INFORMATION, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_VERSION, CK_VOID_PTR,
    CKA_ALWAYS_AUTHENTICATE, CKA_EC_POINT, CKA_ECDSA_PARAMS, CKA_ID, CKA_KEY_TYPE, CKA_LABEL,
    CKA_MODULUS, CKA_PUBLIC_EXPONENT, CKF_HW, CKF_SIGN, CKF_TOKEN_INITIALIZED, CKF_TOKEN_PRESENT,
    CKF_USER_PIN_INITIALIZED, CKK_EC, CKK_RSA, CKM_ECDSA, CKM_RSA_PKCS, CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_TYPE_INVALID, CKR_BUFFER_TOO_SMALL, CKR_DEVICE_ERROR, CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR, CKR_MECHANISM_INVALID, CKR_OK,
};
use tracing_subscriber::EnvFilter;

use tracing::{debug, error, trace, warn};

use tssh_core::{
    sqlite::types::DBKey,
    tpm::{self, EccTemplate, RsaTemplate, Template},
};

use crate::pkcs11::session::{FindObjects, FindObjectsInit, SignInit, State};

mod session;

static LOG: Once = Once::new();

fn init_logging() {
    LOG.call_once(|| {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .with_writer(std::io::stderr)
            .init();
    });
}

static DB: OnceLock<Mutex<tssh_core::sqlite::DB>> = OnceLock::new();

fn get_db() -> MutexGuard<'static, tssh_core::sqlite::DB> {
    let mutex = DB.get_or_init(|| {
        let db = tssh_core::sqlite::DB::new().expect("can't connect to sqlite db");
        Mutex::new(db)
    });

    mutex.lock().expect("should not happen")
}

static TPM: OnceLock<Mutex<tssh_core::tpm::TPMContext>> = OnceLock::new();

fn get_tpm() -> MutexGuard<'static, tssh_core::tpm::TPMContext> {
    let mutex = TPM.get_or_init(|| {
        let db = tssh_core::tpm::TPMContext::new_default().expect("can't use tpm");
        Mutex::new(db)
    });

    mutex.lock().expect("should not happen")
}

static FUNCTION_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: CK_VERSION {
        major: 2,
        minor: 40,
    },
    C_Initialize: Some(C_Initialize),
    C_Sign: Some(C_Sign),
    C_SignInit: Some(C_SignInit),
    C_FindObjectsInit: Some(C_FindObjectsInit),
    C_FindObjects: Some(C_FindObjects),
    C_FindObjectsFinal: Some(C_FindObjectsFinal),
    C_GetAttributeValue: Some(C_GetAttributeValue),
    C_OpenSession: Some(C_OpenSession),
    C_CloseSession: Some(C_CloseSession),
    C_GetSlotList: Some(C_GetSlotList),
    C_Finalize: Some(C_Finalize),
    C_GetInfo: Some(C_GetInfo),
    C_GetFunctionList: Some(C_GetFunctionList),
    C_GetSlotInfo: Some(C_GetSlotInfo),
    C_GetTokenInfo: Some(C_GetTokenInfo),
    C_GetMechanismList: Some(C_GetMechanismList),
    C_GetMechanismInfo: Some(C_GetMechanismInfo),
    C_InitToken: Some(stub_4),
    C_InitPIN: Some(C_InitPIN),
    C_SetPIN: Some(stub_5),
    C_CloseAllSessions: Some(stub_1),
    C_GetSessionInfo: Some(C_GetSessionInfo),
    C_GetOperationState: Some(stub_3),
    C_SetOperationState: Some(stub_5),
    C_Login: Some(C_Login),
    C_Logout: Some(stub_1),
    C_CreateObject: Some(stub_4),
    C_CopyObject: Some(stub_5),
    C_DestroyObject: Some(stub_2),
    C_GetObjectSize: Some(stub_3),
    C_SetAttributeValue: Some(stub_4),
    C_EncryptInit: Some(stub_3),
    C_Encrypt: Some(stub_5),
    C_EncryptUpdate: Some(stub_5),
    C_EncryptFinal: Some(stub_3),
    C_DecryptInit: Some(stub_3),
    C_Decrypt: Some(stub_5),
    C_DecryptUpdate: Some(stub_5),
    C_DecryptFinal: Some(stub_3),
    C_DigestInit: Some(stub_2),
    C_Digest: Some(stub_5),
    C_DigestUpdate: Some(stub_3),
    C_DigestKey: Some(stub_2),
    C_DigestFinal: Some(stub_3),
    C_SignUpdate: Some(stub_3),
    C_SignFinal: Some(stub_3),
    C_SignRecoverInit: Some(stub_3),
    C_SignRecover: Some(stub_5),
    C_VerifyInit: Some(stub_3),
    C_Verify: Some(stub_5),
    C_VerifyUpdate: Some(stub_3),
    C_VerifyFinal: Some(stub_3),
    C_VerifyRecoverInit: Some(stub_3),
    C_VerifyRecover: Some(stub_5),
    C_DigestEncryptUpdate: Some(stub_5),
    C_DecryptDigestUpdate: Some(stub_5),
    C_SignEncryptUpdate: Some(stub_5),
    C_DecryptVerifyUpdate: Some(stub_5),
    C_GenerateKey: Some(stub_5),
    C_GenerateKeyPair: Some(stub_8),
    C_WrapKey: Some(stub_6),
    C_UnwrapKey: Some(stub_8),
    C_DeriveKey: Some(stub_6),
    C_SeedRandom: Some(stub_3),
    C_GenerateRandom: Some(stub_3),
    C_GetFunctionStatus: Some(stub_1),
    C_CancelFunction: Some(stub_1),
    C_WaitForSlotEvent: Some(C_WaitForSlotEvent),
};

#[named]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetFunctionList(ppFunctionList: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    init_logging();
    trace!("{} called", function_name!());
    if ppFunctionList.is_null() {
        error!("received NULL functionList pointer");
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        *ppFunctionList = &FUNCTION_LIST as *const _ as *mut _;
    }
    CKR_OK
}

#[named]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Initialize(_pInitArgs: CK_VOID_PTR) -> CK_RV {
    trace!("{} called", function_name!());
    CKR_OK
}

#[named]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Finalize(_p_reserved: CK_VOID_PTR) -> CK_RV {
    trace!("{} called", function_name!());

    CKR_OK
}

#[named]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_OpenSession(
    slot_id: CK_SLOT_ID,
    _flags: CK_FLAGS,
    _p_application: CK_VOID_PTR,
    _notify: CK_NOTIFY,
    ph_session: CK_SESSION_HANDLE_PTR,
) -> CK_RV {
    trace!("{} called with slot id {slot_id}", function_name!());

    if ph_session.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    match session::get_sessions().new_session() {
        Ok(session_handle) => {
            trace!("adding new session handle {session_handle}");
            unsafe { *ph_session = session_handle };
            CKR_OK
        }
        Err(e) => {
            error!("can't initialize session: {:?}", e);
            CKR_GENERAL_ERROR
        }
    }
}

#[named]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_CloseSession(h_session: CK_SESSION_HANDLE) -> CK_RV {
    trace!("{} called", function_name!());
    if let Err(e) = session::get_sessions().remove(h_session) {
        error!("can't remove session {h_session}: {e}");
    }
    CKR_OK
}

#[named]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetSlotList(
    _token_present: CK_BBOOL,
    pSlotList: CK_SLOT_ID_PTR,
    pulCount: CK_ULONG_PTR,
) -> CK_RV {
    trace!("{} called", function_name!());

    const UNIQUE_SLOTLIST_HANDLE: u64 = 101;

    if pulCount.is_null() {
        debug!("pulCount is null");
        return CKR_ARGUMENTS_BAD;
    }

    if pSlotList.is_null() {
        //caller only wants the count value
        debug!("pSlotList is Null only returning length");
        unsafe { *pulCount = 1 };
        return CKR_OK;
    }

    //slot list i not null  so it wants content
    if unsafe { *pulCount } < 1 {
        debug!("buffer to small for complete slotlist");
        return CKR_BUFFER_TOO_SMALL;
    }

    debug!("returing 101 as unique slotList content");
    unsafe {
        *pSlotList = UNIQUE_SLOTLIST_HANDLE;
        *pulCount = 1;
    }

    CKR_OK
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Login(
    _h_session: CK_SESSION_HANDLE,
    _user_type: CK_USER_TYPE,
    _p_pin: CK_UTF8CHAR_PTR,
    _ul_pin_len: CK_ULONG,
) -> CK_RV {
    warn!("the key is not a login key ....");
    CKR_OK
}

#[named]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetTokenInfo(slotID: CK_SLOT_ID, pInfo: *mut CK_TOKEN_INFO) -> CK_RV {
    trace!("{} called with slotid {slotID}", function_name!());

    if pInfo.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    //TODO: fill out correctly
    unsafe {
        let info = &mut *pInfo;
        fill_pkcs11_str(&mut info.label, "TSSH");
        fill_pkcs11_str(&mut info.manufacturerID, "Cmdscale");
        fill_pkcs11_str(&mut info.model, "v1.0");
        fill_pkcs11_str(&mut info.serialNumber, "0001");

        info.flags = CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED;
        info.ulMaxSessionCount = CK_UNAVAILABLE_INFORMATION;
        info.ulMaxPinLen = CK_UNAVAILABLE_INFORMATION;
        info.ulMinPinLen = CK_UNAVAILABLE_INFORMATION;
    }
    CKR_OK
}

#[named]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_FindObjectsInit(
    h_session: CK_SESSION_HANDLE,
    p_template: CK_ATTRIBUTE_PTR,
    ul_count: CK_ULONG,
) -> CK_RV {
    trace!("{} called with sessionId {h_session}", function_name!());

    let session_state = unsafe {
        let attributes = std::slice::from_raw_parts(p_template, ul_count as usize);
        State::FindObjectsInit(FindObjectsInit::new(attributes))
    };
    if let Err(e) = session::get_sessions().set_state(h_session, session_state) {
        error!("can't set state of session {h_session}: {e}");
        return CKR_GENERAL_ERROR;
    };

    CKR_OK
}

fn load_objects(find_objects: &mut FindObjects) -> Result<()> {
    let result = get_db()
        .get_all_keys()?
        .into_iter()
        .filter(|k| find_objects.criteria.has(k))
        .collect::<Vec<DBKey>>();
    trace!("loaded {} results", result.len());

    find_objects.results = Some((result, 0));
    Ok(())
}

#[named]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_FindObjects(
    h_session: CK_SESSION_HANDLE,
    phObject: CK_OBJECT_HANDLE_PTR,
    ul_max_object_count: CK_ULONG,
    pulObjectCount: CK_ULONG_PTR,
) -> CK_RV {
    trace!("{} called with sessionId {h_session}", function_name!());

    //TODO: would me good to just receive a &mut state...
    let Ok(state) = session::get_sessions().get_state(h_session) else {
        error!("can't get state of session with handle {h_session}");
        return CKR_ARGUMENTS_BAD;
    };

    let mut find_objects = match state {
        State::FindObjectsInit(find_objects_init) => {
            let mut new_state = find_objects_init.into();
            if let Err(e) = load_objects(&mut new_state) {
                error!("can't find objects: {e}");
                return CKR_GENERAL_ERROR;
            }
            if let Err(e) =
                session::get_sessions().set_state(h_session, State::FindObjects(new_state.clone()))
            {
                error!("can't update state of session {h_session}: {e}");
                return CKR_GENERAL_ERROR;
            }
            new_state
        }
        State::FindObjects(find_objects) => find_objects,
        _ => {
            error!("session {h_session} is in wrong state");
            return CKR_ARGUMENTS_BAD;
        }
    };

    unsafe { *pulObjectCount = 0 };

    if let Some((results, next_index)) = &mut find_objects.results {
        if results.len() <= *next_index {
            return CKR_OK;
        }

        let remaining = results.len().saturating_sub(*next_index);

        if remaining == 0 {
            return CKR_OK;
        }

        let amount_to_write = std::cmp::min(ul_max_object_count as usize, remaining);

        let out = unsafe { std::slice::from_raw_parts_mut(phObject, amount_to_write) };

        for v in out.iter_mut() {
            *v = results.get(*next_index).unwrap().id as u64;
            *next_index += 1;
            unsafe { *pulObjectCount += 1 }
        }

        if let Err(e) =
            session::get_sessions().set_state(h_session, State::FindObjects(find_objects))
        {
            error!("can't update state of session {h_session}: {e}");
            return CKR_GENERAL_ERROR;
        }

        return CKR_OK;
    }

    CKR_OK
}

#[named]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_FindObjectsFinal(h_session: CK_SESSION_HANDLE) -> CK_RV {
    trace!("{} called with sessionId {h_session}", function_name!());

    if let Err(e) = session::get_sessions().set_state(h_session, State::FindObjectsFinal) {
        error!("can't set state of session {h_session}: {e}");

        return CKR_GENERAL_ERROR;
    }

    CKR_OK
}

#[named]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetAttributeValue(
    h_session: CK_SESSION_HANDLE,
    h_object: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
) -> CK_RV {
    trace!(
        "{} called with sessionId {h_session} and object handle {h_object}",
        function_name!()
    );

    let key = match get_key_from_db(h_object) {
        Ok(key) => key,
        Err(e) => {
            error!("error while getting handle {h_object} for session {h_session}: {e}");
            return CKR_GENERAL_ERROR;
        }
    };

    let host_template = match tpm::HostTemplate::try_from(&key) {
        Ok(t) => t,
        Err(e) => {
            error!("can't get template from db key: {e}");
            return CKR_GENERAL_ERROR;
        }
    };

    let template = unsafe { std::slice::from_raw_parts_mut(pTemplate, ulCount as usize) };

    let mut global_return = CKR_OK;

    for (i, attr) in template.iter_mut().enumerate() {
        match attr.type_ {
            CKA_ID => {
                trace!("{i} call asking for CK_ID for object {h_object}");

                if attr.pValue.is_null() {
                    debug!("CKA ID size request");
                    attr.ulValueLen = key.pkcs11_id.len() as u64;
                    continue;
                }

                if attr.ulValueLen < key.pkcs11_id.len() as u64 {
                    warn!("Buffer to small in CKA ID");
                    attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    global_return = CKR_BUFFER_TOO_SMALL;
                    continue;
                }
                trace!(
                    "Returnin CK_ID={} len={}",
                    key.pkcs11_id,
                    key.pkcs11_id.len()
                );
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        key.pkcs11_id.as_ptr(),
                        attr.pValue as *mut u8,
                        key.pkcs11_id.len(),
                    );
                }
                attr.ulValueLen = key.pkcs11_id.len() as u64;
            }
            CKA_ECDSA_PARAMS => {
                trace!("{i} call asking for CKA_ECDSA_PARAMS for object {h_object}");

                const P256_OID: &[u8] =
                    &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
                const P384_OID: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
                const P521_OID: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23];

                let Template::ECC(curve) = host_template.template.clone() else {
                    error!("Handle does not correspond to ECC key");
                    return CKR_GENERAL_ERROR;
                };

                let used_oid = match curve.curve {
                    tpm::ECCCurve::NistP256 => P256_OID,
                    tpm::ECCCurve::NistP384 => P384_OID,
                    tpm::ECCCurve::NistP521 => P521_OID,
                };

                if attr.pValue.is_null() {
                    attr.ulValueLen = used_oid.len() as u64;
                    continue;
                }

                if attr.ulValueLen < used_oid.len() as u64 {
                    warn!("Buffer to small in CKA ECDSA PARAMS");
                    attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    global_return = CKR_BUFFER_TOO_SMALL;
                    continue;
                }

                unsafe {
                    std::ptr::copy_nonoverlapping(
                        used_oid.as_ptr(),
                        attr.pValue as *mut u8,
                        used_oid.len(),
                    );
                    attr.ulValueLen = used_oid.len() as u64;
                }
            }
            CKA_EC_POINT => {
                trace!("{i} call asking for CKA_EC_POINT for object {h_object}");

                let mut tpm = get_tpm();

                let tpm_key = match tpm.get_primary_key(&host_template) {
                    Ok(key) => key,
                    Err(e) => {
                        error!("can't get key from tpm: {e}");
                        return CKR_GENERAL_ERROR;
                    }
                };

                let ecc_key = match tpm_key.get_ecc_pub_key() {
                    Ok(key) => key,
                    Err(e) => {
                        error!("can't get ecc key from tpm key: {e}");
                        return CKR_GENERAL_ERROR;
                    }
                };

                let ecc_point = match ecc_key.get_cka_ec_point() {
                    Ok(key) => key,
                    Err(e) => {
                        error!("can't ecc point from ecc key: {e}");
                        return CKR_GENERAL_ERROR;
                    }
                };

                if attr.pValue.is_null() {
                    debug!("CKA_EC_POINT size request");
                    attr.ulValueLen = ecc_point.len() as u64;
                    continue;
                }

                if attr.ulValueLen < ecc_point.len() as u64 {
                    warn!("Buffer to small in CKA EC POINT");
                    attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    global_return = CKR_BUFFER_TOO_SMALL;
                    continue;
                }
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        ecc_point.as_ptr(),
                        attr.pValue as *mut u8,
                        ecc_point.len(),
                    );
                    attr.ulValueLen = ecc_point.len() as u64;
                }
            }
            CKA_LABEL => {
                trace!("{i} call asking for CKA_LABEL for object {h_object}");

                if attr.pValue.is_null() {
                    debug!("CKA LABEL size request");
                    attr.ulValueLen = key.pkcs11_id.len() as u64;
                    continue;
                }

                if attr.ulValueLen < key.pkcs11_id.len() as u64 {
                    warn!("Buffer to small in CKA_LABEL");
                    attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    global_return = CKR_BUFFER_TOO_SMALL;
                    continue;
                }

                unsafe {
                    std::ptr::copy_nonoverlapping(
                        key.pkcs11_id.as_ptr(),
                        attr.pValue as *mut u8,
                        key.pkcs11_id.len(),
                    );
                    attr.ulValueLen = key.pkcs11_id.len() as u64;
                }
                trace!(
                    "Returnin CK_LABEL={} len={}",
                    key.pkcs11_id,
                    key.pkcs11_id.len()
                );
            }
            CKA_PUBLIC_EXPONENT => {
                trace!("{i} call asking for CKA_PUBLIC_Exponent for object {h_object}");

                let mut tpm = get_tpm();

                let tpm_key = match tpm.get_primary_key(&host_template) {
                    Ok(key) => key,
                    Err(e) => {
                        error!("can't get key from tpm: {e}");
                        return CKR_GENERAL_ERROR;
                    }
                };

                let rsa_key = match tpm_key.get_rsa_pub_key() {
                    Ok(key) => key,
                    Err(e) => {
                        error!("can't get rsa key from tpm key: {e}");
                        return CKR_GENERAL_ERROR;
                    }
                };

                let exponent_be_bytes = rsa_key.exponent.to_be_bytes();

                //according to spec we must cut leading 0

                let exponent = match exponent_be_bytes.iter().position(|b| *b != 0) {
                    Some(idx) => &exponent_be_bytes[idx..],
                    None => &[0], //dunno ...
                };

                if attr.pValue.is_null() {
                    debug!("CKA_PUBLIC_EXPONENT size request");
                    attr.ulValueLen = exponent.len() as u64;
                    continue;
                }
                if attr.ulValueLen < exponent.len() as u64 {
                    warn!("Buffer to small in CKA_PUBLIC_EXPONENT");
                    attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    global_return = CKR_BUFFER_TOO_SMALL;
                    continue;
                }

                unsafe {
                    std::ptr::copy_nonoverlapping(
                        exponent.as_ptr(),
                        attr.pValue as *mut u8,
                        exponent.len(),
                    );
                    attr.ulValueLen = exponent.len() as u64;
                }
            }
            CKA_MODULUS => {
                trace!("{i} call asking for CKA_MODULUS for object {h_object}");

                let mut tpm = get_tpm();

                let tpm_key = match tpm.get_primary_key(&host_template) {
                    Ok(key) => key,
                    Err(e) => {
                        error!("can't get key from tpm: {e}");
                        return CKR_GENERAL_ERROR;
                    }
                };

                let rsa_key = match tpm_key.get_rsa_pub_key() {
                    Ok(key) => key,
                    Err(e) => {
                        error!("can't get rsa key from tpm key: {e}");
                        return CKR_GENERAL_ERROR;
                    }
                };

                if attr.pValue.is_null() {
                    debug!("CKA_MODULUS size request");
                    attr.ulValueLen = rsa_key.modulus.len() as u64;
                    continue;
                }

                if attr.ulValueLen < rsa_key.modulus.len() as u64 {
                    warn!("Buffer to small in CKA_MODULUS");
                    attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    global_return = CKR_BUFFER_TOO_SMALL;
                    continue;
                }
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        rsa_key.modulus.as_ptr(),
                        attr.pValue as *mut u8,
                        rsa_key.modulus.len(),
                    );
                    attr.ulValueLen = rsa_key.modulus.len() as u64;
                }
            }
            CKA_KEY_TYPE => {
                trace!("{i} call asking for CKA_KEY_TYPE for object {h_object}");

                if attr.pValue.is_null() {
                    attr.ulValueLen = std::mem::size_of::<CK_KEY_TYPE>() as u64;
                    continue;
                }

                if attr.ulValueLen < std::mem::size_of::<CK_KEY_TYPE>() as u64 {
                    warn!("Buffer to small in CKA_KEY_TYPE ");
                    attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    global_return = CKR_BUFFER_TOO_SMALL;
                    continue;
                }

                let key_type = match host_template.template {
                    Template::RSA(_) => CKK_RSA,
                    Template::ECC(_) => CKK_EC,
                };

                unsafe {
                    *(attr.pValue as *mut CK_KEY_TYPE) = key_type;
                }
            }

            CKA_ALWAYS_AUTHENTICATE => {
                if attr.pValue.is_null() {
                    debug!("CKA_ALWAYS_AUTHENTICATE size request");
                    attr.ulValueLen = 1_u64;
                    continue;
                }

                if attr.ulValueLen < 1_u64 {
                    warn!("Buffer to small in CKA_ALWAYS_AUTHENTICATE");
                    attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    global_return = CKR_BUFFER_TOO_SMALL;
                    continue;
                }
                unsafe {
                    let slice = std::slice::from_raw_parts_mut(attr.pValue as *mut u8, 1);
                    slice[0] = CK_FALSE;
                    attr.ulValueLen = 1_u64;
                }
            }

            _ => {
                error!("{i} asking for unknow atribute {}", attr.type_);
                attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                global_return = CKR_ATTRIBUTE_TYPE_INVALID
            }
        }
    }

    global_return
}
#[named]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetMechanismList(
    slot_id: CK_SLOT_ID,
    p_mechanism_list: CK_MECHANISM_TYPE_PTR,
    pul_count: CK_ULONG_PTR,
) -> CK_RV {
    trace!("{} called with slot_id {slot_id}", function_name!());

    const SUPPORTED_MECHANISMS: [CK_ULONG; 2] = [CKM_ECDSA, CKM_RSA_PKCS];

    if pul_count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    if p_mechanism_list.is_null() {
        unsafe { *pul_count = SUPPORTED_MECHANISMS.len() as u64 };
        trace!("returning mechanismlist length only");
        return CKR_OK;
    }

    if unsafe { *pul_count } < SUPPORTED_MECHANISMS.len() as u64 {
        error!("get mechaninslam list buffer too small");
        return CKR_BUFFER_TOO_SMALL;
    }

    unsafe {
        copy_nonoverlapping(
            SUPPORTED_MECHANISMS.as_ptr(),
            p_mechanism_list,
            SUPPORTED_MECHANISMS.len(),
        );
        *pul_count = SUPPORTED_MECHANISMS.len() as u64;
    };

    trace!("returning mechanisms {:?}", SUPPORTED_MECHANISMS);

    CKR_OK
}

#[named]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_WaitForSlotEvent(
    _flags: CK_FLAGS,
    _pSlot: CK_SLOT_ID_PTR,
    _pReserved: CK_VOID_PTR,
) -> CK_RV {
    trace!("{} called ", function_name!());
    CKR_FUNCTION_NOT_SUPPORTED
}

#[named]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetMechanismInfo(
    slot_id: CK_SLOT_ID,
    type_: CK_MECHANISM_TYPE,
    pInfo: CK_MECHANISM_INFO_PTR,
) -> CK_RV {
    trace!("{} called with slot_id {slot_id}", function_name!());

    trace!("asking for type {type_}");

    const SUPPORTED_TYPES: [u64; 2] = [CKM_ECDSA, CKM_RSA_PKCS];

    if !SUPPORTED_TYPES.contains(&type_) {
        error!("only types {SUPPORTED_TYPES:?} is supported but asked for type {type_}");
        return CKR_MECHANISM_INVALID;
    }

    if pInfo.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    unsafe {
        *pInfo = CK_MECHANISM_INFO {
            ulMinKeySize: 256,
            ulMaxKeySize: 256,
            flags: CKF_HW | CKF_SIGN,
        }
    };

    CKR_OK
}

#[named]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetInfo(pInfo: *mut CK_INFO) -> CK_RV {
    trace!("{} called", function_name!());

    if pInfo.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    //TODO: fill out correctly
    unsafe {
        let info = &mut *pInfo;
        fill_pkcs11_str(&mut info.manufacturerID, "Cmdscale");
        info.flags = 0;
        fill_pkcs11_str(&mut info.libraryDescription, "TSSH");
        info.libraryVersion = CK_VERSION { major: 1, minor: 0 };
    }
    CKR_OK
}

#[named]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetSlotInfo(slotID: CK_SLOT_ID, pInfo: *mut CK_SLOT_INFO) -> CK_RV {
    trace!("{} called with slotId {slotID}", function_name!());

    if pInfo.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    //TODO: fill out correctly

    unsafe {
        let info = &mut *pInfo;
        fill_pkcs11_str(&mut info.slotDescription, "TSSH");
        fill_pkcs11_str(&mut info.manufacturerID, "Cmdscale");

        info.flags = CKF_TOKEN_PRESENT;

        info.hardwareVersion = CK_VERSION { major: 1, minor: 0 };
        info.firmwareVersion = CK_VERSION { major: 1, minor: 0 };
    }
    CKR_OK
}

#[named]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_SignInit(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    h_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    trace!("{} called with session id {h_session}", function_name!());
    if p_mechanism.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let key = match get_key_from_db(h_key) {
        Ok(k) => k,
        Err(e) => {
            error!("while getting key with id {h_key} from db: {e}");
            return CKR_GENERAL_ERROR;
        }
    };

    let template = match Template::try_from(key.template.as_str()) {
        Ok(t) => t,
        Err(e) => {
            error!("while parsing template of key with id {h_key}: {e}");
            return CKR_GENERAL_ERROR;
        }
    };

    let mechanism = unsafe { *p_mechanism };

    match template {
        Template::RSA(_) => {
            if mechanism.mechanism != CKM_RSA_PKCS {
                error!("requested invalid mechanism {}", mechanism.mechanism);
                return CKR_MECHANISM_INVALID;
            }
        }
        Template::ECC(_) => {
            if mechanism.mechanism != CKM_ECDSA {
                error!("requested invalid mechanism {}", mechanism.mechanism);
                return CKR_MECHANISM_INVALID;
            }
        }
    }

    if let Err(e) = session::get_sessions().set_state(
        h_session,
        State::SignInit(SignInit {
            object_handle: h_key,
        }),
    ) {
        error!("can't update state of session {h_session}: {e}");
        return CKR_GENERAL_ERROR;
    }

    CKR_OK
}

#[named]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Sign(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pSignature: CK_BYTE_PTR,
    pulSignatureLen: CK_ULONG_PTR,
) -> CK_RV {
    trace!("{} called with sessionId {hSession}", function_name!());
    if pulSignatureLen.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let state = match session::get_sessions().get_state(hSession) {
        Ok(s) => s,
        Err(e) => {
            error!("can't get state of session {hSession}: {e}");
            return CKR_GENERAL_ERROR;
        }
    };

    let State::SignInit(signinit) = state else {
        error!("session {hSession} is in wrong state3");
        return CKR_GENERAL_ERROR;
    };

    let key = match get_key_from_db(signinit.object_handle) {
        Ok(key) => key,
        Err(e) => {
            error!(
                "error while getting handle {} for session {hSession}: {e}",
                signinit.object_handle
            );
            return CKR_GENERAL_ERROR;
        }
    };

    let data = unsafe { std::slice::from_raw_parts(pData, ulDataLen as usize) };
    trace!("C_Sign: signing {} bytes using TPM", ulDataLen);

    let Ok(template) = tssh_core::tpm::HostTemplate::try_from(&key) else {
        error!("can't construct host template");
        return CKR_GENERAL_ERROR;
    };

    if pSignature.is_null() {
        unsafe { *pulSignatureLen = template.template.signature_size() as u64 };
        return CKR_OK;
    }

    let mut tpm = get_tpm();

    let data_to_sign = match prepare_data_for_signing(template.template.clone(), data) {
        Ok(d) => d,
        Err(e) => {
            error!("can't prepare data for signing: {e}");
            return CKR_DEVICE_ERROR;
        }
    };

    let raw_tpm_sig = match tpm.sign(&template, &data_to_sign) {
        Ok(sig) => sig,
        Err(e) => {
            error!("TPM Signing failed: {:?}", e);
            return CKR_DEVICE_ERROR;
        }
    };

    let Ok(der_sig) = parse_tpm_sign(&template.template, &raw_tpm_sig) else {
        error!("can't parse raw tpm signature");
        return CKR_DEVICE_ERROR;
    };

    let provided_len = unsafe { *pulSignatureLen } as usize;
    if provided_len < der_sig.len() {
        error!(
            "got buffer of size {provided_len} but need {}",
            der_sig.len()
        );
        unsafe { *pulSignatureLen = der_sig.len() as u64 };
        return CKR_BUFFER_TOO_SMALL;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(der_sig.as_ptr(), pSignature, der_sig.len());
        *pulSignatureLen = der_sig.len() as u64;
    }

    CKR_OK
}

#[named]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_InitPIN(
    hSession: CK_SESSION_HANDLE,
    _pPin: CK_UTF8CHAR_PTR,
    _ulPinLen: CK_ULONG,
) -> CK_RV {
    trace!("{} called with sessionId {hSession}", function_name!());
    warn!("this is not a pin device..");
    CKR_OK
}

#[named]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_SetPIN(
    hSession: CK_SESSION_HANDLE,
    _pOldPin: CK_UTF8CHAR_PTR,
    _ulOldLen: CK_ULONG,
    _pNewPin: CK_UTF8CHAR_PTR,
    _ulNewLen: CK_ULONG,
) -> CK_RV {
    trace!("{} called with sessionId {hSession}", function_name!());
    warn!("this is not a pin device..");
    CKR_OK
}

#[named]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetSessionInfo(
    hSession: CK_SESSION_HANDLE,
    pInfo: CK_SESSION_INFO_PTR,
) -> CK_RV {
    trace!("{} called with sessionId {hSession}", function_name!());
    if pInfo.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        (*pInfo).slotID = 101;
        (*pInfo).state = 0;
        (*pInfo).flags = 1;
    }
    CKR_OK
}

//
//
// Helpers
//
//
fn fill_pkcs11_str(dest: &mut [u8], src: &str) {
    let bytes = src.as_bytes();
    for i in 0..dest.len() {
        dest[i] = if i < bytes.len() { bytes[i] } else { b' ' };
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_FunctionNotSupported() -> CK_RV {
    error!("call to unsupported function");
    CKR_FUNCTION_NOT_SUPPORTED
}

fn prepare_data_for_signing(template: Template, data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let Template::RSA(rsa_template) = template else {
        return Ok(data.to_vec());
    };

    match rsa_template.keybits {
        tpm::RsaKeyBits::Rsa1024 => {
            if data.len() != 51 {
                bail!("expected 51 signing bytes")
            }
            Ok(data[19..].to_vec())
        }
        tpm::RsaKeyBits::Rsa2048 => {
            if data.len() != 51 {
                bail!("expected 51 signing bytes")
            }
            Ok(data[19..].to_vec())
        }
        tpm::RsaKeyBits::Rsa3072 => {
            if data.len() != 51 {
                bail!("expected 51 signing bytes")
            }
            Ok(data[19..].to_vec())
        }
        tpm::RsaKeyBits::Rsa4096 => {
            if data.len() != 83 {
                bail!("expected 83 signing bytes")
            }
            Ok(data[19..].to_vec())
        }
    }
}

//TODO: I guess we could use anyhow because we don't export
fn parse_tpm_sign(
    template: &Template,
    signature: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match template {
        Template::RSA(rsa_template) => parse_tpm_rsa_sign(rsa_template, signature),
        Template::ECC(ecc_template) => parse_tpm_ecc_sign(ecc_template, signature),
    }
}

fn parse_tpm_ecc_sign(
    ecc_template: &EccTemplate,
    signature: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match ecc_template.curve {
        tpm::ECCCurve::NistP256 => Ok(p256::ecdsa::Signature::from_der(signature)?.to_vec()),
        tpm::ECCCurve::NistP384 => Ok(p384::ecdsa::Signature::from_der(signature)?.to_vec()),
        tpm::ECCCurve::NistP521 => Ok(p521::ecdsa::Signature::from_der(signature)?.to_vec()),
    }
}

fn parse_tpm_rsa_sign(
    _rsa_template: &RsaTemplate,
    signature: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(signature.to_vec())
}

fn get_key_from_db(handle: CK_OBJECT_HANDLE) -> Result<DBKey> {
    get_db().get_key_by_id(handle as i32)
}

unsafe extern "C" fn stub_1<A>(_: A) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

unsafe extern "C" fn stub_2<A, B>(_: A, _: B) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
unsafe extern "C" fn stub_3<A, B, C>(_: A, _: B, _: C) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

unsafe extern "C" fn stub_4<A, B, C, D>(_: A, _: B, _: C, _: D) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

unsafe extern "C" fn stub_5<A, B, C, D, E>(_: A, _: B, _: C, _: D, _: E) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

unsafe extern "C" fn stub_6<A, B, C, D, E, F>(_: A, _: B, _: C, _: D, _: E, _: F) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

unsafe extern "C" fn stub_8<A, B, C, D, E, F, G, H>(
    _: A,
    _: B,
    _: C,
    _: D,
    _: E,
    _: F,
    _: G,
    _: H,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
