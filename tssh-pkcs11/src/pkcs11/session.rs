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

use anyhow::Result;
use pkcs11_sys::{
    CK_ATTRIBUTE, CK_OBJECT_HANDLE, CK_SESSION_HANDLE, CKA_CLASS, CKA_ID, CKA_LABEL, CKA_SIGN,
    CKO_PRIVATE_KEY, CKO_PUBLIC_KEY,
};
use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock, atomic::AtomicU64},
};
use tracing::warn;

use tssh_core::sqlite::types::DBKey;

static SESSION_HANDLER: OnceLock<SessionHandler> = OnceLock::new();

pub fn get_sessions() -> &'static SessionHandler {
    SESSION_HANDLER.get_or_init(|| SessionHandler {
        sessions: Mutex::new(HashMap::default()),
        session_counter: AtomicU64::new(23),
    })
}

#[derive(Clone, Debug)]
pub enum State {
    Init,
    FindObjectsInit(FindObjectsInit),
    FindObjects(FindObjects),
    FindObjectsFinal,
    SignInit(SignInit),
}

#[derive(Clone, Debug)]
pub struct SignInit {
    pub object_handle: CK_OBJECT_HANDLE,
}

#[derive(Clone, Debug)]
pub struct FindObjectsInit {
    pub criteria: FindObjectsCriteria,
}

impl FindObjectsInit {
    pub fn new(attributes: &[CK_ATTRIBUTE]) -> Self {
        Self {
            criteria: FindObjectsCriteria::from(attributes),
        }
    }
}

#[derive(Clone, Debug)]
pub struct FindObjects {
    pub criteria: FindObjectsCriteria,
    pub results: Option<(Vec<DBKey>, usize)>, //result, next_index
}

impl From<FindObjectsInit> for FindObjects {
    fn from(value: FindObjectsInit) -> Self {
        Self {
            criteria: value.criteria,
            results: None,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct FindObjectsCriteria {
    pub classes: Vec<u64>,
    pub labels: Vec<Vec<u8>>,
    pub ids: Vec<Vec<u8>>,
    pub always_fail: bool,
    pub sign: Option<bool>,
}

impl From<&[CK_ATTRIBUTE]> for FindObjectsCriteria {
    fn from(value: &[CK_ATTRIBUTE]) -> Self {
        let mut ret = FindObjectsCriteria::default();

        for a in value {
            match a.type_ {
                CKA_CLASS => {
                    ret.classes.push(unsafe { *(a.pValue as *const u64) });
                }

                CKA_LABEL => {
                    let slice = unsafe {
                        std::slice::from_raw_parts(a.pValue as *const u8, a.ulValueLen as usize)
                    };
                    ret.labels.push(slice.to_vec());
                }
                CKA_ID => {
                    let slice = unsafe {
                        std::slice::from_raw_parts(a.pValue as *const u8, a.ulValueLen as usize)
                    };
                    ret.ids.push(slice.to_vec());
                }
                CKA_SIGN => {
                    let can_sign = unsafe { *(a.pValue as *const u8) } != 0;
                    ret.sign = Some(can_sign);
                }

                _ => {
                    ret.always_fail = true;
                    warn!(
                        "don't know about CKA type {} this will never match",
                        a.type_
                    );
                }
            }
        }
        ret
    }
}

impl FindObjectsCriteria {
    pub fn has(&self, dbKey: &DBKey) -> bool {
        if self.always_fail {
            return false;
        }

        if let Some(sign) = self.sign
            && !sign
        {
            return false;
        }

        for class in self.classes.iter() {
            if *class == CKO_PUBLIC_KEY || *class == CKO_PRIVATE_KEY {
                continue;
            }
            return false;
        }

        for id in self.ids.iter() {
            if id != dbKey.pkcs11_id.as_bytes() {
                return false;
            }
        }

        for label in self.labels.iter() {
            if label != dbKey.pkcs11_id.as_bytes() {
                return false;
            }
        }
        true
    }
}

pub struct Session {
    state: State,
}

pub struct SessionHandler {
    sessions: Mutex<HashMap<CK_SESSION_HANDLE, Session>>,
    session_counter: AtomicU64,
}

impl SessionHandler {
    pub fn new_session(&self) -> Result<CK_SESSION_HANDLE> {
        let session_id = self
            .session_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut s = self.sessions.lock().expect("can't lock sessions");
        s.insert(session_id, Session { state: State::Init });
        Ok(session_id)
    }

    pub fn remove(&self, handle: CK_SESSION_HANDLE) -> Result<()> {
        let mut s = self.sessions.lock().expect("can't lock session");
        if s.remove(&handle).is_none() {
            warn!("handle {} does not belong to a tracked session", handle);
        }
        Ok(())
    }

    pub fn get_state(&self, handle: CK_SESSION_HANDLE) -> Result<State> {
        let s = self.sessions.lock().expect("can't lock session");

        Ok(s.get(&handle)
            .ok_or(anyhow::anyhow!(
                "there is no session with handle {}",
                handle
            ))?
            .state
            .clone())
    }

    pub fn set_state(&self, handle: CK_SESSION_HANDLE, state: State) -> Result<()> {
        let mut s = self.sessions.lock().expect("can't lock session");

        s.get_mut(&handle)
            .ok_or(anyhow::anyhow!(
                "there is not session with handle {}",
                handle
            ))?
            .state = state;

        Ok(())
    }
}
