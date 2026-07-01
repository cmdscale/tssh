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

use anyhow::Context;
use linux_keyutils::KeyRing;
use serde::{Deserialize, Serialize};

use crate::external_seed::ExternalSeed;

#[derive(Deserialize, Serialize, Clone)]
pub struct KeyUtilsConf {}

pub struct KeyUtils {
    key_name: String,
    key_ring: KeyRing,
}

impl KeyUtils {
    pub fn from_config(_config: KeyUtilsConf, name: &str) -> anyhow::Result<Self> {
        let key_ring = KeyRing::from_special_id(linux_keyutils::KeyRingIdentifier::User, true)?;
        Ok(Self {
            key_name: name.to_string(), //TODO: prefix?
            key_ring,
        })
    }
}

impl ExternalSeed for KeyUtils {
    fn check(&self) -> anyhow::Result<bool> {
        match self.key_ring.search(&self.key_name) {
            Err(linux_keyutils::KeyError::KeyDoesNotExist) => Ok(false),
            Err(e) => Err(e.into()),
            Ok(_) => Ok(true),
        }
    }

    fn populate(&self) -> anyhow::Result<()> {
        let config = rpassword::ConfigBuilder::new()
            .password_feedback_mask('*')
            .build();

        let seed =
            rpassword::prompt_password_with_config(format!("seed for {}: ", self.key_name), config)
                .unwrap();

        self.key_ring.add_key(&self.key_name, &seed)?;

        Ok(())
    }

    fn seed(&self) -> anyhow::Result<Vec<u8>> {
        let key = self.key_ring.search(&self.key_name)?;

        key.read_to_vec().context("while reading key to vec")
    }
}

impl KeyUtils {}
