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

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::sqlite::types::DBExternalSeed;

#[cfg(target_os = "linux")]
pub mod key_utils;

pub mod file;

pub trait ExternalSeed {
    //type Config: Serialize + DeserializeOwned + Clone;
    //fn from_config(config: Self::Config, name: &str) -> Result<Self>;
    //checks if populate is neccessary
    fn check(&self) -> Result<bool>;
    //populates if neccessary
    fn populate(&self) -> Result<()>;
    //gets the seed
    fn seed(&self) -> Result<Vec<u8>>;
}

#[derive(Serialize, Deserialize)]
pub enum SeedConfig {
    #[cfg(target_os = "linux")]
    KeyUtils(key_utils::KeyUtilsConf),
    File(file::FileSeedConf),
}

impl TryFrom<&str> for SeedConfig {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> std::prelude::v1::Result<Self, Self::Error> {
        serde_json::from_str(value).context("while parsing SeedConfig")
    }
}

impl SeedConfig {
    pub fn seed(&self, name: &str) -> Result<Vec<u8>> {
        self.instance(name)?.seed()
    }

    pub fn check(&self, name: &str) -> Result<bool> {
        self.instance(name)?.check()
    }
    pub fn instance(&self, name: &str) -> Result<Box<dyn ExternalSeed>> {
        match self {
            #[cfg(target_os = "linux")]
            SeedConfig::KeyUtils(conf) => {
                let ret = key_utils::KeyUtils::from_config(conf.clone(), name)?;
                Ok(Box::new(ret))
            }
            SeedConfig::File(conf) => {
                let ret = file::FileSeed::from_config(conf.clone(), name)?;
                Ok(Box::new(ret))
            }
        }
    }

    pub fn get_type_string(&self) -> String {
        match self {
            #[cfg(target_os = "linux")]
            SeedConfig::KeyUtils(_conf) => "KeyUtils".into(),
            SeedConfig::File(_file_seed_conf) => "File".into(),
        }
    }

    pub fn serialze(self) -> Result<String> {
        serde_json::to_string(&self).context("while serializing seed config")
    }
}

pub fn instance_from_db_entity(external_seed: &DBExternalSeed) -> Result<Box<dyn ExternalSeed>> {
    let config = SeedConfig::try_from(external_seed.config.as_str())?;
    config.instance(&external_seed.name)
}
