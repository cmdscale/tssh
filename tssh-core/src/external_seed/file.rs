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

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::external_seed::ExternalSeed;

#[derive(Serialize, Deserialize, Clone)]
pub struct FileSeedConf {
    pub path: String,
}

pub struct FileSeed {
    path: PathBuf,
}

impl FileSeed {
    pub fn from_config(config: FileSeedConf, _name: &str) -> Result<Self> {
        let path = PathBuf::from(&config.path);
        if !path.exists() {
            bail!("seed file path {} does not exist", path.to_string_lossy());
        }

        if !path.is_file() {
            bail!("seed {} is not a file", path.to_string_lossy());
        }

        Ok(Self { path })
    }
}

impl ExternalSeed for FileSeed {
    fn check(&self) -> Result<bool> {
        Ok(true)
    }

    fn populate(&self) -> Result<()> {
        Ok(())
    }

    fn seed(&self) -> Result<Vec<u8>> {
        std::fs::read(&self.path).context(format!(
            "while reading seed file {}",
            self.path.to_string_lossy()
        ))
    }
}
