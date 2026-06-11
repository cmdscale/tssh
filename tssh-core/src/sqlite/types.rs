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
#[derive(Debug, PartialEq, PartialOrd, Clone)]
pub struct DBKey {
    pub id: i32,
    pub backup_key: Option<i32>,
    pub pkcs11_id: String,
    pub username: String,
    pub host: String,
    pub port: u16,
    pub pub_key: String,
    pub template: String,
}

impl DBKey {
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
impl DBKey {
    pub fn generate_random_key() -> Self {
        use rand::{RngExt, distr::Alphanumeric};
        Self {
            id: rand::random_range(0..1111),
            backup_key: None,
            pkcs11_id: rand::rng()
                .sample_iter(Alphanumeric)
                .take(13)
                .map(char::from)
                .collect(),
            host: rand::rng()
                .sample_iter(Alphanumeric)
                .take(13)
                .map(char::from)
                .collect(),
            username: rand::rng()
                .sample_iter(Alphanumeric)
                .take(13)
                .map(char::from)
                .collect(),
            port: rand::random(),
            pub_key: rand::rng()
                .sample_iter(Alphanumeric)
                .take(13)
                .map(char::from)
                .collect(),
            template: "".to_string(),
        }
    }
}

#[derive(Debug, PartialEq, PartialOrd, Clone)]
pub struct DBDefaults {
    pub id: i32,
    pub default_ecc: Option<i32>,
    pub default_rsa: Option<i32>,
}

impl DBDefaults {
    pub fn with_id(mut self, id: i32) -> Self {
        self.id = id;
        self
    }

    pub fn with_default_ecc(mut self, default_ecc: Option<i32>) -> Self {
        self.default_ecc = default_ecc;
        self
    }
    pub fn with_default_rsa(mut self, default_rsa: Option<i32>) -> Self {
        self.default_rsa = default_rsa;
        self
    }
}

#[cfg(test)]
impl DBDefaults {
    pub fn generate_random() -> Self {
        Self {
            id: rand::random_range(0..1111),
            default_ecc: Some(rand::random_range(0..1111)),
            default_rsa: Some(rand::random_range(0..1111)),
        }
    }
}

pub struct DBPage {
    pub page: u32,
    pub size: u32,
}

impl DBPage {
    pub fn offset(&self) -> u32 {
        self.page * self.size
    }

    pub fn limit(&self) -> u32 {
        self.size
    }
}

impl Default for DBPage {
    fn default() -> Self {
        Self { page: 0, size: 101 }
    }
}
