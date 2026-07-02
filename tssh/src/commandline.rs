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

use std::{fmt::Display, str::FromStr};

use anyhow::{Ok, bail};
use clap::{Args, Parser, Subcommand};
use tssh_core::{
    external_seed::{file::FileSeedConf, key_utils::KeyUtilsConf},
    tpm,
};

#[derive(Parser)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Add(AddKey),
    Get(GetKey),
    Delete(DeleteKey),
    Sync,
    List(List),
    Clear,
    Include(Include),
    Check,
    AddSeed(ExternalSeed),
    ListSeeds(List),
    PopulateSeed { id: i32 },
}

#[derive(Args, Debug)]
pub struct ExternalSeed {
    pub name: String,
    #[command(subcommand)]
    pub seed_type: SeedType,
}

#[derive(Subcommand, Debug)]
pub enum SeedType {
    #[cfg(target_os = "linux")]
    KeyUtils,
    File {
        path: String,
    },
}

impl From<SeedType> for tssh_core::external_seed::SeedConfig {
    fn from(value: SeedType) -> Self {
        match value {
            #[cfg(target_os = "linux")]
            SeedType::KeyUtils => tssh_core::external_seed::SeedConfig::KeyUtils(KeyUtilsConf {}),
            SeedType::File { path } => {
                tssh_core::external_seed::SeedConfig::File(FileSeedConf { path })
            }
        }
    }
}

#[derive(Args, Debug)]
pub struct List {
    #[arg(long, default_value_t = 0)]
    pub page: u32,
    #[arg(long, default_value_t = 101)]
    pub size: u32,
}

#[derive(Args, Debug)]
pub struct Include {
    #[arg(short, long)]
    pub raw: bool,
}

#[derive(Args, Debug)]
pub struct DeleteKey {
    pub id: Identifier,
}

#[derive(Args, Debug)]
pub struct AddKey {
    pub user: User,
    #[arg(long, default_value = "default-ecc")]
    pub kind: Kind,
    #[arg(long)]
    pub key_name: Option<String>,

    #[command(subcommand)]
    pub seed_mode: Option<SeedMode>,
}

impl AddKey {
    pub fn seed_mode(&self) -> SeedMode {
        self.seed_mode.clone().unwrap_or(SeedMode::AnyIfPresent)
    }
}

#[derive(Subcommand, Debug, Clone)]
pub enum SeedMode {
    None,
    AnyIfPresent,
    Any,
    Id { id: i32 },
}

#[derive(Args, Debug)]
pub struct GetKey {
    pub identifier: Identifier,
    #[arg(long)]
    pub raw: bool,
}

#[derive(Debug, Clone)]
pub struct User {
    pub host: String,
    pub username: String,
    pub port: u16,
}

impl FromStr for User {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        //TODO: better parsing

        let (username, rest) = s
            .split_once('@')
            .ok_or(anyhow::anyhow!("Expected format: username@host[:port]"))?;

        let (host, port_str) = rest.split_once(':').unwrap_or((rest, "22"));

        let port = port_str
            .parse::<u16>()
            .map_err(|_| anyhow::anyhow!("Invalid port number: {port_str}"))?;

        Ok(Self {
            host: host.to_string(),
            username: username.to_string(),
            port,
        })
    }
}

impl Display for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}:{}", self.username, self.host, self.port)
    }
}

#[derive(Debug, Clone)]
pub enum Identifier {
    Id(i32),
    User(User),
}

impl std::fmt::Display for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Identifier::Id(i) => write!(f, "{i}"),
            Identifier::User(user) => write!(f, "{user}"),
        }
    }
}

impl FromStr for Identifier {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains("@") {
            return Ok(Identifier::User(User::from_str(s)?));
        }

        Ok(Identifier::Id(i32::from_str(s).map_err(|_| {
            anyhow::anyhow!("expected i32 or username@host[:port]")
        })?))
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Kind {
    DefaultRsa,
    DefaultECC,
    FixedECC(tpm::ECCCurve),
    FixedRSA(tpm::RsaKeyBits),
}

impl FromStr for Kind {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let lower_s = s.to_lowercase();

        match lower_s.as_str() {
            "default-ecc" => Ok(Kind::DefaultECC),
            "default-rsa" => Ok(Kind::DefaultRsa),
            "nistp256" => Ok(Kind::FixedECC(tpm::ECCCurve::NistP256)),
            "nistp384" => Ok(Kind::FixedECC(tpm::ECCCurve::NistP384)),
            "nistp521" => Ok(Kind::FixedECC(tpm::ECCCurve::NistP521)),
            "rsa1024" => Ok(Kind::FixedRSA(tpm::RsaKeyBits::Rsa1024)),
            "rsa2048" => Ok(Kind::FixedRSA(tpm::RsaKeyBits::Rsa2048)),
            "rsa3072" => Ok(Kind::FixedRSA(tpm::RsaKeyBits::Rsa3072)),
            "rsa4096" => Ok(Kind::FixedRSA(tpm::RsaKeyBits::Rsa4096)),
            _ => bail!(
                "expected one of default-ecc, default-rsa, nistp256, nistp384, nistp521, rsa1024, rsa2048, rsa3072, rsa4096"
            ),
        }
    }
}
