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

use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::{fs::OpenOptions, io::Write};

use anyhow::{Context, Result};

use tssh_core::sqlite::types::DBKeySeedTuple;
use tssh_core::tpm::HostTemplate;

pub struct DirEnv {
    pub data_dir: PathBuf,
    pub lib_path: PathBuf,
}

#[derive(Clone)]
pub struct FileEntry {
    host: String,
    username: String,
    port: u16,
    accepted_algorithms: String,
    pkcs11_provider: String,
    identity_file: String,
}

impl FileEntry {
    fn as_file_entry(&self) -> String {
        format!(
            "Host {}\n\tUser {}\n\tPort {}\n\tPKCS11Provider {}\n\tPubkeyAcceptedAlgorithms {}\n\tIdentityFile \"{}\"\n\tIdentitiesOnly yes\n\n",
            self.host,
            self.username,
            self.port,
            self.pkcs11_provider,
            self.accepted_algorithms,
            self.identity_file
        )
    }
}

impl TryFrom<(DBKeySeedTuple, &str, &str)> for FileEntry {
    type Error = anyhow::Error;

    fn try_from(
        (db_key_tuple, lib_path, file_path): (DBKeySeedTuple, &str, &str),
    ) -> std::prelude::v1::Result<Self, Self::Error> {
        let host_template = HostTemplate::try_from(&db_key_tuple)
            .context("while parsing host template from db key")?;

        let accepted_algorithms = match host_template.template {
            tssh_core::tpm::Template::RSA(rsa_template) => match rsa_template.keybits {
                tssh_core::tpm::RsaKeyBits::Rsa1024 => "rsa-sha2-256",
                tssh_core::tpm::RsaKeyBits::Rsa2048 => "rsa-sha2-256",
                tssh_core::tpm::RsaKeyBits::Rsa3072 => "rsa-sha2-256",
                tssh_core::tpm::RsaKeyBits::Rsa4096 => "rsa-sha2-512",
            },
            tssh_core::tpm::Template::ECC(ecc_template) => match ecc_template.curve {
                tssh_core::tpm::ECCCurve::NistP256 => "ecdsa-sha2-nistp256",
                tssh_core::tpm::ECCCurve::NistP384 => "ecdsa-sha2-nistp384",
                tssh_core::tpm::ECCCurve::NistP521 => "ecdsa-sha2-nistp521",
            },
        };

        Ok(Self {
            host: db_key_tuple.key.host.clone(),
            username: db_key_tuple.key.username.clone(),
            port: db_key_tuple.key.port,
            pkcs11_provider: lib_path.to_string(),
            identity_file: file_path.to_string(),
            accepted_algorithms: accepted_algorithms.to_string(),
        })
    }
}

const KEY_DIR_NAME: &str = "keys";
const SSH_FILE_NAME: &str = "ssh_file";

pub fn write<T>(i: T, env: &DirEnv) -> Result<()>
where
    T: IntoIterator<Item = DBKeySeedTuple>,
{
    let tssh_key_dir = env.data_dir.join(KEY_DIR_NAME);

    let _ = std::fs::remove_dir_all(&tssh_key_dir); //TODO: better

    std::fs::create_dir_all(&tssh_key_dir).context("while creating tssh key directory")?;

    let tssh_ssh_file_path = env.data_dir.join(SSH_FILE_NAME);

    let mut ssh_file_content = String::new();

    for x in i.into_iter() {
        let file_path = tssh_key_dir.join(format!("{}.pub", x.key.pkcs11_id));

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&file_path)
            .context("while creating keyfile")?;

        file.write_all(x.key.pub_key.as_bytes())
            .context("while writing to keyfile")?;
        ssh_file_content.push_str(
            FileEntry::try_from((
                x,
                env.lib_path.to_string_lossy().to_string().as_str(),
                file_path.to_string_lossy().to_string().as_str(),
            ))?
            .as_file_entry()
            .as_str(),
        );
    }

    std::fs::write(tssh_ssh_file_path, ssh_file_content.as_bytes())
        .context("while writing ssh file")
}

pub fn generate_include(env: &DirEnv) -> Result<String> {
    let tssh_ssh_file_path = env.data_dir.join(SSH_FILE_NAME);
    Ok(format!("Include {}", tssh_ssh_file_path.to_string_lossy()))
}
