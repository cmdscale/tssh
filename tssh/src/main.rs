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
use clap::Parser;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Table};
use ssh_writer::DirEnv;
use std::env;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::{fs::OpenOptions, path::PathBuf};
use tssh_core::sqlite::types::DBDefaults;
use tssh_core::sqlite::{
    DB,
    types::{DBKey, DBPage},
};
use tssh_core::tpm::{ECCCurve, RsaKeyBits, Template};
use xxhash_rust::xxh3::xxh3_64;

use rand::{RngExt, distr::Alphanumeric};
mod commandline;
mod ssh_writer;

const TSSH_LIB_BYTES: &[u8] = include_bytes!(env!("TSSH_CDYLIB_PATH"));

include!(concat!(env!("OUT_DIR"), "/checksum.rs"));

fn main() -> anyhow::Result<()> {
    //tpm-tss2 logs all to stdout/err we shut them up
    unsafe {
        env::set_var("TSS2_LOG", "all+NONE");
    }

    let _dir_env = ensure_dir_env()?;

    let db = DB::new()?;

    let commands = commandline::Cli::parse();

    match commands.command {
        commandline::Commands::Add(add_key) => handle_add(db, add_key),
        commandline::Commands::List(list) => handle_list(db, list),
        commandline::Commands::Clear => handle_clear(db),
        commandline::Commands::Get(get_key) => handle_get(db, get_key),
        commandline::Commands::Sync => handle_sync(db),
        commandline::Commands::Include(i) => handle_include(db, i),
        commandline::Commands::Check => handle_check(db),
        commandline::Commands::Delete(delete_key) => handle_delete(db, delete_key),
    }
}

fn handle_delete(db: DB, delete_key: commandline::DeleteKey) -> Result<()> {
    let ret = match &delete_key.id {
        commandline::Identifier::Id(id) => db.delete_id(*id),
        commandline::Identifier::User(user) => {
            db.delete_login(&user.host, &user.username, user.port)
        }
    };

    if let Err(e) = ret {
        println!("Can't delete key with id {}", delete_key.id);
        return Err(e);
    }
    handle_sync(db)
}

fn handle_check(_db: DB) -> Result<()> {
    let mut tpm = tssh_core::tpm::TPMContext::new_default()?;

    let supported = check_support(&mut tpm);

    for c in supported.supported_rsa.iter() {
        println!("\u{2714} {}", c);
    }

    for c in supported.supported_ecc.iter() {
        println!("\u{2714} {}", c);
    }

    println!(
        "Best Ecc: {}",
        supported
            .get_best_ecc()
            .map(|c| c.to_string())
            .unwrap_or("Not supported".to_string())
    );

    println!(
        "Best Rsa: {}",
        supported
            .get_best_rsa()
            .map(|c| c.to_string())
            .unwrap_or("Not supported".to_string())
    );

    Ok(())
}

fn handle_include(_db: DB, i: commandline::Include) -> Result<()> {
    let include = ssh_writer::generate_include(&ensure_dir_env()?)?;

    if i.raw {
        print!("{}", include);
        return Ok(());
    }
    println!("Let this be the first entry of your ssh config:\n\n{include}\n\n");

    Ok(())
}

fn handle_sync(db: DB) -> Result<()> {
    let entries = db.get_all_keys()?; //TODO: all keys..
    ssh_writer::write(entries, &ensure_dir_env()?)
}

fn handle_add(db: DB, add_key: commandline::AddKey) -> Result<()> {
    let mut tpm = tssh_core::tpm::TPMContext::new_default()?;
    let template_defaults = ensure_defaults(&mut tpm, &db)?;

    let template = match add_key.kind {
        commandline::Kind::DefaultRsa => Template::new_rsa(
            template_defaults
                .rsa_default
                .ok_or(anyhow::anyhow!("default rsa not set"))?,
        ),
        commandline::Kind::DefaultECC => Template::new_ecc(
            template_defaults
                .ecc_default
                .ok_or(anyhow::anyhow!("default rsa not set"))?,
        ),
        commandline::Kind::FixedECC(ecccurve) => Template::new_ecc(ecccurve),
        commandline::Kind::FixedRSA(rsa_key_bits) => Template::new_rsa(rsa_key_bits),
    };

    let host_template = tssh_core::tpm::HostTemplate::new_default()
        .with_host(&add_key.user.host)
        .with_user(&add_key.user.username)
        .with_port(add_key.user.port)
        .with_template(template);

    let key = tpm.get_primary_key(&host_template)?;
    db.add_key(DBKey {
        id: 0,
        backup_key: None,
        pkcs11_id: rand::rng()
            .sample_iter(Alphanumeric)
            .take(13)
            .map(char::from)
            .collect(),
        host: add_key.user.host,
        username: add_key.user.username,
        port: add_key.user.port,
        pub_key: key.openssh_string(&add_key.key_name.unwrap_or_default())?,
        template: host_template.template.to_json(),
    })?;
    handle_sync(db)?;
    Ok(())
}

fn handle_list(db: DB, list: commandline::List) -> Result<()> {
    let keys = db.get_keys(DBPage::new(list.page, list.size))?;

    let mut table = Table::new();

    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(comfy_table::ContentArrangement::DynamicFullWidth)
        .set_header(vec![
            Cell::new("Id").set_alignment(comfy_table::CellAlignment::Center),
            Cell::new("User").set_alignment(comfy_table::CellAlignment::Center),
            Cell::new("Type").set_alignment(comfy_table::CellAlignment::Center),
            Cell::new("Key").set_alignment(comfy_table::CellAlignment::Center),
        ]);

    for k in keys {
        table.add_row(vec![
            Cell::new(format!("{}", k.id)),
            Cell::new(format!("{}@{}:{}", k.username, k.host, k.port)),
            Cell::new(
                Template::try_from(k.template.as_str())?
                    .get_type_string()
                    .replace(",", "\n"),
            ),
            Cell::new(k.pub_key),
        ]);
    }

    println!("{table}");

    Ok(())
}

fn handle_get(db: DB, get_key: commandline::GetKey) -> Result<()> {
    let key = match get_key.identifier {
        commandline::Identifier::Id(id) => db.get_key_by_id(id)?,
        commandline::Identifier::User(user) => {
            db.get_key_by_login(&user.host, &user.username, user.port)?
        }
    };

    if get_key.raw {
        print!("{}", key.pub_key);
        return Ok(());
    }

    println!(
        "========== Key for {}@{}:{} =========\n\n{}\n",
        key.username, key.host, key.port, key.pub_key
    );

    Ok(())
}

fn handle_clear(db: DB) -> Result<()> {
    if let Err(e) = db.clear() {
        println!("Error while clearing db");
        return Err(e);
    }
    handle_sync(db)
}

pub fn ensure_dir_env() -> Result<DirEnv> {
    let Some(data_path) = dirs::data_dir() else {
        return Err(anyhow::anyhow!("data directory does not exist"));
    };

    const PKCS11_LIB: &str = "libtssh.so";
    const DATA_DIR_NAME: &str = "tssh";

    let data_dir = data_path.join(DATA_DIR_NAME);

    std::fs::create_dir_all(&data_dir).context("while creating tssh data directory")?;

    let lib_path = data_dir.join(PKCS11_LIB);

    if lib_path.exists() {
        if !lib_path.is_file() {
            return Err(anyhow::anyhow!(
                "{} must be a file",
                lib_path.to_string_lossy()
            ));
        }

        let lib_bytes = std::fs::read(&lib_path).context("while reading lib file")?;
        let old_checksum = xxh3_64(&lib_bytes);
        if old_checksum != TSSH_LIB_CHECK_SUM {
            write_pkcs11_lib(&lib_path).context("while updating lib")?;
        }

        return Ok(DirEnv { data_dir, lib_path });
    }

    write_pkcs11_lib(&lib_path)?;
    Ok(DirEnv { data_dir, lib_path })
}

pub fn ensure_defaults(tpm: &mut tssh_core::tpm::TPMContext, db: &DB) -> Result<TemplateDefaults> {
    if let Some(d) = db.get_defaults()? {
        let ecc_default = d.default_ecc.map(|c| c.try_into()).transpose()?;
        let rsa_default = d.default_rsa.map(|c| c.try_into()).transpose()?;

        return Ok(TemplateDefaults {
            ecc_default,
            rsa_default,
        });
    }

    let supported_algorithms = check_support(tpm);

    db.set_defaults(&DBDefaults {
        id: 1,
        default_ecc: supported_algorithms.get_best_ecc().map(|c| c as i32),
        default_rsa: supported_algorithms.get_best_rsa().map(|c| c as i32),
    })?;

    Ok(supported_algorithms.into())
}

pub fn write_pkcs11_lib(path: &PathBuf) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .context("while creating lib file")?;

    file.write_all(TSSH_LIB_BYTES)
        .context("while writing to libfile")
}

struct SupportedAlgorithms {
    supported_ecc: Vec<ECCCurve>,
    supported_rsa: Vec<RsaKeyBits>,
}
impl SupportedAlgorithms {
    fn new(mut supported_ecc: Vec<ECCCurve>, mut supported_rsa: Vec<RsaKeyBits>) -> Self {
        supported_rsa.sort();
        supported_ecc.sort();

        Self {
            supported_ecc,
            supported_rsa,
        }
    }

    fn get_best_rsa(&self) -> Option<RsaKeyBits> {
        self.supported_rsa.last().cloned()
    }
    fn get_best_ecc(&self) -> Option<ECCCurve> {
        self.supported_ecc.last().cloned()
    }
}

fn check_support(tpm: &mut tssh_core::tpm::TPMContext) -> SupportedAlgorithms {
    let supported_ecc = tpm.get_supported_ecc_curves();
    let supported_rsa = tpm.get_supported_rsa_key_bits();

    SupportedAlgorithms::new(supported_ecc, supported_rsa)
}

pub struct TemplateDefaults {
    ecc_default: Option<ECCCurve>,
    rsa_default: Option<RsaKeyBits>,
}

impl From<SupportedAlgorithms> for TemplateDefaults {
    fn from(value: SupportedAlgorithms) -> Self {
        Self {
            ecc_default: value.get_best_ecc(),
            rsa_default: value.get_best_rsa(),
        }
    }
}
