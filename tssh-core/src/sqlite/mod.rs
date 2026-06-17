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
use rusqlite::{Connection, OptionalExtension};

use crate::sqlite::types::{DBDefaults, DBKey, DBPage};

pub mod types;

refinery::embed_migrations!("migrations");

pub struct DB {
    c: Connection,
}

impl DB {
    pub fn new_in_memory() -> Result<Self> {
        let mut c = Connection::open_in_memory()?;

        migrations::runner().run(&mut c)?;

        Ok(Self { c })
    }

    //TODO: Global dir environment ..
    pub fn new() -> Result<Self> {
        const DATA_DIR_NAME: &str = "tssh";
        const DB_NAME: &str = "tssh.db";

        let Some(data_path) = dirs::data_dir() else {
            return Err(anyhow::anyhow!("data directory does not exist"));
        };

        let tssh_data_dir = data_path.join(DATA_DIR_NAME);

        std::fs::create_dir_all(&tssh_data_dir).context("while creating tssh data directory")?;

        let tssh_db_path = tssh_data_dir.join(DB_NAME);

        let mut c = Connection::open(tssh_db_path).context("while opening tssh data base")?;

        migrations::runner().run(&mut c)?;

        Ok(Self { c })
    }

    pub fn add_key(&self, mut key: DBKey) -> Result<DBKey> {
        key.validate()?;

        const STMT: &str = "
INSERT INTO Keys(pkcs11_id,host,username,port,pub_key,template)
VALUES (?1,?2,?3,?4,?5,?6)
RETURNING id
";

        let mut stmt = self.c.prepare(STMT)?;
        stmt.query_row(
            (
                key.pkcs11_id.clone(),
                key.host.clone(),
                key.username.clone(),
                key.port,
                key.pub_key.clone(),
                key.template.clone(),
            ),
            |r| {
                key.id = r.get(0)?;
                Ok(key)
            },
        )
        .context("while adding key to DB")
    }

    pub fn get_all_keys(&self) -> Result<Vec<DBKey>> {
        const STMT: &str = "
SELECT
id,
pkcs11_id,
host,
username,
port,
pub_key,
template,
backup_key_id
FROM KEYS
ORDER BY id ASC
";

        let mut stmt = self.c.prepare(STMT)?;

        let mut rows = stmt.query([])?;

        let mut ret = Vec::new();

        while let Some(r) = rows.next()? {
            ret.push(DBKey {
                id: r.get(0)?,
                pkcs11_id: r.get(1)?,
                host: r.get(2)?,
                username: r.get(3)?,
                port: r.get(4)?,
                pub_key: r.get(5)?,
                template: r.get(6)?,
                backup_key: r.get(7)?,
            });
        }

        Ok(ret)
    }

    pub fn get_keys(&self, page: DBPage) -> Result<Vec<DBKey>> {
        const STMT: &str = "
SELECT
id,
pkcs11_id,
host,
username,
port,
pub_key,
template,
backup_key_id
FROM KEYS
ORDER BY id ASC
LIMIT ?1 OFFSET ?2
";

        let mut stmt = self.c.prepare(STMT)?;

        let mut rows = stmt.query((page.limit(), page.offset()))?;

        let mut ret = Vec::new();

        while let Some(r) = rows.next()? {
            ret.push(DBKey {
                id: r.get(0)?,
                pkcs11_id: r.get(1)?,
                host: r.get(2)?,
                username: r.get(3)?,
                port: r.get(4)?,
                pub_key: r.get(5)?,
                template: r.get(6)?,
                backup_key: r.get(7)?,
            });
        }

        Ok(ret)
    }

    pub fn get_key_by_id(&self, id: i32) -> Result<DBKey> {
        const STMT: &str = "
SELECT
id,
pkcs11_id,
host,
username,
port,
pub_key,
template,
backup_key_id
FROM Keys
WHERE id=?1
";

        let mut stmt = self.c.prepare(STMT)?;

        Ok(stmt.query_row([id], |r| {
            Ok(DBKey {
                id: r.get(0)?,
                pkcs11_id: r.get(1)?,
                host: r.get(2)?,
                username: r.get(3)?,
                port: r.get(4)?,
                pub_key: r.get(5)?,
                template: r.get(6)?,
                backup_key: r.get(7)?,
            })
        })?)
    }

    pub fn get_key_by_pkcs11_id(&self, id: &str) -> Result<DBKey> {
        const STMT: &str = "
SELECT
id,
pkcs11_id,
host,
username,
port,
pub_key,
template,
backup_key_id
FROM Keys
WHERE pkcs11_id=?1
";

        let mut stmt = self.c.prepare(STMT)?;

        Ok(stmt.query_row([id], |r| {
            Ok(DBKey {
                id: r.get(0)?,
                pkcs11_id: r.get(1)?,
                host: r.get(2)?,
                username: r.get(3)?,
                port: r.get(4)?,
                pub_key: r.get(5)?,
                template: r.get(6)?,
                backup_key: r.get(7)?,
            })
        })?)
    }

    pub fn get_key_by_login(&self, host: &str, username: &str, port: u16) -> Result<DBKey> {
        const STMT: &str = "
SELECT
id,
pkcs11_id,
host,
username,
port,
pub_key,
template,
backup_key_id
FROM Keys
WHERE host=?1 AND username=?2 AND port=?3
";

        let mut stmt = self.c.prepare(STMT)?;

        Ok(stmt.query_row((host, username, port), |r| {
            Ok(DBKey {
                id: r.get(0)?,
                pkcs11_id: r.get(1)?,
                host: r.get(2)?,
                username: r.get(3)?,
                port: r.get(4)?,
                pub_key: r.get(5)?,
                template: r.get(6)?,
                backup_key: r.get(7)?,
            })
        })?)
    }

    pub fn clear(&self) -> Result<()> {
        const STMT: &str = "DELETE FROM Keys";

        self.c.execute(STMT, [])?;
        Ok(())
    }

    pub fn delete_id(&self, id: i32) -> Result<()> {
        const STMT: &str = "DELETE FROM Keys WHERE id=?1";

        if self.c.execute(STMT, [id])? == 0 {
            return Err(anyhow::anyhow!("Key with id {id} not found"));
        }
        Ok(())
    }

    pub fn delete_login(&self, host: &str, username: &str, port: u16) -> Result<()> {
        const STMT: &str = "DELETE FROM Keys WHERE host=?1 AND username=?2 AND port=?3";

        if self.c.execute(STMT, (host, username, port))? == 0 {
            return Err(anyhow::anyhow!(
                "Key with id {username}@{host}:{port} not found"
            ));
        }
        Ok(())
    }

    pub fn get_defaults(&self) -> Result<Option<DBDefaults>> {
        const STMT: &str = "
SELECT
id,
default_ecc,
default_rsa
FROM Defaults
";

        let mut stmt = self.c.prepare(STMT)?;

        stmt.query_row([], |r| {
            Ok(DBDefaults {
                id: r.get(0)?,
                default_ecc: r.get(1)?,
                default_rsa: r.get(2)?,
            })
        })
        .optional()
        .context("while getting defaults")
    }

    pub fn set_defaults(&self, defaults: &DBDefaults) -> Result<()> {
        const STMT: &str = "
INSERT OR REPLACE into Defaults (id,default_ecc,default_rsa)
VALUES (1,?1,?2)
";
        let mut stmt = self.c.prepare(STMT)?;
        stmt.execute([defaults.default_ecc, defaults.default_rsa])?;
        Ok(())
    }
}

#[test]
fn keys() -> Result<()> {
    let db = DB::new_in_memory()?;

    let keys = db
        .get_keys(DBPage::default())
        .context("while getting keys")?;
    assert!(keys.is_empty());

    let keys = db.get_all_keys().context("while getting all keys")?;
    assert!(keys.is_empty());

    let key = DBKey::generate_random_key();
    let ret = db.add_key(key).context("while adding key")?;

    let keys = db.get_keys(DBPage::default())?;
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0], ret);

    let keys = db.get_all_keys()?;
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0], ret);

    let key = db.get_key_by_pkcs11_id(&ret.pkcs11_id)?;
    assert_eq!(key, ret);

    let key = db.get_key_by_login(&ret.host, &ret.username, ret.port)?;
    assert_eq!(key, ret);

    let key = db.get_key_by_id(ret.id)?;
    assert_eq!(key, ret);

    //getting an unknown key is an error
    let err = db.get_key_by_pkcs11_id("???");
    assert!(err.is_err());

    //adding a key with same pkcs11 id must fail
    let mut key = DBKey::generate_random_key();
    key.pkcs11_id = ret.pkcs11_id;
    let err = db.add_key(key);
    assert!(err.is_err());

    //adding a key with same user,host,port combination must fail
    let mut key = DBKey::generate_random_key();
    key.host = ret.host;
    key.username = ret.username;
    key.port =ret.port;
    let err = db.add_key(key);
    assert!(err.is_err());

    db.clear()?;

    assert!(db.get_keys(DBPage::default())?.is_empty());

    Ok(())
}

#[test]
fn delete_id() -> Result<()> {
    let db = DB::new_in_memory()?;

    let key = DBKey::generate_random_key();
    let ret = db.add_key(key).context("while adding key")?;

    assert!(db.delete_id(ret.id + 1).is_err());

    assert!(db.get_key_by_id(ret.id).is_ok());

    assert!(db.delete_id(ret.id).is_ok());

    assert!(db.get_key_by_id(ret.id).is_err());

    Ok(())
}

#[test]
fn delete_login() -> Result<()> {
    let db = DB::new_in_memory()?;

    let key = DBKey::generate_random_key();
    let ret = db.add_key(key).context("while adding key")?;

    assert!(db.delete_login("??", &ret.username, ret.port).is_err());

    assert!(db.get_key_by_id(ret.id).is_ok());

    assert!(db.delete_login(&ret.host, &ret.username, ret.port).is_ok());

    assert!(db.get_key_by_id(ret.id).is_err());

    Ok(())
}

#[test]
fn defaults() -> Result<()> {
    let db = DB::new_in_memory()?;

    let ret_defaults = db.get_defaults()?;

    assert!(ret_defaults.is_none());

    let defaults = DBDefaults::generate_random().with_id(1);

    db.set_defaults(&defaults)?;

    let ret_defaults = db.get_defaults()?;

    assert!(ret_defaults.is_some());

    assert_eq!(defaults, ret_defaults.unwrap());

    let defaults = defaults.with_default_rsa(None).with_default_ecc(None);

    db.set_defaults(&defaults)?;

    let ret_defaults = db.get_defaults()?;

    assert!(ret_defaults.is_some());

    assert_eq!(defaults, ret_defaults.unwrap());

    Ok(())
}
