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

use std::str::FromStr;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, digest::Output};
use ssh_key::Mpint;
use tss_esapi::{
    attributes::ObjectAttributes,
    constants::tss::{TPM2_RH_OWNER, TPM2_ST_HASHCHECK},
    interface_types::algorithm::HashingAlgorithm,
    structures::{
        CreatePrimaryKeyResult, EccParameter, EccPoint, HashScheme, HashcheckTicket, Public,
        PublicBuilder, PublicEccParametersBuilder, PublicKeyRsa, PublicRsaParameters, Signature,
    },
    tcti_ldr::DeviceConfig,
    tss2_esys::TPMT_TK_HASHCHECK,
};

use crate::sqlite::types::DBKey;

#[derive(Serialize, Deserialize, Clone)]
pub enum Template {
    RSA(RsaTemplate),
    ECC(EccTemplate),
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RsaTemplate {
    pub keybits: RsaKeyBits,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RsaKeyBits {
    Rsa1024 = 0,
    Rsa2048 = 1,
    Rsa3072 = 2,
    Rsa4096 = 3,
}

impl TryFrom<i32> for RsaKeyBits {
    type Error = anyhow::Error;

    fn try_from(value: i32) -> std::prelude::v1::Result<Self, Self::Error> {
        match value {
            0 => Ok(RsaKeyBits::Rsa1024),
            1 => Ok(RsaKeyBits::Rsa2048),
            2 => Ok(RsaKeyBits::Rsa3072),
            3 => Ok(RsaKeyBits::Rsa4096),
            _ => Err(anyhow::anyhow!("unknown rsa bits {}", value)),
        }
    }
}

impl From<RsaKeyBits> for HashingAlgorithm {
    fn from(value: RsaKeyBits) -> Self {
        match value {
            RsaKeyBits::Rsa1024 => HashingAlgorithm::Sha256,
            RsaKeyBits::Rsa2048 => HashingAlgorithm::Sha256,
            RsaKeyBits::Rsa3072 => HashingAlgorithm::Sha256,
            RsaKeyBits::Rsa4096 => HashingAlgorithm::Sha512,
        }
    }
}

impl RsaKeyBits {
    fn generate_salted_public_key(&self, a: &[u8], b: &[u8], c: &[u8]) -> Result<PublicKeyRsa> {
        let salt = Salt::new(a, b, c)
            .take(self.public_key_bytes())
            .collect::<Vec<u8>>();
        Ok(PublicKeyRsa::from_bytes(&salt[0..self.public_key_bytes()])?)
    }

    fn public_key_bytes(&self) -> usize {
        match self {
            RsaKeyBits::Rsa1024 => 128,
            RsaKeyBits::Rsa2048 => 256,
            RsaKeyBits::Rsa3072 => 384,
            RsaKeyBits::Rsa4096 => 512,
        }
    }
}

impl std::fmt::Display for RsaKeyBits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RsaKeyBits::Rsa1024 => write!(f, "Rsa1024"),
            RsaKeyBits::Rsa2048 => write!(f, "Rsa2048"),
            RsaKeyBits::Rsa3072 => write!(f, "Rsa3072"),
            RsaKeyBits::Rsa4096 => write!(f, "Rsa4096"),
        }
    }
}

impl From<RsaKeyBits> for tss_esapi::interface_types::key_bits::RsaKeyBits {
    fn from(value: RsaKeyBits) -> Self {
        match value {
            RsaKeyBits::Rsa1024 => tss_esapi::interface_types::key_bits::RsaKeyBits::Rsa1024,
            RsaKeyBits::Rsa2048 => tss_esapi::interface_types::key_bits::RsaKeyBits::Rsa2048,
            RsaKeyBits::Rsa3072 => tss_esapi::interface_types::key_bits::RsaKeyBits::Rsa3072,
            RsaKeyBits::Rsa4096 => tss_esapi::interface_types::key_bits::RsaKeyBits::Rsa4096,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct EccTemplate {
    pub curve: ECCCurve,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ECCCurve {
    NistP256 = 0,
    NistP384 = 1,
    NistP521 = 2,
}

impl TryFrom<tss_esapi::interface_types::ecc::EccCurve> for ECCCurve {
    type Error = anyhow::Error;

    fn try_from(
        value: tss_esapi::interface_types::ecc::EccCurve,
    ) -> std::prelude::v1::Result<Self, Self::Error> {
        match value {
            tss_esapi::interface_types::ecc::EccCurve::NistP256 => Ok(ECCCurve::NistP256),
            tss_esapi::interface_types::ecc::EccCurve::NistP384 => Ok(ECCCurve::NistP384),
            tss_esapi::interface_types::ecc::EccCurve::NistP521 => Ok(ECCCurve::NistP521),
            _ => anyhow::bail!("unsupported curve"),
        }
    }
}

impl ECCCurve {
    fn generate_salted_point(&self, a: &[u8], b: &[u8], c: &[u8]) -> Result<EccPoint> {
        let point_size = self.point_size();
        let salt = Salt::new(a, b, c).take(2 * point_size).collect::<Vec<u8>>();

        Ok(EccPoint::new(
            EccParameter::from_bytes(&salt[0..point_size])?,
            EccParameter::from_bytes(&salt[point_size..2 * point_size])?,
        ))
    }
    fn point_size(&self) -> usize {
        match self {
            ECCCurve::NistP256 => 32,
            ECCCurve::NistP384 => 48,
            ECCCurve::NistP521 => 66,
        }
    }
}

impl TryFrom<i32> for ECCCurve {
    type Error = anyhow::Error;

    fn try_from(value: i32) -> std::prelude::v1::Result<Self, Self::Error> {
        match value {
            0 => Ok(ECCCurve::NistP256),
            1 => Ok(ECCCurve::NistP384),
            2 => Ok(ECCCurve::NistP521),
            _ => Err(anyhow::anyhow!("unknown curve {}", value)),
        }
    }
}

impl std::fmt::Display for ECCCurve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ECCCurve::NistP256 => write!(f, "NistP256"),
            ECCCurve::NistP384 => write!(f, "NistP384"),
            ECCCurve::NistP521 => write!(f, "NistP521"),
        }
    }
}

impl From<ECCCurve> for HashingAlgorithm {
    fn from(value: ECCCurve) -> Self {
        match value {
            ECCCurve::NistP256 => HashingAlgorithm::Sha256,
            ECCCurve::NistP384 => HashingAlgorithm::Sha384,
            ECCCurve::NistP521 => HashingAlgorithm::Sha512,
        }
    }
}

impl From<ECCCurve> for tss_esapi::interface_types::ecc::EccCurve {
    fn from(val: ECCCurve) -> Self {
        match val {
            ECCCurve::NistP256 => tss_esapi::interface_types::ecc::EccCurve::NistP256,
            ECCCurve::NistP384 => tss_esapi::interface_types::ecc::EccCurve::NistP384,
            ECCCurve::NistP521 => tss_esapi::interface_types::ecc::EccCurve::NistP521,
        }
    }
}

impl Template {
    pub fn ecc_default() -> Self {
        Template::ECC(EccTemplate {
            curve: ECCCurve::NistP384,
        })
    }
    pub fn new_ecc(curve: ECCCurve) -> Self {
        Template::ECC(EccTemplate { curve })
    }

    pub fn new_rsa(keybits: RsaKeyBits) -> Self {
        Template::RSA(RsaTemplate { keybits })
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("json serialization failed")
    }
    pub fn get_type_string(&self) -> String {
        match self {
            Template::RSA(rsa_template) => format!("RSA {}", rsa_template.keybits),
            Template::ECC(ecc_template) => format!("ECC,{}", ecc_template.curve),
        }
    }

    pub fn signature_size(&self) -> usize {
        match self {
            Template::RSA(rsa_template) => rsa_template.keybits.public_key_bytes(),
            Template::ECC(ecc_template) => ecc_template.curve.point_size() * 2,
        }
    }
}

impl TryFrom<&str> for Template {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> std::prelude::v1::Result<Self, Self::Error> {
        serde_json::from_str(value).context("while parsing template json")
    }
}

pub struct HostTemplate {
    pub template: Template,
    pub user: String,
    pub host: String,
    pub port: u16,
}

impl HostTemplate {
    //TODO: might be better to introduce a builder ...
    pub fn new_default() -> Self {
        Self {
            host: "".to_string(),
            user: "".to_string(),
            port: 22,
            template: Template::ecc_default(),
        }
    }

    pub fn with_host(mut self, host: &str) -> Self {
        self.host = host.to_string();
        self
    }

    pub fn with_user(mut self, user: &str) -> Self {
        self.user = user.to_string();
        self
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    pub fn with_template(mut self, template: Template) -> Self {
        self.template = template;
        self
    }
}

impl TryFrom<&DBKey> for HostTemplate {
    type Error = anyhow::Error;

    fn try_from(value: &DBKey) -> std::prelude::v1::Result<Self, Self::Error> {
        let template =
            serde_json::from_str::<Template>(&value.template).context("while parsing template")?;

        Ok(Self {
            template,
            user: value.username.clone(),
            host: value.host.clone(),
            port: value.port,
        })
    }
}

impl TryFrom<&HostTemplate> for Public {
    type Error = anyhow::Error;
    fn try_from(host_template: &HostTemplate) -> Result<Self, Self::Error> {
        let object_attributes = ObjectAttributes::builder()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_sign_encrypt(true)
            .with_decrypt(false)
            .with_restricted(false)
            .with_user_with_auth(true)
            .build()?;

        let mut builder = PublicBuilder::new()
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes);

        match &host_template.template {
            Template::ECC(ecc_template) => {
                let ecc_params = PublicEccParametersBuilder::new()
                    .with_ecc_scheme(tss_esapi::structures::EccScheme::EcDsa(HashScheme::new(
                        ecc_template.curve.into(),
                    )))
                    .with_curve(ecc_template.curve.into())
                    .with_key_derivation_function_scheme(
                        tss_esapi::structures::KeyDerivationFunctionScheme::Null,
                    )
                    .with_restricted(false)
                    .with_is_signing_key(true)
                    .with_is_decryption_key(false)
                    .build()?;

                let salted_point = ecc_template
                    .curve
                    .generate_salted_point(
                        host_template.host.as_bytes(),
                        host_template.user.as_bytes(),
                        &host_template.port.to_le_bytes(),
                    )
                    .context("while constructing salted point")?;

                builder = builder
                    .with_public_algorithm(
                        tss_esapi::interface_types::algorithm::PublicAlgorithm::Ecc,
                    )
                    .with_name_hashing_algorithm(
                        tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256,
                    )
                    .with_ecc_parameters(ecc_params)
                    .with_ecc_unique_identifier(salted_point);
            }
            Template::RSA(rsa_template) => {
                let rsa_parameters = PublicRsaParameters::builder()
                    .with_scheme(tss_esapi::structures::RsaScheme::RsaSsa(HashScheme::new(
                        rsa_template.keybits.into(),
                    )))
                    .with_key_bits(rsa_template.keybits.into())
                    .with_is_signing_key(true)
                    .with_is_decryption_key(false)
                    .with_symmetric(tss_esapi::structures::SymmetricDefinitionObject::Null)
                    .with_restricted(false)
                    .build()
                    .context("while building rsa parameters")?;

                builder = builder
                    .with_rsa_parameters(rsa_parameters)
                    .with_public_algorithm(
                        tss_esapi::interface_types::algorithm::PublicAlgorithm::Rsa,
                    )
                    .with_name_hashing_algorithm(
                        tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256,
                    )
                    .with_rsa_unique_identifier(
                        rsa_template
                            .keybits
                            .generate_salted_public_key(
                                host_template.host.as_bytes(),
                                host_template.user.as_bytes(),
                                &host_template.port.to_le_bytes(),
                            )
                            .context("while constructing salted public key")?,
                    )
            }
        }

        builder.build().context("while constructing tpm public")
    }
}

pub struct TPMRsaPubKey {
    pub modulus: Vec<u8>,
    pub exponent: u32,
}

pub struct TPMEccPubKey {
    pub x: Vec<u8>,
    pub y: Vec<u8>,
}

impl TPMEccPubKey {
    pub fn get_cka_ec_point(&self) -> Result<Vec<u8>> {
        let mut raw_point = Vec::with_capacity(1 + self.x.len() + self.y.len());
        raw_point.push(0x04);
        raw_point.extend_from_slice(&self.x);
        raw_point.extend_from_slice(&self.y);

        let mut ret = Vec::new();
        ret.push(0x4);

        if raw_point.len() < 128 {
            ret.push(raw_point.len() as u8);
        } else {
            ret.push(0x81);
            ret.push(raw_point.len() as u8);
        }

        ret.extend(raw_point);
        Ok(ret)
    }
}

pub struct TPMPubKey {
    p: CreatePrimaryKeyResult,
}

impl TPMPubKey {
    pub fn get_ecc_pub_key(&self) -> Result<TPMEccPubKey> {
        let unique = match &self.p.out_public {
            Public::Ecc {
                object_attributes: _,
                name_hashing_algorithm: _,
                auth_policy: _,
                parameters: _,
                unique,
            } => unique,
            _ => return Err(anyhow::anyhow!("not an ecc key")),
        };

        Ok(TPMEccPubKey {
            x: unique.x().to_vec(),
            y: unique.y().to_vec(),
        })
    }

    pub fn get_rsa_pub_key(&self) -> Result<TPMRsaPubKey> {
        let Public::Rsa {
            object_attributes: _,
            name_hashing_algorithm: _,
            auth_policy: _,
            parameters,
            unique,
        } = &self.p.out_public
        else {
            bail!("not a rsa key")
        };

        let exponent = if parameters.exponent().value() == 0 {
            65537
        } else {
            parameters.exponent().value()
        };

        Ok(TPMRsaPubKey {
            modulus: unique.to_vec(),
            exponent,
        })
    }

    pub fn openssh_string(&self, key_name: &str) -> Result<String> {
        match &self.p.out_public {
            Public::Rsa {
                object_attributes: _,
                name_hashing_algorithm: _,
                auth_policy: _,
                parameters,
                unique,
            } => {
                let exponent = if parameters.exponent().value() == 0 {
                    65537
                } else {
                    parameters.exponent().value()
                };

                ssh_key::PublicKey::new(
                    ssh_key::public::KeyData::Rsa(ssh_key::public::RsaPublicKey {
                        e: Mpint::from_positive_bytes(exponent.to_be_bytes().as_slice())?,
                        n: Mpint::from_positive_bytes(unique)?,
                    }),
                    key_name,
                )
                .to_openssh()
                .context("while generating openssh rsa string")
            }
            Public::Ecc {
                object_attributes: _,
                name_hashing_algorithm: _,
                auth_policy: _,
                parameters,
                unique,
            } => {
                let x_bytes = unique.x().as_ref();
                let y_bytes = unique.y().as_ref();

                let point_size = ECCCurve::try_from(parameters.ecc_curve())?.point_size();

                if x_bytes.len() > point_size || y_bytes.len() > point_size {
                    anyhow::bail!("TPM returned wrong sized array");
                }

                let mut x_padded = vec![0u8; point_size];
                let mut y_padded = vec![0u8; point_size];

                x_padded[point_size - x_bytes.len()..].copy_from_slice(x_bytes);
                y_padded[point_size - y_bytes.len()..].copy_from_slice(y_bytes);

                let mut sec1_bytes = vec![0x04];
                sec1_bytes.extend_from_slice(&x_padded);
                sec1_bytes.extend_from_slice(&y_padded);

                let pub_key = ssh_key::public::EcdsaPublicKey::from_sec1_bytes(&sec1_bytes)?;

                ssh_key::PublicKey::new(ssh_key::public::KeyData::Ecdsa(pub_key), key_name)
                    .to_openssh()
                    .context("while generating openssh ecc string")
            }
            _ => todo!(),
        }
    }
}

impl From<CreatePrimaryKeyResult> for TPMPubKey {
    fn from(p: CreatePrimaryKeyResult) -> Self {
        Self { p }
    }
}

pub struct TPMContext {
    context: tss_esapi::Context,
}

impl TPMContext {
    pub fn new_default() -> Result<Self> {
        let context = tss_esapi::Context::new(tss_esapi::Tcti::Device(DeviceConfig::from_str(
            "/dev/tpmrm0",
        )?))?;

        Ok(Self { context })
    }
    pub fn get_supported_ecc_curves(&mut self) -> Vec<ECCCurve> {
        let mut ret = vec![];

        for c in [ECCCurve::NistP256, ECCCurve::NistP384, ECCCurve::NistP521] {
            if self
                .get_primary_key(&HostTemplate::new_default().with_template(Template::new_ecc(c)))
                .is_err()
            {
                continue;
            }
            ret.push(c);
        }

        ret
    }

    pub fn get_supported_rsa_key_bits(&mut self) -> Vec<RsaKeyBits> {
        let mut ret = vec![];

        for c in [
            RsaKeyBits::Rsa1024,
            RsaKeyBits::Rsa2048,
            RsaKeyBits::Rsa3072,
            RsaKeyBits::Rsa4096,
        ] {
            if self
                .get_primary_key(&HostTemplate::new_default().with_template(Template::new_rsa(c)))
                .is_err()
            {
                continue;
            }

            ret.push(c);
        }

        ret
    }

    pub fn get_primary_key(&mut self, host_template: &HostTemplate) -> Result<TPMPubKey> {
        let public = Public::try_from(host_template)?;
        self.context.set_sessions((
            Some(tss_esapi::interface_types::session_handles::AuthSession::Password),
            None,
            None,
        ));
        let ret = self
            .context
            .create_primary(
                tss_esapi::interface_types::reserved_handles::Hierarchy::Owner,
                public,
                None,
                None,
                None,
                None,
            )
            .context("while creating primary tpm key")?;

        self.context
            .flush_context(ret.key_handle.into())
            .context("while flushing key handle")?;

        Ok(ret.into())
    }

    pub fn sign_ecc(
        &mut self,
        public: Public,
        ecc_template: EccTemplate,
        blob: &[u8],
    ) -> Result<Vec<u8>> {
        self.context.set_sessions((
            Some(tss_esapi::interface_types::session_handles::AuthSession::Password),
            None,
            None,
        ));
        let create_primary_result = self
            .context
            .create_primary(
                tss_esapi::interface_types::reserved_handles::Hierarchy::Owner,
                public,
                None,
                None,
                None,
                None,
            )
            .context("while creating primary tpm key")?;

        let Public::Ecc {
            object_attributes: _,
            name_hashing_algorithm: _,
            auth_policy: _,
            parameters: _,
            unique: _,
        } = create_primary_result.out_public
        else {
            unreachable!()
        };

        let digest = tss_esapi::structures::Digest::from_bytes(blob).context("can't digest")?;

        let fake_hashcheck = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_OWNER,
            ..Default::default()
        };

        let fake_ticket =
            HashcheckTicket::try_from(fake_hashcheck).context("can't generate ticket")?;

        self.context.set_sessions((
            Some(tss_esapi::interface_types::session_handles::AuthSession::Password),
            None,
            None,
        ));
        let sign_result = self.context.sign(
            create_primary_result.key_handle,
            digest,
            tss_esapi::structures::SignatureScheme::EcDsa {
                scheme: HashScheme::new(ecc_template.curve.into()),
            },
            fake_ticket,
        )?;

        self.context
            .flush_context(create_primary_result.key_handle.into())
            .context("while flushing key handle")?;

        let Signature::EcDsa(ecc_signature) = sign_result else {
            unreachable!()
        };

        match ecc_template.curve {
            ECCCurve::NistP256 => {
                let r = *p256::FieldBytes::from_slice(ecc_signature.signature_r().as_bytes());
                let s = *p256::FieldBytes::from_slice(ecc_signature.signature_s().as_bytes());

                Ok(p256::ecdsa::Signature::from_scalars(r, s)?
                    .to_der()
                    .as_bytes()
                    .to_vec())
            }
            ECCCurve::NistP384 => {
                let r = *p384::FieldBytes::from_slice(ecc_signature.signature_r().as_bytes());
                let s = *p384::FieldBytes::from_slice(ecc_signature.signature_s().as_bytes());

                Ok(p384::ecdsa::Signature::from_scalars(r, s)?
                    .to_der()
                    .as_bytes()
                    .to_vec())
            }
            ECCCurve::NistP521 => {
                let r = *p521::FieldBytes::from_slice(ecc_signature.signature_r().as_bytes());
                let s = *p521::FieldBytes::from_slice(ecc_signature.signature_s().as_bytes());

                Ok(p521::ecdsa::Signature::from_scalars(r, s)?
                    .to_der()
                    .as_bytes()
                    .to_vec())
            }
        }
    }

    pub fn sign_rsa(
        &mut self,
        public: Public,
        rsa_template: RsaTemplate,
        blob: &[u8],
    ) -> Result<Vec<u8>> {
        self.context.set_sessions((
            Some(tss_esapi::interface_types::session_handles::AuthSession::Password),
            None,
            None,
        ));
        let create_primary_result = self
            .context
            .create_primary(
                tss_esapi::interface_types::reserved_handles::Hierarchy::Owner,
                public,
                None,
                None,
                None,
                None,
            )
            .context("while creating primary tpm key")?;

        let Public::Rsa {
            object_attributes: _,
            name_hashing_algorithm: _,
            auth_policy: _,
            parameters: _,
            unique: _,
        } = create_primary_result.out_public
        else {
            unreachable!()
        };

        let digest = tss_esapi::structures::Digest::from_bytes(blob).context("can't digest")?;

        let fake_hashcheck = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_OWNER,
            ..Default::default()
        };

        let fake_ticket =
            HashcheckTicket::try_from(fake_hashcheck).context("can't generate ticket")?;

        self.context.set_sessions((
            Some(tss_esapi::interface_types::session_handles::AuthSession::Password),
            None,
            None,
        ));
        let sign_result = self.context.sign(
            create_primary_result.key_handle,
            digest,
            tss_esapi::structures::SignatureScheme::RsaSsa {
                scheme: HashScheme::new(rsa_template.keybits.into()),
            },
            fake_ticket,
        )?;

        self.context
            .flush_context(create_primary_result.key_handle.into())
            .context("while flushing key handle")?;

        let Signature::RsaSsa(rsa_signature) = sign_result else {
            unreachable!()
        };
        Ok(rsa_signature.signature().to_vec())
    }

    pub fn sign(&mut self, host_template: &HostTemplate, blob: &[u8]) -> Result<Vec<u8>> {
        let public = Public::try_from(host_template)?;

        match &host_template.template {
            Template::RSA(rsa_template) => self.sign_rsa(public, rsa_template.clone(), blob),
            Template::ECC(ecc_template) => self.sign_ecc(public, ecc_template.clone(), blob),
        }
    }
}

pub struct Salt {
    hash: Output<sha2::Sha512>,
    idx: usize,
}

impl Salt {
    fn new(a: &[u8], b: &[u8], c: &[u8]) -> Self {
        let mut hasher = sha2::Sha512::new();
        hasher.update(a);
        hasher.update(b);
        hasher.update(c);

        let hash = hasher.finalize();

        Self { hash, idx: 0 }
    }
}

impl Iterator for Salt {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        let ret = self.hash[self.idx % self.hash.len()];
        self.idx = self.idx.wrapping_add(1);
        Some(ret)
    }
}
