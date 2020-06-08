use age_core::{format::AgeStanza, primitives::aead_decrypt};
use secrecy::{ExposeSecret, Secret, SecretString};
use std::convert::TryInto;
use std::time::Duration;

use crate::{error::Error, keys::FileKey, primitives::scrypt, util::read::base64_arg};

pub(super) const SCRYPT_RECIPIENT_TAG: &str = "scrypt";
const SCRYPT_SALT_LABEL: &[u8] = b"age-encryption.org/v1/scrypt";
const ONE_SECOND: Duration = Duration::from_secs(1);

const SALT_LEN: usize = 16;
const ENCRYPTED_FILE_KEY_BYTES: usize = 32;

/// Pick an scrypt work factor that will take around 1 second on this device.
///
/// Guaranteed to return a valid work factor (less than 64).
fn target_scrypt_work_factor() -> u8 {
    // Time a work factor that should always be fast.
    let mut log_n = 10;

    let duration: Option<Duration> = {
        // Platforms that have a functional SystemTime::now():
        #[cfg(not(all(target_arch = "wasm32", not(target_os = "wasi"))))]
        {
            use std::time::SystemTime;
            let start = SystemTime::now();
            scrypt(&[], log_n, "").expect("log_n < 64");
            SystemTime::now().duration_since(start).ok()
        }

        // Platforms where SystemTime::now() panics:
        #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
        {
            None
        }
    };

    duration
        .map(|mut d| {
            // Use duration as a proxy for CPU usage, which scales linearly with N.
            while d < ONE_SECOND && log_n < 63 {
                log_n += 1;
                d *= 2;
            }
            log_n
        })
        .unwrap_or({
            // Couldn't measure, so guess. This is roughly 1 second on a modern machine.
            18
        })
}

#[derive(Debug)]
pub(crate) struct RecipientStanza {
    pub(crate) salt: [u8; SALT_LEN],
    pub(crate) log_n: u8,
    pub(crate) encrypted_file_key: [u8; ENCRYPTED_FILE_KEY_BYTES],
}

impl RecipientStanza {
    pub(super) fn from_stanza(stanza: AgeStanza<'_>) -> Option<Self> {
        if stanza.tag != SCRYPT_RECIPIENT_TAG {
            return None;
        }

        let salt = base64_arg(stanza.args.get(0)?, [0; SALT_LEN])?;
        let log_n = u8::from_str_radix(stanza.args.get(1)?, 10).ok()?;

        Some(RecipientStanza {
            salt,
            log_n,
            encrypted_file_key: stanza.body[..].try_into().ok()?,
        })
    }

    pub(crate) fn unwrap_file_key(
        &self,
        passphrase: &SecretString,
        max_work_factor: Option<u8>,
    ) -> Result<Option<FileKey>, Error> {
        // Place bounds on the work factor we will accept (roughly 16 seconds).
        let target = target_scrypt_work_factor();
        if self.log_n > max_work_factor.unwrap_or_else(|| target + 4) {
            return Err(Error::ExcessiveWork {
                required: self.log_n,
                target,
            });
        }

        let mut inner_salt = vec![];
        inner_salt.extend_from_slice(SCRYPT_SALT_LABEL);
        inner_salt.extend_from_slice(&self.salt);

        let enc_key =
            scrypt(&inner_salt, self.log_n, passphrase.expose_secret()).map_err(|_| {
                Error::ExcessiveWork {
                    required: self.log_n,
                    target,
                }
            })?;
        aead_decrypt(&enc_key, &self.encrypted_file_key)
            .map(|pt| {
                // It's ours!
                let mut file_key = [0; 16];
                file_key.copy_from_slice(&pt);
                Some(FileKey(Secret::new(file_key)))
            })
            .map_err(Error::from)
    }
}

pub(super) mod write {
    use age_core::format::write::age_stanza;
    use cookie_factory::{SerializeFn, WriteContext};
    use std::io::Write;

    use super::*;

    pub(crate) fn recipient_stanza<'a, W: 'a + Write>(
        r: &'a RecipientStanza,
    ) -> impl SerializeFn<W> + 'a {
        move |w: WriteContext<W>| {
            let encoded_salt = base64::encode_config(&r.salt, base64::STANDARD_NO_PAD);
            let args = &[encoded_salt.as_str(), &format!("{}", r.log_n)];
            let writer = age_stanza(SCRYPT_RECIPIENT_TAG, args, &r.encrypted_file_key);
            writer(w)
        }
    }
}
