//! Recipient plugin helpers.

use age_core::{
    format::{FileKey, Stanza},
    plugin::{Connection, UnidirSend},
};
use std::convert::TryInto;
use std::io;

const ADD_RECIPIENT: &str = "add-recipient";
const WRAP_FILE_KEY: &str = "wrap-file-key";
const RECIPIENT_STANZA: &str = "recipient-stanza";

/// The interface that age implementations will use to interact with an age plugin.
pub trait RecipientPluginV1 {
    /// Stores recipients that the user would like to encrypt age files.
    ///
    /// `plugin_name` identifies the plugin that generated this identity. In most cases,
    /// it will be identical to the name of the plugin implementing this trait. However,
    /// age implementations look up plugins by their binary name, and if a plugin is
    /// renamed or aliased in the user's OS environment, it is possible for a plugin to
    /// receive identities that it does not support. Implementations must check
    /// `plugin_name` before using `identity`.
    fn add_recipients<'a, I: Iterator<Item = &'a str>>(
        &mut self,
        recipients: I,
    ) -> Result<(), Vec<Error>>;

    /// Wraps `file_key` in an age recipient stanza that can be unwrapped by `recipient`.
    ///
    /// `plugin_name` identifies the plugin that generated this recipient. In most cases,
    /// it will be identical to the name of the plugin implementing this trait. However,
    /// age implementations look up plugins by their binary name, and if a plugin is
    /// renamed or aliased in the user's OS environment, it is possible for a plugin to
    /// receive identities that it does not support. Implementations must check
    /// `plugin_name` before using `recipient`.
    fn wrap_file_key(&mut self, file_key: &FileKey) -> Result<Vec<Stanza>, Vec<Error>>;
}

/// The kinds of errors that can occur within the recipient plugin state machine.
pub enum Error {
    /// An error caused by a specific recipient.
    Recipient {
        /// The index of the recipient.
        index: usize,
        /// The error message.
        message: String,
    },
    /// A general error that occured inside the state machine.
    Internal {
        /// The error message.
        message: String,
    },
}

impl Error {
    fn kind(&self) -> &str {
        match self {
            Error::Recipient { .. } => "recipient",
            Error::Internal { .. } => "internal",
        }
    }

    fn message(&self) -> &str {
        match self {
            Error::Recipient { message, .. } => &message,
            Error::Internal { message } => &message,
        }
    }

    fn send<R: io::Read, W: io::Write>(self, phase: &mut UnidirSend<R, W>) -> io::Result<()> {
        let index = match self {
            Error::Recipient { index, .. } => Some(index.to_string()),
            Error::Internal { .. } => None,
        };

        let metadata = match &index {
            Some(index) => vec![self.kind(), &index],
            None => vec![self.kind()],
        };

        phase.send("error", &metadata, self.message().as_bytes())
    }
}

/// Runs the recipient plugin v1 protocol.
///
/// This should be triggered if the `--recipient-plugin-v1` flag is provided as an
/// argument when starting the plugin.
pub fn run_v1<P: RecipientPluginV1>(mut plugin: P) -> io::Result<()> {
    let mut conn = Connection::accept();

    // Phase 1: collect recipients
    let recipients = match conn
        .unidir_receive(&[ADD_RECIPIENT])?
        .into_iter()
        .map(|s| {
            if s.args.len() == 1 && s.body.is_empty() {
                Ok(s)
            } else {
                Err(Error::Internal {
                    message: format!(
                        "{} command must have exactly one metadata argument and no data",
                        ADD_RECIPIENT
                    ),
                })
            }
        })
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(r) if r.is_empty() => Err(Error::Internal {
            message: format!("Need at least one {} command", ADD_RECIPIENT),
        }),
        r => r,
    };

    // Phase 2: return errors
    conn.unidir_send(|mut phase| {
        match recipients {
            Ok(recipients) => {
                if let Err(errors) = plugin
                    .add_recipients(recipients.iter().map(|s| s.args.first().unwrap().as_str()))
                {
                    for error in errors {
                        error.send(&mut phase)?;
                    }
                }
            }
            Err(error) => error.send(&mut phase)?,
        }
        Ok(())
    })?;

    // Phase 3: receive file key to be wrapped
    let file_key = {
        let mut res = conn.unidir_receive(&[WRAP_FILE_KEY])?.into_iter();
        match (res.next(), res.next()) {
            (Some(s), None) => TryInto::<[u8; 16]>::try_into(&s.body[..])
                .map_err(|_| Error::Internal {
                    message: "invalid file key length".to_owned(),
                })
                .map(FileKey::from),
            (Some(_), Some(_)) => Err(Error::Internal {
                message: format!("received more than one {} command", WRAP_FILE_KEY),
            }),
            (None, None) => Err(Error::Internal {
                message: format!("missing {} command", WRAP_FILE_KEY),
            }),
            (None, Some(_)) => unreachable!(),
        }
    };

    // Phase 4: wrap the file key
    conn.unidir_send(|mut phase| {
        match file_key {
            Ok(file_key) => match plugin.wrap_file_key(&file_key) {
                Ok(stanzas) => {
                    for stanza in stanzas {
                        phase.send_stanza(RECIPIENT_STANZA, &["0"], &stanza)?;
                    }
                }
                Err(errors) => {
                    for error in errors {
                        error.send(&mut phase)?;
                    }
                }
            },
            Err(error) => error.send(&mut phase)?,
        }
        Ok(())
    })?;

    Ok(())
}
