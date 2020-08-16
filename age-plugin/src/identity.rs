//! Identity plugin helpers.

use age_core::{
    format::{FileKey, Stanza},
    plugin::{self, BidirSend, Connection},
};
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;
use std::io;

const ADD_IDENTITY: &str = "add-identity";
const RECIPIENT_STANZA: &str = "recipient-stanza";

/// The interface that age plugins can use to interact with an age implementation.
pub trait Callbacks {
    /// Shows a message to the user.
    ///
    /// This can be used to prompt the user to take some physical action, such as
    /// inserting a hardware key.
    fn prompt(&mut self, message: &str) -> plugin::Result<(), ()>;

    /// Requests a secret value from the user, such as a passphrase.
    ///
    /// `message` will be displayed to the user, providing context for the request.
    fn request_secret(&mut self, message: &str) -> plugin::Result<SecretString, ()>;

    /// Sends an error.
    fn error(&mut self, error: Error) -> plugin::Result<(), ()>;
}

/// The interface that age implementations will use to interact with an age plugin.
pub trait IdentityPluginV1 {
    /// Stores an identity that the user would like to use for decrypting age files.
    ///
    /// `plugin_name` identifies the plugin that generated this identity. In most cases,
    /// it will be identical to the name of the plugin implementing this trait. However,
    /// age implementations look up plugins by their binary name, and if a plugin is
    /// renamed or aliased in the user's OS environment, it is possible for a plugin to
    /// receive identities that it does not support. Implementations must check
    /// `plugin_name` before using `identity`.
    fn add_identities<'a, I: Iterator<Item = &'a str>>(
        &mut self,
        identities: I,
    ) -> Result<(), Vec<Error>>;

    /// Attempts to unwrap the file keys contained within the given age recipient stanzas,
    /// using identities previously stored via [`add_identity`].
    ///
    /// `prompt` shows a message to the user. This can be used to prompt the user to take
    /// some physical action, such as inserting a hardware key.
    ///
    /// `request_secret` requests a secret value from the user, such as a passphrase. It
    /// takes a `message` will be displayed to the user, providing context for the
    /// request.
    ///
    /// [`add_identity`]: AgePlugin::add_identity
    fn unwrap_file_keys(
        &mut self,
        files: Vec<Vec<Stanza>>,
        callbacks: impl Callbacks,
    ) -> io::Result<HashMap<usize, FileKey>>;
}

/// The interface that age plugins can use to interact with an age implementation.
struct BidirCallbacks<'a, 'b, R: io::Read, W: io::Write>(&'b mut BidirSend<'a, R, W>);

impl<'a, 'b, R: io::Read, W: io::Write> Callbacks for BidirCallbacks<'a, 'b, R, W> {
    /// Shows a message to the user.
    ///
    /// This can be used to prompt the user to take some physical action, such as
    /// inserting a hardware key.
    fn prompt(&mut self, message: &str) -> plugin::Result<(), ()> {
        self.0
            .send("prompt", &[], message.as_bytes())
            .map(|res| res.map(|_| ()))
    }

    /// Requests a secret value from the user, such as a passphrase.
    ///
    /// `message` will be displayed to the user, providing context for the request.
    fn request_secret(&mut self, message: &str) -> plugin::Result<SecretString, ()> {
        self.0
            .send("request-secret", &[], message.as_bytes())
            .and_then(|res| match res {
                Ok(s) => String::from_utf8(s.body)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "secret is not UTF-8"))
                    .map(|s| Ok(SecretString::new(s))),
                Err(()) => Ok(Err(())),
            })
    }

    fn error(&mut self, error: Error) -> plugin::Result<(), ()> {
        error.send(self.0).map(|()| Ok(()))
    }
}

/// The kinds of errors that can occur within the identity plugin state machine.
pub enum Error {
    /// None of the stanzas with the given file index could be unwrapped with any of the
    /// provided identities.
    CouldNotUnwrapFileKey(usize),
    /// An error caused by a specific identity.
    Identity {
        /// The index of the identity.
        index: usize,
        /// The error message.
        message: String,
    },
    /// A general error that occured inside the state machine.
    Internal {
        /// The error message.
        message: String,
    },
    /// An error caused by a specific stanza.
    ///
    /// Note that unknown stanzas MUST be ignored by plugins; this error is only for
    /// stanzas that have a supported tag but are otherwise invalid (indicating an invalid
    /// age file).
    Stanza {
        /// The error message.
        message: String,
    },
}

impl Error {
    fn kind(&self) -> &str {
        match self {
            Error::CouldNotUnwrapFileKey(..) => "file",
            Error::Identity { .. } => "identity",
            Error::Internal { .. } => "internal",
            Error::Stanza { .. } => "stanza",
        }
    }

    fn message(&self) -> &str {
        match self {
            Error::CouldNotUnwrapFileKey(..) => "",
            Error::Identity { message, .. } => &message,
            Error::Internal { message } => &message,
            Error::Stanza { message } => &message,
        }
    }

    fn send<R: io::Read, W: io::Write>(self, phase: &mut BidirSend<R, W>) -> io::Result<()> {
        let index = match self {
            Error::CouldNotUnwrapFileKey(index) => Some(index.to_string()),
            Error::Identity { index, .. } => Some(index.to_string()),
            Error::Internal { .. } => None,
            Error::Stanza { .. } => None,
        };

        let metadata = match &index {
            Some(index) => vec![self.kind(), &index],
            None => vec![self.kind()],
        };

        phase
            .send("error", &metadata, self.message().as_bytes())?
            .unwrap();

        Ok(())
    }
}

/// Runs the recipient plugin v1 protocol.
///
/// This should be triggered if the `--identity-plugin-v1` flag is provided as an argument
/// when starting the plugin.
pub fn run_v1<P: IdentityPluginV1>(mut plugin: P) -> io::Result<()> {
    let mut conn = Connection::accept();

    // Phase 1: receive identities and stanzas
    let (identities, recipient_stanzas) = {
        let (identities, rest) = conn
            .unidir_receive(&[ADD_IDENTITY, RECIPIENT_STANZA])?
            .into_iter()
            .partition::<Vec<_>, _>(|s| s.tag == ADD_IDENTITY);
        (
            identities
                .into_iter()
                .map(|s| {
                    if s.args.len() == 1 && s.body.is_empty() {
                        Ok(s)
                    } else {
                        Err(Error::Internal {
                            message: format!(
                                "{} command must have exactly one metadata argument and no data",
                                ADD_IDENTITY
                            ),
                        })
                    }
                })
                .collect::<Result<Vec<_>, _>>(),
            rest.into_iter()
                .map(|mut s| {
                    if s.args.len() >= 2 {
                        let file_index = s.args.remove(0);
                        s.tag = s.args.remove(0);
                        file_index
                            .parse::<usize>()
                            .map(|i| (i, s))
                            .map_err(|_| Error::Internal {
                                message: format!(
                                    "first metadata argument to {} must be an integer",
                                    RECIPIENT_STANZA
                                ),
                            })
                    } else {
                        Err(Error::Internal {
                            message: format!(
                                "{} command must have at least two metadata arguments",
                                RECIPIENT_STANZA
                            ),
                        })
                    }
                })
                .collect::<Vec<_>>(),
        )
    };

    // Phase 2: interactively unwrap
    conn.bidir_send(|mut phase| {
        match identities {
            Ok(identities) => {
                if let Err(errors) = plugin
                    .add_identities(identities.iter().map(|s| s.args.first().unwrap().as_str()))
                {
                    for error in errors {
                        error.send(&mut phase)?;
                    }
                } else {
                    let mut stanzas: Vec<Vec<Stanza>> = Vec::new();
                    for recipient_stanza in recipient_stanzas {
                        match recipient_stanza {
                            Ok((file_index, stanza)) => {
                                if let Some(file) = stanzas.get_mut(file_index) {
                                    file.push(stanza);
                                } else if stanzas.len() == file_index {
                                    stanzas.push(vec![stanza]);
                                } else {
                                    Error::Internal {
                                        message: format!(
                                            "{} indices are not sequential",
                                            RECIPIENT_STANZA
                                        ),
                                    }
                                    .send(&mut phase)?;
                                }
                            }
                            Err(error) => error.send(&mut phase)?,
                        }
                    }

                    let num_files = stanzas.len();
                    let unwrapped = plugin.unwrap_file_keys(stanzas, BidirCallbacks(&mut phase))?;

                    for file_index in 0..num_files {
                        if let Some(file_key) = unwrapped.get(&file_index) {
                            phase
                                .send(
                                    "file-key",
                                    &[&format!("{}", file_index)],
                                    file_key.expose_secret(),
                                )?
                                .unwrap();
                        } else {
                            Error::CouldNotUnwrapFileKey(file_index).send(&mut phase)?;
                        }
                    }
                }
            }
            Err(error) => error.send(&mut phase)?,
        }
        Ok(())
    })?;

    Ok(())
}
