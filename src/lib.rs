//! The passarg ("password argument") module implements
//! OpenSSL-style password/passphrase argument handling.
//!
//! # Quickstart
//!
//! ```rust
//! use clap::Parser;
//!
//! #[derive(Parser)]
//! struct Cli {
//!     #[arg(long, value_name = "SPEC", default_value = "env:MY_PASS_IN")]
//!     pass_in: String,
//!
//!     #[arg(long, value_name = "SPEC", default_value = "env:MY_PASS_OUT")]
//!     pass_out: String,
//! }
//!
//! fn main() -> Result<(), passarg::Error> {
//!     let cli = Cli::parse();
//!     let mut r = passarg::Reader::new();
//!     let pass_in = r.read_pass_arg(&cli.pass_in)?;
//!     let pass_out = r.read_pass_arg(&cli.pass_out)?;
//!     // ...
//!     Ok(())
//! }
//! ```
//!
//! The program above then by default reads the input/output passphrases
//! from the environment variables `${MY_PASS_IN}` and `${MY_PASS_OUT}`;
//! if run with `--pass-in file:dec-pass.txt --pass-out stdin`,
//! then it reads the input/output passphrases
//! from the file `dec-pass.txt` and the standard input respectively.
//!
//! # Passphrase Argument Syntax
//!
//! passarg supports the following OpenSSL-compatible arguments
//! ([openssl-passphrase-options(1)]):
//!
//! * **pass**:*password*
//!
//!   The actual password is *password*.
//!   Since the password is visible to utilities (like 'ps' under Unix)
//!   this form should only be used where security is not important.
//!
//! * **env**:*var*
//!
//!   Obtain the password from the environment variable *var*.
//!   Since the environment of other processes is visible on certain platforms
//!   (e.g. ps under certain Unix OSes)
//!   this option should be used with caution.
//!
//! * **file**:*pathname*
//!
//!   Reads the password from the specified file *pathname*,
//!   which can be a regular file, device, or named pipe.
//!   Only the first line, up to the newline character, is read from the stream.
//!
//!   If the same *pathname* argument is supplied
//!   to both **-passin** and **-passout** arguments,
//!   the first line will be used for the input password,
//!   and the next line will be used for the output password.
//!
//! * **fd**:*number*
//!
//!   Reads the password from the file descriptor *number*.
//!   This can be useful for sending data via a pipe, for example.
//!   The same line handling as described for **file:** applies
//!   to passwords read from file descriptors.
//!
//!   **fd:** is not supported on Windows.
//!
//! * **stdin**
//!
//!   Reads the password from standard input.
//!   The same line handling as described for **file:** applies
//!   to passwords read from standard input.
//!
//! passarg also supports the following non-OpenSSL extensions:
//!
//! * **prompt**\[:*text*]
//!
//!   Prompts the password using [`rpassword::prompt_password()`].
//!   If *text* is given, it is used as the prompt.
//!   Otherwise, `Password: ` is used.
//!
//! # Passargs Sharing Same File-like Source
//!
//! As explained in [Passphrase Argument Syntax](#passphrase-argument-syntax) above,
//! multiple passphrase arguments can share the same file-like source,
//! with each source reading one line from the source.
//!
//! The order of calls to [`Reader::read_pass_arg()`] matters, and should be documented.
//! For example, the [Quickstart example](#quickstart) above
//! reads `--pass-in` first then `--pass-out`,
//! implementing the same input-password-first ordering as with OpenSSL.
//!
//! [openssl-passphrase-options(1)]: https://docs.openssl.org/3.3/man1/openssl-passphrase-options/
//! [`rpassword::prompt_password()`]: https://docs.rs/rpassword/latest/rpassword/fn.prompt_password.html

use rpassword::prompt_password;
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{stdin, BufRead, BufReader, StdinLock};
use std::num::ParseIntError;
use std::os::fd::{FromRawFd, RawFd};

/// Errors that can arise while reading password argument.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid type {0}")]
    InvalidType(String),
    #[error("{0}")]
    EnvVar(#[from] env::VarError),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    FdLiteral(#[from] ParseIntError),
}

/// Password argument reader.
///
/// The main function, [Reader::read_pass_arg()], reads one password from the given source,
/// opening the resources (such as files, file descriptors) as needed.
///
/// When `Reader` goes out of scope, it closes all files and file descriptors opened it opened.
/// `Reader` leaves stdin open even when used.
pub struct Reader<'a> {
    files: HashMap<std::path::PathBuf, BufReader<File>>,
    fds: HashMap<RawFd, BufReader<File>>,
    stdin: Option<StdinLock<'a>>,
}

impl Reader<'_> {
    pub fn new() -> Self {
        Self {
            files: Default::default(),
            fds: Default::default(),
            stdin: None,
        }
    }

    /// Reads and returns a password from the given source (`arg`).
    /// See package documentation for the accepted formats of `arg`.
    pub fn read_pass_arg(&mut self, arg: &str) -> Result<String, Error> {
        let kv: Vec<&str> = arg.splitn(2, ":").collect();
        Ok(match kv[..] {
            [] => panic!("splitn returned nothing"),
            ["pass", password] => String::from(password),
            ["env", var] => env::var(var)?,
            ["file", path] => {
                let path = std::fs::canonicalize(path)?;
                let f = match self.files.get_mut(&path) {
                    Some(f) => f,
                    None => {
                        self.files.insert(path.clone(), BufReader::new(File::open(&path)?));
                        self.files.get_mut(&path).unwrap()
                    }
                };
                Self::read_from_bufreader(f)?
            }
            ["fd", fd] => {
                let fd = fd.parse::<RawFd>()?;
                let f = match self.fds.get_mut(&fd) {
                    Some(f) => f,
                    None => {
                        self.fds.insert(fd, BufReader::new(unsafe { File::from_raw_fd(fd) }));
                        self.fds.get_mut(&fd).unwrap()
                    }
                };
                Self::read_from_bufreader(f)?
            }
            ["stdin"] => {
                Self::read_from_bufreader(self.stdin.get_or_insert_with(|| stdin().lock()))?
            }
            ["prompt"] => prompt_password("Password: ")?,
            ["prompt", prompt] => prompt_password(prompt)?,
            [t, ..] => return Err(Error::InvalidType(t.into())),
        })
    }

    fn read_from_bufreader(r: &mut dyn BufRead) -> Result<String, Error> {
        let mut line = String::new();
        r.read_line(&mut line)?;
        Ok(line.trim_end_matches('\n').into())
    }
}
