The `passarg ("password argument") module implements
OpenSSL-style password/passphrase argument handling.

# Quickstart

```rust
use clap::Parser;

#[derive(Parser)]
struct Cli {
    #[arg(long, value_name = "SPEC", default_value = "env:MY_PASS_IN")]
    pass_in: String,

    #[arg(long, value_name = "SPEC", default_value = "env:MY_PASS_OUT")]
    pass_out: String,
}

fn main() -> Result<(), passarg::Error> {
    let cli = Cli::parse();
    let mut r = passarg::Reader::new();
    let pass_in = r.read_pass_arg(&cli.pass_in)?;
    let pass_out = r.read_pass_arg(&cli.pass_out)?;
    // ...
    Ok(())
}
```

The program above then by default reads the input/output passphrases
from the environment variables `${MY_PASS_IN}` and `${MY_PASS_OUT}`;
if run with `--pass-in file:dec-pass.txt --pass-out stdin`,
then it reads the input/output passphrases
from the file `dec-pass.txt` and the standard input respectively.

# Passphrase Argument Syntax

passarg supports the following OpenSSL-compatible arguments
([openssl-passphrase-options(1)]):

* **pass**:*password*

  The actual password is *password*.
  Since the password is visible to utilities (like 'ps' under Unix)
  this form should only be used where security is not important.

* **env**:*var*

  Obtain the password from the environment variable *var*.
  Since the environment of other processes is visible on certain platforms
  (e.g. ps under certain Unix OSes)
  this option should be used with caution.

* **file**:*pathname*

  Reads the password from the specified file *pathname*,
  which can be a regular file, device, or named pipe.
  Only the first line, up to the newline character, is read from the stream.

  If the same *pathname* argument is supplied
  to both **-passin** and **-passout** arguments,
  the first line will be used for the input password,
  and the next line will be used for the output password.

* **fd**:*number*

  Reads the password from the file descriptor *number*.
  This can be useful for sending data via a pipe, for example.
  The same line handling as described for **file:** applies
  to passwords read from file descriptors.

  **fd:** is not supported on Windows.

* **stdin**

  Reads the password from standard input.
  The same line handling as described for **file:** applies
  to passwords read from standard input.

passarg also supports the following non-OpenSSL extensions:

* **prompt**\[:*text*]

  Prompts the password using [`rpassword::prompt_password()`].
  If *text* is given, it is used as the prompt.
  Otherwise, `Password: ` is used.

# Passargs Sharing Same File-like Source

As explained in [Passphrase Argument Syntax](#passphrase-argument-syntax) above,
multiple passphrase arguments can share the same file-like source,
with each source reading one line from the source.

The order of calls to [`Reader::read_pass_arg()`] matters, and should be documented.
For example, the [Quickstart example](#quickstart) above
reads `--pass-in` first then `--pass-out`,
implementing the same input-password-first ordering as with OpenSSL.

[openssl-passphrase-options(1)]: https://docs.openssl.org/3.3/man1/openssl-passphrase-options/
[`rpassword::prompt_password()`]: https://docs.rs/rpassword/latest/rpassword/fn.prompt_password.html
[`Reader::read_pass_arg()`]: https://docs.rs/passarg/latest/passarg/struct.Reader.html#method.read_pass_arg
