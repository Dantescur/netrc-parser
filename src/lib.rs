#![feature(closure_lifetime_binder)]

//! A modern and idiomatic .netrc parser in Rust
//!
//! This library provides a robust parser for `.netrc` files, supporting machine
//! entries, login credentials, accounts, and macro definitions (`macdef`). It
//! includes serialization to JSON and TOML, file I/O, and comprehensive error
//! handling.
//!
//! The parser handles standard `.netrc` file formats, validates machine names,
//! and supports flexible input with whitespace. Errors are reported via the
//! `NetrcError` enum, which includes detailed parse error messages and input
//! context.
//!
//! # Example
//!
//! ```
//! use netrc_rs::{Netrc, NetrcError};
//!
//! let input = "machine example.com login user password pass";
//! let netrc = Netrc::parse_from_str(input,)?;
//! let creds = netrc
//!     .get("example.com",)
//!     .ok_or_else(|| NetrcError::NotFound("example.com".to_string(),),)?;
//! assert_eq!(creds.login, "user");
//! assert_eq!(creds.password, "pass");
//! # Ok::<(), NetrcError>(())
//! ```

mod error;
pub use error::NetrcError;
use log::{debug, error, info, warn};
use nom::{IResult, Parser,
          branch::alt,
          bytes::complete::{tag, take_while1},
          character::complete::{line_ending, multispace0, multispace1, not_line_ending},
          combinator::{all_consuming, eof, opt},
          multi::many0};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, path::Path};

/// Represents a single machine entry in a `.netrc` file.
///
/// Each entry contains a machine name (or "default"), login credentials, an
/// optional account, and an optional macro definition (`macdef`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize,)]
pub struct NetrcMachine {
    pub machine: String,
    pub login: String,
    pub password: String,
    pub account: Option<String,>,
    pub macdef: Option<String,>,
}

/// Represents a complete `.netrc` file with multiple machine entries.
///
/// Stores machine entries in a `HashMap` keyed by machine name for efficient
/// lookup. Provides methods for parsing, serialization, and manipulation of
/// entries.
#[derive(Debug, Default, Deserialize, Serialize,)]
pub struct Netrc {
    pub machines: HashMap<String, NetrcMachine,>,
}

/// Checks if a character is valid for a token (non-whitespace).
///
/// Returns `true` for any non-whitespace character, used in token parsing.
fn is_token_char(c: char,) -> bool {
    !c.is_whitespace()
}

/// Parses a single token from input.
///
/// A token is a sequence of non-whitespace characters. Returns an error if no
/// valid token is found.
fn parse_token(input: &str,) -> IResult<&str, &str,> {
    take_while1(is_token_char,)(input,)
}

/// Parses a single machine entry from the input string.
///
/// The parser supports `machine` or `default` entries with `login`, `password`,
/// `account`, and `macdef` fields. A `macdef` block is terminated by an empty
/// line or end-of-input. Invalid machine names (empty or reserved keywords like
/// `login`, `password`, `account`, `macdef`) result in a parse error.
fn parse_machine(input: &str,) -> IResult<&str, NetrcMachine,> {
    debug!("Parsing machine entry from input: {:?}", input);
    let (input, _,) = multispace0(input,)?;
    let (input, key,): (&str, &str,) = alt((tag("machine",), tag("default",),),).parse(input,)?;
    debug!("Parsed key: {}", key);
    let (input, _,) = multispace1(input,)?;
    let (input, machine_name,) = if key == "default" {
        (input, "default",)
    } else {
        let (input, name,) = parse_token(input,).map_err(|_| {
            debug!("Failed to parse machine name");
            nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify,),)
        },)?;
        if name.trim().is_empty()
            || name == "login"
            || name == "password"
            || name == "account"
            || name == "macdef"
        {
            debug!("Invalid machine name: {}", name);
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Verify,
            ),),);
        }
        (input, name,)
    };
    debug!("Parsed machine name: {}", machine_name);

    let mut login = String::new();
    let mut password = String::new();
    let mut account = None;
    let mut macdef = None;
    let mut rest = input;

    loop {
        let (next_input, _,) = multispace0(rest,)?;
        if let Ok((next_input, _,),) = eof::<_, nom::error::Error<_,>,>(next_input,) {
            debug!("Reached end of input for machine: {}", machine_name);
            rest = next_input;
            break;
        }

        let (next_input, token,): (&str, Option<&str,>,) = opt(parse_token,).parse(next_input,)?;
        match token {
            Some("machine",) | Some("default",) => {
                debug!(
                    "Encountered new machine or default, stopping parsing for: {}",
                    machine_name
                );
                break;
            },
            Some("login",) => {
                let (next_input, _,) = multispace1(next_input,)?;
                let (next_input, val,) = parse_token(next_input,).map_err(|_| {
                    debug!("Failed to parse login token for machine: {}", machine_name);
                    nom::Err::Failure(nom::error::Error::new(
                        next_input,
                        nom::error::ErrorKind::Verify,
                    ),)
                },)?;
                login = val.to_string();
                debug!("Parsed login: {} for machine: {}", login, machine_name);
                rest = next_input;
            },
            Some("password",) => {
                let (next_input, _,) = multispace1(next_input,)?;
                let (next_input, val,) = parse_token(next_input,).map_err(|_| {
                    debug!("Failed to parse password token for machine: {}", machine_name);
                    nom::Err::Error(nom::error::Error::new(
                        next_input,
                        nom::error::ErrorKind::Verify,
                    ),)
                },)?;
                password = val.to_string();
                debug!("Parsed password for machine: {}", machine_name);
                rest = next_input;
            },
            Some("account",) => {
                let (next_input, _,) = multispace1(next_input,)?;
                let (next_input, val,) = parse_token(next_input,).map_err(|_| {
                    debug!("Failed to parse account token for machine: {}", machine_name);
                    nom::Err::Error(nom::error::Error::new(
                        next_input,
                        nom::error::ErrorKind::Verify,
                    ),)
                },)?;
                account = Some(val.to_string(),);
                debug!("Parsed account: {} for machine: {}", val, machine_name);
                rest = next_input;
            },
            Some("macdef",) => {
                let (next_input, _,) = multispace1(next_input,)?;
                let (next_input, macdef_name,) = parse_token(next_input,).map_err(|_| {
                    debug!("Failed to parse macdef name for machine: {}", machine_name);
                    nom::Err::Error(nom::error::Error::new(
                        next_input,
                        nom::error::ErrorKind::Verify,
                    ),)
                },)?;
                debug!("Parsing macdef: {} for machine: {}", macdef_name, machine_name);
                let (next_input, _,) = line_ending(next_input,)?;

                let mut lines = Vec::new();
                let mut current_input = next_input;
                loop {
                    let (next, _,) = multispace0(current_input,)?;
                    let (next, line,) = not_line_ending(next,)?;
                    let (next, line_end,) = opt(line_ending,).parse(next,)?;
                    if line.trim().is_empty() && line_end.is_some() {
                        debug!("Reached empty line, ending macdef for machine: {}", machine_name);
                        current_input = next;
                        break;
                    }
                    if next.is_empty() {
                        debug!("Reached end of macdef for machine: {}", machine_name);
                        current_input = next;
                        break;
                    }
                    lines.push(line.to_string(),);
                    current_input = next;
                }

                let macdef_content = lines.join("\n",).trim_end().to_string();
                macdef =
                    Some(if macdef_content.is_empty() { "" } else { &macdef_content }.to_string(),);
                debug!("Parsed macdef content: {:?} for machine: {}", macdef, machine_name);
                rest = current_input;
            },
            Some(token,) => {
                warn!("Unexpected token: {} for machine: {}, skipping", token, machine_name);
                let (next_input, _,) = multispace0(next_input,)?;
                rest = next_input;
            },
            None => {
                debug!("No more tokens for machine: {}, stopping parsing", machine_name);
                rest = next_input;
                break;
            },
        }
    }

    if login.is_empty() {
        warn!("No login provided for machine: {}", machine_name);
    }
    if password.is_empty() {
        warn!("No password provided for machine: {}", machine_name);
    }

    Ok((
        rest,
        NetrcMachine { machine: machine_name.to_string(), login, password, account, macdef, },
    ),)
}

/// Parses an entire `.netrc` file content into a `Netrc` struct.
///
/// Consumes the input string and returns a `Netrc` containing all parsed
/// machine entries. Duplicate machine names result in a parse error.
fn parse_netrc(input: &str,) -> IResult<&str, Netrc,> {
    info!("Parsing entire .netrc content");
    let (input, machine_list,) = all_consuming(many0(parse_machine,),).parse(input,)?;
    debug!("Parsed {} machine entries", machine_list.len());
    let mut machines = HashMap::new();
    for machine in machine_list {
        if machines.contains_key(&machine.machine,) {
            error!("Duplicate machine entry found: {}", machine.machine);
            return Err(nom::Err::Failure(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Many1,
            ),),);
        }
        debug!("Adding machine entry: {}", machine.machine);
        machines.insert(machine.machine.clone(), machine,);
    }
    info!("Successfully parsed .netrc with {} machines", machines.len());
    Ok((input, Netrc { machines, },),)
}

impl Netrc {
    /// Parses a `.netrc` string into a `Netrc` struct.
    ///
    /// Returns a `Netrc` containing all machine entries or a `NetrcError` if
    /// parsing fails.
    ///
    /// # Example
    ///
    /// ```
    /// use netrc_rs::{Netrc, NetrcError};
    ///
    /// let input = "machine example.com login user password pass";
    /// let netrc = Netrc::parse_from_str(input,)?;
    /// assert_eq!(netrc.get("example.com").unwrap().login, "user");
    /// # Ok::<(), NetrcError>(())
    /// ```
    pub fn parse_from_str(input: &str,) -> Result<Self, NetrcError,> {
        info!("Parsing .netrc string");
        match parse_netrc(input,) {
            Ok((_, parsed,),) => {
                info!("Successfully parsed .netrc string");
                Ok(parsed,)
            },
            Err(e,) => {
                let err = match e {
                    nom::Err::Incomplete(_,) => {
                        NetrcError::Parse {
                            message: "incomplete input".to_string(),
                            input: input.to_string(),
                        }
                    },
                    nom::Err::Error(e,) => {
                        NetrcError::Parse {
                            message: format!("parse error: {:?}", e),
                            input: input.to_string(),
                        }
                    },
                    nom::Err::Failure(e,) if e.code == nom::error::ErrorKind::Many1 => {
                        NetrcError::DuplicateEntry("duplicate machine entry".to_string(),)
                    },
                    nom::Err::Failure(e,) => {
                        NetrcError::Parse {
                            message: format!("parse failure: {:?}", e),
                            input: input.to_string(),
                        }
                    },
                };
                error!("Failed to parse .netrc string: {}", err);
                Err(err,)
            },
        }
    }

    /// Reads and parses a `.netrc` file from the given path.
    ///
    /// Checks file permissions (must be 0600 or stricter on Unix) and returns a
    /// `Netrc` struct. Returns a `NetrcError` for I/O or parsing errors.
    ///
    /// # Example
    ///
    /// ```
    /// use netrc_rs::{Netrc, NetrcError};
    /// use std::fs;
    ///
    /// let temp_file = std::env::temp_dir().join("test_netrc_doc",);
    /// fs::write(&temp_file, "machine example.com login user password pass",)?;
    /// #[cfg(unix)]
    /// {
    ///     use std::os::unix::fs::PermissionsExt;
    ///     fs::set_permissions(&temp_file, fs::Permissions::from_mode(0o600,),)?;
    /// }
    /// let netrc = Netrc::parse_from_path(&temp_file,)?;
    /// if let Some(creds,) = netrc.get("example.com",) {
    ///     println!("Login: {}", creds.login);
    /// }
    /// fs::remove_file(&temp_file,)?;
    /// # Ok::<(), NetrcError>(())
    /// ```
    ///
    /// # Note
    ///
    /// On Unix systems, the file must have permissions set to `0600` (owner
    /// read/write only). Files with more permissive settings (e.g., group
    /// or world readable) will result in `NetrcError::InsecurePermissions`.
    pub fn parse_from_path<P: AsRef<Path,>,>(path: P,) -> Result<Self, NetrcError,> {
        let path = path.as_ref();
        info!("Reading and parsing .netrc file from path: {:?}", path);
        let metadata = fs::metadata(path,).map_err(|e| {
            error!("Failed to read metadata for {:?}: {}", path, e);
            if e.kind() == std::io::ErrorKind::NotFound {
                NetrcError::FileNotFound(path.display().to_string(),)
            } else {
                NetrcError::Io(e,)
            }
        },)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode();
            if mode & 0o077 != 0 {
                error!("File permissions for {:?} are too open: {:o}", path, mode);
                return Err(NetrcError::InsecurePermissions,);
            }
        }
        match fs::read_to_string(path,) {
            Ok(content,) => {
                debug!("Successfully read .netrc file from {:?}", path);
                Self::parse_from_str(&content,)
            },
            Err(e,) => {
                error!("Failed to read .netrc file from {:?}: Error: {}", path, e);
                if e.kind() == std::io::ErrorKind::NotFound {
                    Err(NetrcError::FileNotFound(path.display().to_string(),),)
                } else {
                    Err(NetrcError::Io(e,),)
                }
            },
        }
    }

    /// Retrieves a machine entry by its name.
    ///
    /// Returns `Some(&NetrcMachine)` if found, or `None` if no entry exists.
    pub fn get(&self, machine: &str,) -> Option<&NetrcMachine,> {
        debug!("Retrieving machine entry for: {}", machine);
        let result = self.machines.get(machine,);
        if result.is_none() {
            warn!("No machine entry found for: {}", machine);
        }
        result
    }

    /// Serializes the `Netrc` struct to JSON format.
    ///
    /// Returns a pretty-printed JSON string or a `NetrcError` if serialization
    /// fails.
    pub fn to_json(&self,) -> Result<String, NetrcError,> {
        info!("Serializing .netrc to JSON");
        match serde_json::to_string_pretty(self,) {
            Ok(json,) => {
                debug!("Successfully serialized .netrc to JSON");
                Ok(json,)
            },
            Err(e,) => {
                error!("Failed to serialize .netrc to JSON: {}", e);
                Err(NetrcError::Serialize(e.to_string(),),)
            },
        }
    }

    /// Serializes the `Netrc` struct to TOML format.
    ///
    /// Returns a pretty-printed TOML string or a `NetrcError` if serialization
    /// fails.
    pub fn to_toml(&self,) -> Result<String, NetrcError,> {
        info!("Serializing .netrc to TOML");
        match toml::to_string_pretty(self,) {
            Ok(toml,) => {
                debug!("Successfully serialized .netrc to TOML");
                Ok(toml,)
            },
            Err(e,) => {
                error!("Failed to serialize .netrc to TOML: {}", e);
                Err(NetrcError::Serialize(e.to_string(),),)
            },
        }
    }

    /// Inserts or replaces a machine entry in the `Netrc`.
    ///
    /// Overwrites any existing entry with the same machine name.
    pub fn insert_machine(&mut self, machine: NetrcMachine,) {
        info!("Inserting or replacing machine entry: {}", machine.machine);
        self.machines.insert(machine.machine.clone(), machine,);
        debug!("Machine entry inserted: {}", self.machines.len());
    }

    /// Removes a machine entry by name.
    ///
    /// Returns the removed `NetrcMachine` if found, or `None` if no entry
    /// exists.
    pub fn remove_machine(&mut self, machine_name: &str,) -> Option<NetrcMachine,> {
        info!("Removing machine entry: {}", machine_name);
        let result = self.machines.remove(machine_name,);
        if result.is_some() {
            debug!("Successfully removed machine entry: {}", machine_name);
        } else {
            warn!("No machine entry found to remove: {}", machine_name);
        }
        result
    }

    /// Updates a machine entry with the provided function.
    ///
    /// Applies the closure to the entry if found, returning `Ok(())` on success
    /// or `NetrcError::NotFound` if no entry exists.
    ///
    /// # Example
    ///
    /// ```
    /// use netrc_rs::{Netrc, NetrcError, NetrcMachine};
    ///
    /// let mut netrc = Netrc::default();
    /// netrc.insert_machine(NetrcMachine {
    ///     machine: "example.com".to_string(),
    ///     login: "user".to_string(),
    ///     password: "pass".to_string(),
    ///     account: None,
    ///     macdef: None,
    /// },);
    /// netrc.update_machine("example.com", |m| m.login = "new_user".to_string(),)?;
    /// assert_eq!(netrc.get("example.com").unwrap().login, "new_user");
    /// # Ok::<(), NetrcError>(())
    /// ```
    pub fn update_machine<F,>(
        &mut self,
        machine_name: &str,
        update_fn: F,
    ) -> Result<(), NetrcError,>
    where
        F: FnOnce(&mut NetrcMachine,),
    {
        info!("Updating machine entry: {}", machine_name);
        if let Some(machine,) = self.machines.get_mut(machine_name,) {
            update_fn(machine,);
            debug!("Successfully updated machine entry: {}", machine_name);
            Ok((),)
        } else {
            error!("Failed to update machine entry: {} not found", machine_name);
            Err(NetrcError::NotFound(machine_name.to_string(),),)
        }
    }

    /// Serializes the `Netrc` struct to `.netrc` format.
    ///
    /// Returns a string in the standard `.netrc` file format.
    pub fn to_netrc_string(&self,) -> String {
        info!("Serializing .netrc to string format");
        let mut output = String::new();
        for machine in self.machines.values() {
            debug!("Serializing machine entry: {}", machine.machine);
            if machine.machine == "default" {
                output.push_str("default\n",);
            } else {
                output.push_str(&format!("machine {}\n", machine.machine),);
            }
            output.push_str(&format!("  login {}\n", machine.login),);
            output.push_str(&format!("  password {}\n", machine.password),);
            if let Some(account,) = &machine.account {
                output.push_str(&format!("  account {}\n", account),);
            }
            if let Some(macdef,) = &machine.macdef {
                output.push_str(&format!("  macdef init\n{}\n\n", macdef),);
            }
        }
        debug!("Completed serialization to .netrc string");
        output
    }

    /// Saves the `.netrc` content to the specified path.
    ///
    /// Writes the serialized `.netrc` content to the given file path, returning
    /// `Ok(())` on success or a `NetrcError` for I/O errors.
    pub fn save_to_path<P: AsRef<Path,>,>(&self, path: P,) -> Result<(), NetrcError,> {
        let path = path.as_ref();
        info!("Saving .netrc to path: {:?}", path);
        let netrc_string = self.to_netrc_string();
        match fs::write(path, &netrc_string,) {
            Ok((),) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(path, fs::Permissions::from_mode(0o600,),).map_err(
                        |e| {
                            error!("Failed to set permissions for {:?}: {}", path, e);
                            NetrcError::Io(e,)
                        },
                    )?;
                }
                debug!("Successfully saved .netrc to {:?}", path);
                Ok((),)
            },
            Err(e,) => {
                error!("Failed to save .netrc to {:?}: {}", path, e);
                Err(NetrcError::Io(e,),)
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use log::Level;
    use std::cell::RefCell;

    thread_local! {
        static LOG_MESSAGES: RefCell<Vec<(Level, String)>> = const { RefCell::new(Vec::new()) };
    }

    // Custom log handler for capturing log messages in tests
    struct TestLogger;

    impl log::Log for TestLogger {
        fn enabled(&self, metadata: &log::Metadata,) -> bool {
            metadata.level() <= Level::Debug
        }

        fn log(&self, record: &log::Record,) {
            if self.enabled(record.metadata(),) {
                eprintln!("Log: {} - {}", record.level(), record.args());
                LOG_MESSAGES.with(|messages| {
                    messages.borrow_mut().push((record.level(), format!("{}", record.args()),),);
                },);
            }
        }

        fn flush(&self,) {
        }
    }

    fn init_logger() {
        eprintln!("Initializing logger with RUST_LOG={:?}", std::env::var("RUST_LOG"));
        let _ =
            log::set_logger(&TestLogger,).map(|()| log::set_max_level(log::LevelFilter::Debug,),);
        LOG_MESSAGES.with(|messages| messages.borrow_mut().clear(),);
    }

    // Helper to safely get log messages
    fn get_log_messages() -> Vec<(Level, String,),> {
        LOG_MESSAGES.with(|messages| messages.borrow().clone(),)
    }

    // Tests parsing a basic .netrc entry
    #[test]
    fn parse_basic_entry() {
        init_logger();
        let input = "machine example.com login user password pass";
        let netrc = Netrc::parse_from_str(input,).unwrap();
        let creds = netrc.get("example.com",).unwrap();

        assert_eq!(creds.login, "user");
        assert_eq!(creds.password, "pass");
        assert!(creds.account.is_none());

        let messages = get_log_messages();
        assert!(messages.iter().any(|(level, msg,)| {
            *level == Level::Info && msg.contains("Parsing .netrc string",)
        }));
        assert!(messages.iter().any(|(level, msg,)| {
            *level == Level::Debug && msg.contains("Parsed machine name: example.com",)
        }));
    }

    // Tests parsing an entry with an account field
    #[test]
    fn parse_with_account() {
        init_logger();
        let input = "machine api.com login alice password secret account dev";
        let netrc = Netrc::parse_from_str(input,).unwrap();
        let creds = netrc.get("api.com",).unwrap();

        assert_eq!(creds.account.as_deref(), Some("dev"));

        let messages = get_log_messages();
        assert!(
            messages
                .iter()
                .any(|(level, msg,)| *level == Level::Debug && msg.contains("Parsed account: dev"))
        );
    }

    // Tests parsing a default entry
    #[test]
    fn parse_default_entry() {
        init_logger();
        let input = "default login guest password guess123";
        let netrc = Netrc::parse_from_str(input,).unwrap();
        let creds = netrc.get("default",).unwrap();

        assert_eq!(creds.login, "guest");
        assert_eq!(creds.password, "guess123");

        let messages = get_log_messages();
        assert!(
            messages
                .iter()
                .any(|(level, msg,)| *level == Level::Debug && msg.contains("Parsed key: default"))
        );
    }

    // Tests parsing an entry with macdef and account
    #[test]
    fn parse_macdef_and_account() {
        init_logger();
        let input = r#"
        machine internal login root password rootpass account admin
        macdef init
        echo Initializing connection...

        "#;

        let netrc = Netrc::parse_from_str(input,).unwrap();
        let creds = netrc.get("internal",).unwrap();

        assert_eq!(creds.account.as_deref(), Some("admin"));
        assert!(creds.macdef.is_some());
        assert!(
            creds
                .macdef
                .as_ref()
                .map(|m| m.contains("echo Initializing connection"))
                .unwrap_or(false)
        );

        let messages = get_log_messages();
        assert!(messages.iter().any(|(level, msg,)| {
            *level == Level::Debug && msg.contains("Parsing macdef: init",)
        }));
    }

    // Tests parsing an empty input
    #[test]
    fn empty_input_returns_empty_netrc() {
        init_logger();
        let netrc = Netrc::parse_from_str("",).unwrap();
        assert!(netrc.machines.is_empty());

        let messages = get_log_messages();
        assert!(messages.iter().any(|(level, msg,)| {
            *level == Level::Info && msg.contains("Successfully parsed .netrc with 0 machines",)
        }));
    }

    // Tests parsing an entry with missing login and password
    #[test]
    fn missing_login_password_fields() {
        init_logger();
        let input = "machine foo.com";
        let netrc = Netrc::parse_from_str(input,).unwrap();
        let creds = netrc.get("foo.com",).unwrap();
        assert_eq!(creds.login, "");
        assert_eq!(creds.password, "");

        let messages = get_log_messages();
        assert!(messages.iter().any(|(level, msg,)| {
            *level == Level::Warn && msg.contains("No login provided for machine: foo.com",)
        }));
        assert!(messages.iter().any(|(level, msg,)| {
            *level == Level::Warn && msg.contains("No password provided for machine: foo.com",)
        }));
    }

    #[test]
    fn parse_duplicate_machine_fails() {
        init_logger();
        let input = "machine example.com login user1 password pass1\nmachine example.com login user2 password pass2";
        let result = Netrc::parse_from_str(input,);
        assert!(matches!(result, Err(NetrcError::DuplicateEntry(_))));
    }

    #[test]
    fn parse_invalid_token_after_login() {
        init_logger();
        let input = "machine example.com login ";
        let result = Netrc::parse_from_str(input,);
        assert!(matches!(result, Err(NetrcError::Parse { message: _, input: _ })));
    }

    #[test]
    fn parse_multiple_machines() {
        init_logger();
        let input = "machine example.com login user1 password pass1\nmachine api.com login user2 password pass2";
        let netrc = Netrc::parse_from_str(input,).unwrap();
        assert_eq!(netrc.machines.len(), 2);
        assert!(netrc.get("example.com").is_some());
        assert!(netrc.get("api.com").is_some());
    }

    #[test]
    fn parse_whitespace_heavy_input() {
        init_logger();
        let input = "\t\n  machine   example.com  \n\t  login  \t user  \n  password  pass  \n";
        let netrc = Netrc::parse_from_str(input,).unwrap();
        let creds = netrc.get("example.com",).unwrap();
        assert_eq!(creds.login, "user");
        assert_eq!(creds.password, "pass");

        let messages = get_log_messages();
        assert!(
            messages
                .iter()
                .any(|(level, msg,)| *level == Level::Debug && msg.contains("Parsed login: user"))
        );
    }

    #[test]
    fn parse_empty_macdef() {
        init_logger();
        let input = "machine example.com login user password pass macdef init\n\n";
        let netrc = Netrc::parse_from_str(input,).unwrap();
        let creds = netrc.get("example.com",).unwrap();
        assert_eq!(creds.macdef, Some("".to_string()));
    }

    #[test]
    fn insert_and_update_machine() {
        init_logger();
        let mut netrc = Netrc::default();
        let machine = NetrcMachine {
            machine: "example.com".to_string(),
            login: "user".to_string(),
            password: "pass".to_string(),
            account: None,
            macdef: None,
        };
        netrc.insert_machine(machine.clone(),);
        assert_eq!(netrc.get("example.com").unwrap().login, "user");

        netrc.update_machine("example.com", |m| m.login = "new_user".to_string(),).unwrap();
        assert_eq!(netrc.get("example.com").unwrap().login, "new_user");

        let result = netrc.update_machine("nonexistent.com", |_| {},);
        assert!(matches!(result, Err(NetrcError::NotFound(_))));

        let messages = get_log_messages();
        assert!(messages.iter().any(|(level, msg,)| {
            *level == Level::Info
                && msg.contains("Inserting or replacing machine entry: example.com",)
        }));
        assert!(messages.iter().any(|(level, msg,)| {
            *level == Level::Info && msg.contains("Updating machine entry: example.com",)
        }));
        assert!(messages.iter().any(|(level, msg,)| {
            *level == Level::Error
                && msg.contains("Failed to update machine entry: nonexistent.com",)
        }));
    }

    #[test]
    fn remove_machine() {
        init_logger();
        let mut netrc = Netrc::default();
        let machine = NetrcMachine {
            machine: "example.com".to_string(),
            login: "user".to_string(),
            password: "pass".to_string(),
            account: None,
            macdef: None,
        };
        netrc.insert_machine(machine.clone(),);
        let removed = netrc.remove_machine("example.com",).unwrap();
        assert_eq!(removed, machine);
        assert!(netrc.get("example.com").is_none());
        assert!(netrc.remove_machine("example.com").is_none());

        let messages = get_log_messages();
        assert!(messages.iter().any(|(level, msg,)| {
            *level == Level::Info && msg.contains("Removing machine entry: example.com",)
        }));
        assert!(messages.iter().any(|(level, msg,)| {
            *level == Level::Debug
                && msg.contains("Successfully removed machine entry: example.com",)
        }));
        assert!(messages.iter().any(|(level, msg,)| {
            *level == Level::Warn && msg.contains("No machine entry found to remove: example.com",)
        }));
    }

    #[test]
    fn serialize_to_json_and_toml() {
        init_logger();
        let mut netrc = Netrc::default();
        let machine = NetrcMachine {
            machine: "example.com".to_string(),
            login: "user".to_string(),
            password: "pass".to_string(),
            account: Some("dev".to_string(),),
            macdef: None,
        };
        netrc.insert_machine(machine,);

        let json = netrc.to_json().unwrap();
        assert!(json.contains(r#""machine": "example.com""#));
        assert!(json.contains(r#""login": "user""#));

        let toml = netrc.to_toml().unwrap();
        assert!(toml.contains("machine = \"example.com\""));
        assert!(toml.contains("login = \"user\""));

        let messages = get_log_messages();
        assert!(messages.iter().any(|(level, msg,)| {
            *level == Level::Info && msg.contains("Serializing .netrc to JSON",)
        }));
        assert!(messages.iter().any(|(level, msg,)| {
            *level == Level::Info && msg.contains("Serializing .netrc to TOML",)
        }));
    }

    #[test]
    fn round_trip_serialization() {
        init_logger();
        let mut netrc = Netrc::default();
        let machine = NetrcMachine {
            machine: "example.com".to_string(),
            login: "user".to_string(),
            password: "pass".to_string(),
            account: Some("dev".to_string(),),
            macdef: Some("echo test".to_string(),),
        };
        netrc.insert_machine(machine.clone(),);

        let netrc_string = netrc.to_netrc_string();
        let parsed_netrc = Netrc::parse_from_str(&netrc_string,).unwrap();
        assert_eq!(parsed_netrc.get("example.com").unwrap(), &machine);

        let messages = get_log_messages();
        assert!(messages.iter().any(|(level, msg,)| {
            *level == Level::Info && msg.contains("Serializing .netrc to string format",)
        }));
        assert!(messages.iter().any(|(level, msg,)| {
            *level == Level::Info && msg.contains("Parsing .netrc string",)
        }));
    }

    #[test]
    fn file_io_round_trip() {
        init_logger();
        let temp_file = std::env::temp_dir().join("test_netrc",);
        let mut netrc = Netrc::default();
        let machine = NetrcMachine {
            machine: "example.com".to_string(),
            login: "user".to_string(),
            password: "pass".to_string(),
            account: None,
            macdef: None,
        };
        netrc.insert_machine(machine.clone(),);

        netrc.save_to_path(&temp_file,).unwrap();
        let loaded_netrc = Netrc::parse_from_path(&temp_file,).unwrap();
        assert_eq!(loaded_netrc.get("example.com").unwrap(), &machine);

        std::fs::remove_file(&temp_file,).unwrap();

        let messages = get_log_messages();
        assert!(messages.iter().any(|(level, msg,)| {
            *level == Level::Info && msg.contains("Saving .netrc to path",)
        }));
        assert!(messages.iter().any(|(level, msg,)| {
            *level == Level::Info && msg.contains("Reading and parsing .netrc file",)
        }));
    }

    #[test]
    fn parse_invalid_file_path() {
        init_logger();
        let result = Netrc::parse_from_path("/nonexistent/path/netrc",);
        assert!(matches!(result, Err(NetrcError::FileNotFound(_))));
        let messages = get_log_messages();
        assert!(messages.iter().any(|(level, msg,)| {
            *level == Level::Error && msg.contains("Failed to read metadata for",)
        }));
    }

    #[test]
    fn parse_complex_macdef() {
        init_logger();
        let input = r#"
    machine example.com login user password pass
    macdef init
    echo Starting...
    sleep 1
    echo Done

    "#;
        let netrc = Netrc::parse_from_str(input,).unwrap();
        let creds = netrc.get("example.com",).unwrap();
        assert!(creds.macdef.is_some());
        let macdef = creds.macdef.as_ref().unwrap();
        assert!(macdef.contains("echo Starting..."));
        assert!(macdef.contains("sleep 1"));
        assert!(macdef.contains("echo Done"));

        let messages = get_log_messages();
        assert!(messages.iter().any(|(level, msg,)| {
            *level == Level::Debug && msg.contains("Parsed macdef content",)
        }));
    }

    #[test]
    fn parse_empty_machine_name() {
        init_logger();
        let input = "machine  login user password pass";
        let result = Netrc::parse_from_str(input,);
        assert!(matches!(result, Err(NetrcError::Parse { message: _, input: _ })));
    }

    #[test]
    fn test_logging() {
        init_logger();
        let input = "machine example.com login user password pass";
        let netrc = Netrc::parse_from_str(input,).unwrap();
        netrc.to_json().unwrap();
        netrc.to_toml().unwrap();
        netrc.to_netrc_string();
        netrc.get("example.com",).unwrap();
        netrc.get("nonexistent.com",);

        let temp_file = std::env::temp_dir().join("test_netrc_log",);
        netrc.save_to_path(&temp_file,).unwrap();
        let _ = Netrc::parse_from_path(&temp_file,);
        std::fs::remove_file(&temp_file,).unwrap();

        let mut netrc = Netrc::default();
        let machine = NetrcMachine {
            machine: "test.com".to_string(),
            login: "test".to_string(),
            password: "test".to_string(),
            account: None,
            macdef: None,
        };
        netrc.insert_machine(machine.clone(),);
        netrc.update_machine("test.com", |m| m.login = "updated".to_string(),).unwrap();
        netrc.remove_machine("test.com",);

        let messages = get_log_messages();
        assert!(messages.iter().any(|(level, msg,)| {
            *level == Level::Info && msg.contains("Parsing .netrc string",)
        }));
        assert!(messages.iter().any(|(level, msg,)| {
            *level == Level::Info && msg.contains("Serializing .netrc to JSON",)
        }));
        assert!(messages.iter().any(|(level, msg,)| {
            *level == Level::Info && msg.contains("Serializing .netrc to TOML",)
        }));
        assert!(messages.iter().any(|(level, msg,)| {
            *level == Level::Info && msg.contains("Serializing .netrc to string format",)
        }));
        assert!(messages.iter().any(|(level, msg,)| {
            *level == Level::Debug && msg.contains("Retrieving machine entry for: example.com",)
        }));
        assert!(messages.iter().any(|(level, msg,)| {
            *level == Level::Warn && msg.contains("No machine entry found for: nonexistent.com",)
        }));
        assert!(messages.iter().any(|(level, msg,)| {
            *level == Level::Info && msg.contains("Saving .netrc to path",)
        }));
        assert!(messages.iter().any(|(level, msg,)| {
            *level == Level::Info && msg.contains("Reading and parsing .netrc file",)
        }));
        assert!(messages.iter().any(|(level, msg,)| {
            *level == Level::Info && msg.contains("Inserting or replacing machine entry: test.com",)
        }));
        assert!(messages.iter().any(|(level, msg,)| {
            *level == Level::Info && msg.contains("Updating machine entry: test.com",)
        }));
        assert!(messages.iter().any(|(level, msg,)| {
            *level == Level::Info && msg.contains("Removing machine entry: test.com",)
        }));
    }

    #[test]
    fn parse_macdef_with_trailing_whitespace() {
        init_logger();
        let input = "machine example.com login user password pass macdef init\n  \n";
        let netrc = Netrc::parse_from_str(input,).unwrap();
        let creds = netrc.get("example.com",).unwrap();
        assert_eq!(creds.macdef, Some("".to_string()));
    }

    #[test]
    fn parse_macdef_with_multiple_empty_lines() {
        init_logger();
        let input = "machine example.com login user password pass macdef init\n\n\n";
        let netrc = Netrc::parse_from_str(input,).unwrap();
        let creds = netrc.get("example.com",).unwrap();
        assert_eq!(creds.macdef, Some("".to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn parse_file_with_insecure_permissions() {
        init_logger();
        let temp_file = std::env::temp_dir().join("test_netrc_perm",);
        fs::write(&temp_file, "machine example.com login user password pass",).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temp_file, fs::Permissions::from_mode(0o666,),).unwrap();
        let result = Netrc::parse_from_path(&temp_file,);
        assert!(matches!(result, Err(NetrcError::InsecurePermissions)));
        let messages = get_log_messages();
        assert!(messages.iter().any(|(level, msg,)| {
            *level == Level::Error && msg.contains("File permissions for",)
        }));
        std::fs::remove_file(&temp_file,).unwrap();
    }
}
