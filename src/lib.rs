#![feature(closure_lifetime_binder)]

//! A modern and idiomatic .netrc parser in Rust
//!
//! This library provides a robust parser for `.netrc` files, supporting machine entries,
//! login credentials, accounts, and macro definitions (`macdef`). It includes serialization
//! to JSON and TOML, file I/O, and comprehensive error handling.
//!
//! ## Logging
//!
//! The library uses the `log` crate for logging. To enable logging, configure a logging backend
//! (e.g., `env_logger`) in your application. Set the `RUST_LOG` environment variable to control
//! log levels (e.g., `RUST_LOG=netrc_rs=debug`). Example:
//!
//! ```rust
//! use env_logger;
//! env_logger::init();
//! ```
//!
//! Log messages are emitted at the following levels:
//! - `info`: High-level operations (e.g., parsing a file, saving to a path).
//! - `debug`: Detailed parsing steps (e.g., parsing a machine entry).
//! - `warn`: Non-critical issues (e.g., missing optional fields).
//! - `error`: Failures (e.g., parsing errors, file I/O errors).

mod error;
pub use error::NetrcError;
use log::{debug, warn};
use proptest::prelude::*;

use nom::{
    IResult, Parser,
    branch::alt,
    bytes::complete::{tag, take_while1},
    character::complete::{line_ending, multispace0, multispace1, not_line_ending},
    combinator::{eof, opt},
    multi::{many_till, many0},
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, path::Path};

/// Represents a single machine entry in a .netrc file
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct NetrcMachine {
    pub machine: String,
    pub login: String,
    pub password: String,
    pub account: Option<String>,
    pub macdef: Option<String>,
}

/// Represents a complete .netrc file with multiple machine entries
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct Netrc {
    pub machines: HashMap<String, NetrcMachine>,
}

/// Checks if a character is valid for a token (non-whitespace)
fn is_token_char(c: char) -> bool {
    !c.is_whitespace()
}

/// Parses a single token from input
fn parse_token(input: &str) -> IResult<&str, &str> {
    take_while1(is_token_char)(input)
}

/// Parses a machine entry from the input string
fn parse_machine(input: &str) -> IResult<&str, NetrcMachine> {
    debug!("Parsing a machine entry from input: {:?}", input);
    let (input, _) = multispace0(input)?;
    let (input, key): (&str, &str) = alt((tag("machine"), tag("default"))).parse(input)?;
    debug!("Parsed key: {}", key);
    let (input, _) = multispace1(input)?;
    let (input, machine_name) = if key == "default" {
        (input, "default")
    } else {
        let (input, name) = parse_token(input).map_err(|_| {
            debug!("Failed to parse machine name");
            nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify))
        })?;
        if name.is_empty() {
            debug!("Machine name is empty");
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Verify,
            )));
        }
        (input, name)
    };
    debug!("Parsed machine name: {}", machine_name);

    let mut login = String::new();
    let mut password = String::new();
    let mut account = None;
    let mut macdef = None;
    let mut rest = input;

    // Loop to parse all fields for the machine
    loop {
        let (next_input, _) = multispace0(rest)?;
        if let Ok((next_input, _)) = eof::<_, nom::error::Error<_>>(next_input) {
            debug!("Reached end of input for machine: {}", machine_name);
            rest = next_input;
            break;
        }

        let (next_input, token): (&str, Option<&str>) = opt(parse_token).parse(next_input)?;
        match token {
            Some("machine") | Some("default") => {
                debug!(
                    "Encountered new machine or default, stopping parsing for: {}",
                    machine_name
                );
                break;
            }
            Some("login") => {
                let (next_input, _) = multispace1(next_input)?;
                let (next_input, val) = parse_token(next_input).map_err(|_| {
                    debug!("Failed to parse login token for machine: {}", machine_name);
                    nom::Err::Error(nom::error::Error::new(
                        next_input,
                        nom::error::ErrorKind::Verify,
                    ))
                })?;
                login = val.to_string();
                debug!("Parsed login: {} for machine: {}", login, machine_name);
                rest = next_input;
            }
            Some("password") => {
                let (next_input, _) = multispace1(next_input)?;
                let (next_input, val) = parse_token(next_input).map_err(|_| {
                    debug!(
                        "Failed to parse password token for machine: {}",
                        machine_name
                    );
                    nom::Err::Error(nom::error::Error::new(
                        next_input,
                        nom::error::ErrorKind::Verify,
                    ))
                })?;
                password = val.to_string();
                debug!("Parsed password for machine: {}", machine_name);
                rest = next_input;
            }
            Some("account") => {
                let (next_input, _) = multispace1(next_input)?;
                let (next_input, val) = parse_token(next_input)?;
                account = Some(val.to_string());
                debug!("Parsed account: {} for machine: {}", val, machine_name);
                rest = next_input;
            }
            Some("macdef") => {
                let (next_input, _) = multispace1(next_input)?;
                let (next_input, macdef_name) = parse_token(next_input)?; // skip macdef name
                debug!(
                    "Parsing macdef: {} for machine: {}",
                    macdef_name, machine_name
                );
                let (next_input, _) = line_ending(next_input)?;

                let mut parser = many_till(
                    not_line_ending.map(|l: &str| l.to_string()),
                    for<'a> |i: &'a str| -> IResult<&'a str, ()> {
                        let (i, _) = multispace0(i)?;
                        if i.is_empty() {
                            debug!("Reached end of macdef for machine: {}", machine_name);
                            Ok((i, ()))
                        } else if i.trim().is_empty() {
                            let (i, _) = line_ending(i)?;
                            debug!(
                                "Reached empty line, ending macdef for machine: {}",
                                machine_name
                            );
                            Ok((i, ()))
                        } else {
                            let (i, _) = line_ending(i)?;
                            Err(nom::Err::Error(nom::error::Error::new(
                                i,
                                nom::error::ErrorKind::Tag,
                            )))
                        }
                    },
                );

                let (next_input, (lines, _)) = parser.parse(next_input)?;
                let macdef_content = lines.join("\n").trim_end().to_string();
                macdef = if macdef_content.is_empty() {
                    Some("".to_string())
                } else {
                    Some(macdef_content)
                };
                debug!(
                    "Parsed macdef content: {:?} for machine: {}",
                    macdef, machine_name
                );
                rest = next_input;
            }
            Some(token) => {
                warn!(
                    "Unexpected token: {} for machine: {}, skipping",
                    token, machine_name
                );
                let (next_input, _) = multispace1(next_input)?;
                let (next_input, _) = opt(parse_token).parse(next_input)?;
                rest = next_input;
            }
            None => {
                debug!(
                    "No more tokens for machine: {}, stopping parsing",
                    machine_name
                );
                break;
            }
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
        NetrcMachine {
            machine: machine_name.to_string(),
            login,
            password,
            account,
            macdef,
        },
    ))
}

/// Parses the entire .netrc content into a Netrc struct
fn parse_netrc(input: &str) -> IResult<&str, Netrc> {
    let (input, machine_list) = many0(parse_machine).parse(input)?;
    let mut machines = HashMap::new();
    for machine in machine_list {
        if machines.contains_key(&machine.machine) {
            return Err(nom::Err::Failure(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Many1, // Use a distinct error kind
            )));
        }
        machines.insert(machine.machine.clone(), machine);
    }
    Ok((input, Netrc { machines }))
}

impl Netrc {
    /// Parses a .netrc string into a Netrc struct
    pub fn parse_from_str(input: &str) -> Result<Self, NetrcError> {
        let (_, parsed) = parse_netrc(input).map_err(|e| match e {
            nom::Err::Failure(e) if e.code == nom::error::ErrorKind::Many1 => {
                NetrcError::DuplicateEntry("duplicate machine entry".to_string())
            }
            nom::Err::Error(e) if e.code == nom::error::ErrorKind::Verify => {
                NetrcError::Parse("invalid or missing token".to_string())
            }
            _ => NetrcError::Parse(e.to_string()),
        })?;
        Ok(parsed)
    }

    /// Reads and parses a .netrc file from the given path
    pub fn parse_from_path<P: AsRef<Path>>(path: P) -> Result<Self, NetrcError> {
        let content = fs::read_to_string(path)?;
        Self::parse_from_str(&content)
    }

    /// Retrieves a machine entry by its name
    pub fn get(&self, machine: &str) -> Option<&NetrcMachine> {
        self.machines.get(machine)
    }

    /// Serializes the Netrc struct to JSON
    pub fn to_json(&self) -> Result<String, NetrcError> {
        serde_json::to_string_pretty(self).map_err(|e| NetrcError::Serialize(e.to_string()))
    }

    /// Serializes the Netrc struct to TOML
    pub fn to_toml(&self) -> Result<String, NetrcError> {
        toml::to_string_pretty(self).map_err(|e| NetrcError::Serialize(e.to_string()))
    }

    /// Inserts or replaces a machine entry
    pub fn insert_machine(&mut self, machine: NetrcMachine) {
        self.machines.insert(machine.machine.clone(), machine);
    }

    /// Removes a machine entry by name
    pub fn remove_machine(&mut self, machine_name: &str) -> Option<NetrcMachine> {
        self.machines.remove(machine_name)
    }

    /// Updates a machine entry with the provided function
    pub fn update_machine<F>(&mut self, machine_name: &str, update_fn: F) -> Result<(), NetrcError>
    where
        F: FnOnce(&mut NetrcMachine),
    {
        if let Some(machine) = self.machines.get_mut(machine_name) {
            update_fn(machine);
            Ok(())
        } else {
            Err(NetrcError::NotFound(machine_name.to_string()))
        }
    }

    /// Serializes the Netrc struct to .netrc format
    pub fn to_netrc_string(&self) -> String {
        let mut output = String::new();
        for machine in self.machines.values() {
            if machine.machine == "default" {
                output.push_str("default\n");
            } else {
                output.push_str(&format!("machine {}\n", machine.machine));
            }
            output.push_str(&format!("  login {}\n", machine.login));
            output.push_str(&format!("  password {}\n", machine.password));
            if let Some(account) = &machine.account {
                output.push_str(&format!("  account {}\n", account));
            }
            if let Some(macdef) = &machine.macdef {
                output.push_str(&format!("  macdef init\n{}\n\n", macdef));
            }
        }
        output
    }

    /// Saves the .netrc content to the specified path
    pub fn save_to_path<P: AsRef<Path>>(&self, path: P) -> Result<(), NetrcError> {
        let netrc_string = self.to_netrc_string();
        fs::write(path, netrc_string)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests parsing a basic .netrc entry
    #[test]
    fn parse_basic_entry() {
        let input = "machine example.com login user password pass";
        let netrc = Netrc::parse_from_str(input).unwrap();
        let creds = netrc.get("example.com").unwrap();

        assert_eq!(creds.login, "user");
        assert_eq!(creds.password, "pass");
        assert!(creds.account.is_none());
    }

    // Tests parsing an entry with an account field
    #[test]
    fn parse_with_account() {
        let input = "machine api.com login alice password secret account dev";
        let netrc = Netrc::parse_from_str(input).unwrap();
        let creds = netrc.get("api.com").unwrap();

        assert_eq!(creds.account.as_deref(), Some("dev"));
    }

    // Tests parsing a default entry
    #[test]
    fn parse_default_entry() {
        let input = "default login guest password guess123";
        let netrc = Netrc::parse_from_str(input).unwrap();
        let creds = netrc.get("default").unwrap();

        assert_eq!(creds.login, "guest");
        assert_eq!(creds.password, "guess123");
    }

    // Tests parsing an entry with macdef and account
    #[test]
    fn parse_macdef_and_account() {
        let input = r#"
        machine internal login root password rootpass account admin
        macdef init
        echo Initializing connection...

        "#;

        let netrc = Netrc::parse_from_str(input).unwrap();
        let creds = netrc.get("internal").unwrap();

        assert_eq!(creds.account.as_deref(), Some("admin"));
        assert!(creds.macdef.is_some());
        assert!(
            creds
                .macdef
                .as_ref()
                .unwrap()
                .contains("echo Initializing connection")
        );
    }

    // Tests parsing an empty input
    #[test]
    fn empty_input_returns_empty_netrc() {
        let netrc = Netrc::parse_from_str("").unwrap();
        assert!(netrc.machines.is_empty());
    }

    // Tests parsing an entry with missing login and password
    #[test]
    fn missing_login_password_fields() {
        let input = "machine foo.com";
        let netrc = Netrc::parse_from_str(input).unwrap();
        let creds = netrc.get("foo.com").unwrap();
        assert_eq!(creds.login, "");
        assert_eq!(creds.password, "");
    }

    #[test]
    fn parse_duplicate_machine_fails() {
        let input = "machine example.com login user1 password pass1\nmachine example.com login user2 password pass2";
        let result = Netrc::parse_from_str(input);
        assert!(matches!(result, Err(NetrcError::DuplicateEntry(_))));
    }

    #[test]
    fn parse_invalid_token_after_login() {
        let input = "machine example.com login ";
        let result = Netrc::parse_from_str(input);
        eprintln!("Result: {:?}", result); // Debug output
        assert!(matches!(result, Err(NetrcError::Parse(_))));
    }

    #[test]
    fn parse_multiple_machines() {
        let input = "machine example.com login user1 password pass1\nmachine api.com login user2 password pass2";
        let netrc = Netrc::parse_from_str(input).unwrap();
        assert_eq!(netrc.machines.len(), 2);
        assert!(netrc.get("example.com").is_some());
        assert!(netrc.get("api.com").is_some());
    }

    #[test]
    fn parse_whitespace_heavy_input() {
        let input = "\t\n  machine   example.com  \n\t  login  \t user  \n  password  pass  \n";
        let netrc = Netrc::parse_from_str(input).unwrap();
        let creds = netrc.get("example.com").unwrap();
        assert_eq!(creds.login, "user");
        assert_eq!(creds.password, "pass");
    }

    #[test]
    fn parse_empty_macdef() {
        let input = "machine example.com login user password pass macdef init\n\n";
        let netrc = Netrc::parse_from_str(input).unwrap();
        let creds = netrc.get("example.com").unwrap();
        assert_eq!(creds.macdef, Some("".to_string()));
    }

    #[test]
    fn insert_and_update_machine() {
        let mut netrc = Netrc::default();
        let machine = NetrcMachine {
            machine: "example.com".to_string(),
            login: "user".to_string(),
            password: "pass".to_string(),
            account: None,
            macdef: None,
        };
        netrc.insert_machine(machine.clone());
        assert_eq!(netrc.get("example.com").unwrap().login, "user");

        netrc
            .update_machine("example.com", |m| m.login = "new_user".to_string())
            .unwrap();
        assert_eq!(netrc.get("example.com").unwrap().login, "new_user");

        let result = netrc.update_machine("nonexistent.com", |_| {});
        assert!(matches!(result, Err(NetrcError::NotFound(_))));
    }

    #[test]
    fn remove_machine() {
        let mut netrc = Netrc::default();
        let machine = NetrcMachine {
            machine: "example.com".to_string(),
            login: "user".to_string(),
            password: "pass".to_string(),
            account: None,
            macdef: None,
        };
        netrc.insert_machine(machine.clone());
        let removed = netrc.remove_machine("example.com").unwrap();
        assert_eq!(removed, machine);
        assert!(netrc.get("example.com").is_none());
        assert!(netrc.remove_machine("example.com").is_none());
    }

    #[test]
    fn serialize_to_json_and_toml() {
        let mut netrc = Netrc::default();
        let machine = NetrcMachine {
            machine: "example.com".to_string(),
            login: "user".to_string(),
            password: "pass".to_string(),
            account: Some("dev".to_string()),
            macdef: None,
        };
        netrc.insert_machine(machine);

        let json = netrc.to_json().unwrap();
        assert!(json.contains(r#""machine": "example.com""#));
        assert!(json.contains(r#""login": "user""#));

        let toml = netrc.to_toml().unwrap();
        assert!(toml.contains("machine = \"example.com\""));
        assert!(toml.contains("login = \"user\""));
    }

    #[test]
    fn round_trip_serialization() {
        let mut netrc = Netrc::default();
        let machine = NetrcMachine {
            machine: "example.com".to_string(),
            login: "user".to_string(),
            password: "pass".to_string(),
            account: Some("dev".to_string()),
            macdef: Some("echo test".to_string()),
        };
        netrc.insert_machine(machine.clone());

        let netrc_string = netrc.to_netrc_string();
        let parsed_netrc = Netrc::parse_from_str(&netrc_string).unwrap();
        assert_eq!(parsed_netrc.get("example.com").unwrap(), &machine);
    }

    #[test]
    fn file_io_round_trip() {
        let temp_file = std::env::temp_dir().join("test_netrc");
        let mut netrc = Netrc::default();
        let machine = NetrcMachine {
            machine: "example.com".to_string(),
            login: "user".to_string(),
            password: "pass".to_string(),
            account: None,
            macdef: None,
        };
        netrc.insert_machine(machine.clone());

        netrc.save_to_path(&temp_file).unwrap();
        let loaded_netrc = Netrc::parse_from_path(&temp_file).unwrap();
        assert_eq!(loaded_netrc.get("example.com").unwrap(), &machine);

        std::fs::remove_file(temp_file).unwrap();
    }

    #[test]
    fn parse_invalid_file_path() {
        let result = Netrc::parse_from_path("/nonexistent/path/netrc");
        assert!(matches!(result, Err(NetrcError::Io(_))));
    }

    #[test]
    fn parse_complex_macdef() {
        let input = r#"
    machine example.com login user password pass
    macdef init
    echo Starting...
    sleep 1
    echo Done

    "#;
        let netrc = Netrc::parse_from_str(input).unwrap();
        let creds = netrc.get("example.com").unwrap();
        let macdef = creds.macdef.as_ref().unwrap();
        assert!(macdef.contains("echo Starting..."));
        assert!(macdef.contains("sleep 1"));
        assert!(macdef.contains("echo Done"));
    }

    #[test]
    fn parse_empty_machine_name() {
        let input = "machine  login user password pass";
        let result = Netrc::parse_from_str(input);
        eprintln!("Result: {:?}", result); // Debug output
        assert!(matches!(result, Err(NetrcError::Parse(_))));
    }
}

proptest! {
    // Tests that parsing random input doesn't crash
    #[test]
    fn doesnt_crash_on_random_input(s in ".*") {
        let _ = Netrc::parse_from_str(&s);
    }

    #[test]
    fn parse_valid_netrc_input(
        machine in "[a-zA-Z0-9.-]+",
        login in "[a-zA-Z0-9]+",
        password in "[a-zA-Z0-9]+",
        account in proptest::option::of("[a-zA-Z0-9]+")
    ) {
        let account_str = account.clone().map_or(String::new(), |a| format!(" account {}", a));
        let input = format!("machine {} login {} password {}{}", machine, login, password, account_str);
        let netrc = Netrc::parse_from_str(&input).unwrap();
        let creds = netrc.get(&machine).unwrap();
        assert_eq!(creds.machine, machine);
        assert_eq!(creds.login, login);
        assert_eq!(creds.password, password);
        assert_eq!(creds.account, account);
    }
}
