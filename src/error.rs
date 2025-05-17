use std::io;

/// Error types for the `netrc-rs` library.
///
/// Represents all possible errors that can occur when parsing, reading, or
/// manipulating `.netrc` files. Each variant provides specific details about
/// the failure, such as I/O issues, parsing errors, or invalid file
/// permissions. Use this enum to handle errors from methods like
/// [`crate::Netrc::parse_from_path`] or [`crate::Netrc::parse_from_str`].
///
/// # Examples
///
/// Handling a file not found error:
///
/// ```
/// use netrc_rs::{Netrc, NetrcError};
///
/// match Netrc::parse_from_path("/nonexistent/.netrc",) {
///     Ok(netrc,) => println!("Parsed netrc: {:?}", netrc),
///     Err(NetrcError::FileNotFound(path,),) => println!("File not found: {}", path),
///     Err(e,) => println!("Other error: {}", e),
/// }
/// ```
///
/// Handling a parse error:
///
/// ```
/// use netrc_rs::{Netrc, NetrcError};
///
/// match Netrc::parse_from_str("machine login user",) {
///     Ok(netrc,) => println!("Parsed netrc: {:?}", netrc),
///     Err(NetrcError::Parse { message, input, },) => {
///         println!("Parse error: {} in input: {}", message, input);
///     },
///     Err(e,) => println!("Other error: {}", e),
/// }
/// ```
#[derive(Debug, thiserror::Error,)]
pub enum NetrcError {
    /// An I/O error occurred while reading or writing a `.netrc` file.
    ///
    /// This variant wraps standard I/O errors, such as permission denied or
    /// disk full, but excludes file not found errors (see
    /// [`NetrcError::FileNotFound`]). It originates from operations like
    /// [`std::fs::metadata`] or [`std::fs::read_to_string`].
    ///
    /// # Fields
    ///
    /// * `0`: The underlying [`std::io::Error`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// use netrc_rs::{Netrc, NetrcError};
    ///
    /// if let Err(NetrcError::Io(e,),) = Netrc::parse_from_path("/protected/.netrc",) {
    ///     println!("I/O error: {}", e);
    /// }
    /// ```
    #[error("I/O error: {0}")]
    Io(#[from] io::Error,),

    /// The specified `.netrc` file was not found.
    ///
    /// This error occurs when the file path provided to
    /// [`crate::Netrc::parse_from_path`] does not exist. It is distinct
    /// from other I/O errors to allow specific handling of missing files.
    ///
    /// # Fields
    ///
    /// * `0`: The path to the non-existent file as a `String`.
    ///
    /// # Example
    ///
    /// ```
    /// use netrc_rs::{Netrc, NetrcError};
    ///
    /// match Netrc::parse_from_path("/nonexistent/.netrc",) {
    ///     Ok(_,) => println!("File parsed"),
    ///     Err(NetrcError::FileNotFound(path,),) => println!("File not found: {}", path),
    ///     Err(e,) => println!("Other error: {}", e),
    /// }
    /// ```
    #[error("File not found: {0}")]
    FileNotFound(String,),

    /// A parsing error occurred while processing `.netrc` content.
    ///
    /// This error is returned by [`crate::Netrc::parse_from_str`] or
    /// [`crate::Netrc::parse_from_path`] when the input cannot be parsed, such
    /// as invalid syntax or missing required fields (e.g., a `machine`
    /// keyword without a name).
    ///
    /// # Fields
    ///
    /// * `message`: A description of the parsing error.
    /// * `input`: The input string that caused the error.
    ///
    /// # Example
    ///
    /// ```
    /// use netrc_rs::{Netrc, NetrcError};
    ///
    /// if let Err(NetrcError::Parse { message, input, },) = Netrc::parse_from_str("machine ",) {
    ///     println!("Parse error: {} in input: {}", message, input);
    /// }
    /// ```
    #[error("Parse error: {message} at input: {input}")]
    Parse { message: String, input: String, },

    /// A duplicate machine entry was found in the `.netrc` content.
    ///
    /// This error occurs when the same machine name (or `default`) appears
    /// multiple times in the input, which is invalid for `.netrc` files.
    ///
    /// # Fields
    ///
    /// * `0`: The name of the duplicated machine.
    ///
    /// # Example
    ///
    /// ```
    /// use netrc_rs::{Netrc, NetrcError};
    ///
    /// let input = "machine example.com login user password pass\nmachine example.com login other password pass";
    /// if let Err(NetrcError::DuplicateEntry(name)) = Netrc::parse_from_str(input) {
    ///     println!("Duplicate machine: {}", name);
    /// }
    /// ```
    #[error("Duplicate entry: {0}")]
    DuplicateEntry(String,),

    /// The requested machine was not found in the `.netrc` data.
    ///
    /// This error is returned by [`crate::Netrc::get`] or
    /// [`crate::Netrc::update_machine`] when the specified machine name
    /// does not exist.
    ///
    /// # Fields
    ///
    /// * `0`: The name of the missing machine.
    ///
    /// # Example
    ///
    /// ```
    /// use netrc_rs::{Netrc, NetrcError};
    ///
    /// let mut netrc = Netrc::default();
    /// if let Err(NetrcError::NotFound(name,),) = netrc.update_machine("example.com", |m| {},) {
    ///     println!("Machine not found: {}", name);
    /// }
    /// ```
    #[error("Machine not found: {0}")]
    NotFound(String,),

    /// The `.netrc` file has insecure permissions.
    ///
    /// On Unix systems, `.netrc` files must have permissions set to `0600`
    /// (owner read/write only). This error is returned by
    /// [`crate::Netrc::parse_from_path`] if the file is readable or writable by
    /// group or others.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use netrc_rs::{Netrc, NetrcError};
    /// use std::fs;
    ///
    /// let path = "/tmp/test_netrc";
    /// fs::write(path, "machine example.com login user password pass",).unwrap();
    /// #[cfg(unix)]
    /// std::os::unix::fs::PermissionsExt::set_mode(
    ///     &mut fs::metadata(path,).unwrap().permissions(),
    ///     0o666,
    /// );
    /// if let Err(NetrcError::InsecurePermissions,) = Netrc::parse_from_path(path,) {
    ///     println!("Insecure permissions detected");
    /// }
    /// ```
    #[error("Insecure file permissions")]
    InsecurePermissions,

    /// A serialization error occurred while converting to JSON or TOML.
    ///
    /// This error is returned by [`crate::Netrc::to_json`] or
    /// [`crate::Netrc::to_toml`] if serialization fails, typically due to
    /// invalid data or internal serializer issues.
    ///
    /// # Fields
    ///
    /// * `0`: A description of the serialization error.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use netrc_rs::{Netrc, NetrcError};
    ///
    /// let netrc = Netrc::default();
    /// if let Err(NetrcError::Serialize(msg,),) = netrc.to_json() {
    ///     println!("Serialization error: {}", msg);
    /// }
    /// ```
    #[error("Serialization error: {0}")]
    Serialize(String,),
}
