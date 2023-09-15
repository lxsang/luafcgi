use mlua::{prelude::*, Variadic};
use nix;
use rand::Rng;
use std::collections::HashMap;
use std::ffi::CString;
use std::fmt::Arguments;
use std::io::{BufRead, BufReader, Cursor, Error, ErrorKind, Read, Write};
use std::os::fd::RawFd;
use std::os::unix::io::AsRawFd;
use std::time::SystemTime;
use twoway;

/// app author
pub const APP_AUTHOR: &str = "Dany LE <mrsang@iohub.dev>";

/// app version
pub const APP_VERSION: &str = "0.1.0";

/// Application name
pub const DAEMON_NAME: &str = "luad";
/// Magic number for lua slice structure
const LUA_SLICE_MAGIC: usize = 0x8AD73B9F;
/// FastCGI frame header len
const FCGI_HEADER_LEN: usize = 8;
/// FastCGI protocol version
const FCGI_VERSION: u8 = 1;
/// Temporal location for file upload
const TMP_DIR: &str = "/tmp";

/// LOG_MASK is used to create the priority mask in setlogmask
/// For a mask UPTO specified
/// used with [Priority]
///
/// # Examples
///
/// ```
///     LOG_UPTO!(Priority::LOG_ALERT)
/// ```
#[macro_export]
macro_rules! LOG_UPTO
{
    ($($arg:tt)*) => (
        ((1 << (($($arg)*) + 1)) - 1)
    )
}

/// Drop user privileges
///
/// This function drop the privileges of the current user
/// to another inferior privileges user.
/// e.g. drop from root->maint
///
/// # Arguments
///
/// * `user` - system user name
/// * `group` - system group name
///
/// # Errors
///
/// * `nix::Error` - The error from the nix package
pub fn privdrop(useropt: Option<&str>, groupopt: Option<&str>) -> Result<(), nix::Error> {
    match groupopt {
        Some(group) => {
            INFO!("Dropping current process group to {}", group);
            match nix::unistd::Group::from_name(group)? {
                Some(group) => nix::unistd::setgid(group.gid),
                None => Err(nix::Error::last()),
            }?;
        }
        None => {}
    }
    match useropt {
        Some(user) => {
            INFO!("Dropping current process user to {}", user);
            match nix::unistd::User::from_name(user)? {
                Some(user) => nix::unistd::setuid(user.uid),
                None => Err(nix::Error::last()),
            }?
        }
        None => {}
    }
    Ok(())
}

pub fn is_unix_socket(fd: libc::c_int) -> Result<bool, Error> {
    unsafe {
        let mut addr: libc::sockaddr_storage = std::mem::zeroed();
        let mut addr_len: libc::socklen_t =
            std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        let ret = libc::getsockname(fd, &mut addr as *mut _ as *mut _, &mut addr_len);
        if ret != 0 {
            return Err(ERR!(format!("Unable to check socket: {}", fd)));
        }
        Ok(i32::from(addr.ss_family) == libc::AF_UNIX)
    }
}

/// Utility function to catch common signal that
/// cause the program to exit
///
/// Signals catched: SIGABRT, SIGINT, SIGTERM, SIGQUIT
///
/// # Arguments
///
/// * `f` - callback function that will be called when a signal is trapped
pub fn on_exit(f: fn(n: i32) -> ()) {
    unsafe {
        let _ = libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        let _ = libc::signal(libc::SIGABRT, (f as *const std::ffi::c_void) as usize);
        let _ = libc::signal(libc::SIGINT, (f as *const std::ffi::c_void) as usize);
        let _ = libc::signal(libc::SIGTERM, (f as *const std::ffi::c_void) as usize);
        let _ = libc::signal(libc::SIGQUIT, (f as *const std::ffi::c_void) as usize);
    };
}

/// Return an Error Result object from error string
///
#[macro_export]
macro_rules! ERR {
    ($x:expr) => {
        Error::new(
            ErrorKind::Other,
            format!("({}:{}): {}", file!(), line!(), $x),
        )
    };
}

#[macro_export]
macro_rules! BITV {
    ($v:expr,$i:expr) => {
        ($v & (1 << $i)) >> $i
    };
}

/// Macro for error log helper
///
#[macro_export]
macro_rules! INFO {
    ($($args:tt)*) => ({
        let prefix = format!(":info@[{}:{}]: ",file!(), line!());
        let _ = LOG::log(&prefix[..], &LogLevel::INFO, format_args!($($args)*));
    })
}

/// Macro for warning log helper
///
#[macro_export]
macro_rules! WARN {
    ($($args:tt)*) => ({
        let prefix = format!(":warning@[{}:{}]: ",file!(), line!());
        let _ = LOG::log(&prefix[..], &LogLevel::WARN, format_args!($($args)*));
    })
}

/// Macro for info log helper
///
#[macro_export]
macro_rules! ERROR {
    ($($args:tt)*) => ({
        let prefix = format!(":error@[{}:{}]: ",file!(), line!());
        let _ = LOG::log(&prefix[..], &LogLevel::ERROR, format_args!($($args)*));
    })
}

/// Macro for info log debug
///
#[macro_export]
macro_rules! DEBUG {
    ($($args:tt)*) => ({
        let prefix = format!(":debug@[{}:{}]: ",file!(), line!());
        let _ = LOG::log(&prefix[..], &LogLevel::DEBUG, format_args!($($args)*));
    })
}

/// Different Logging levels for `LOG`
pub enum LogLevel {
    /// Error conditions
    ERROR,
    /// Normal, but significant, condition
    INFO,
    /// Warning conditions
    WARN,
    /// Debugs message
    DEBUG,
}

/// Log struct wrapper
///
pub struct LOG {}

impl LOG {
    /// Init the system log
    ///
    /// This should be called only once in the entire lifetime
    /// of the program, the returned LOG instance should
    /// be keep alive during the lifetime of the program (the main function).
    /// When it is dropped, the connection to the system log will be
    /// closed automatically
    #[must_use]
    pub fn init_log() -> Self {
        // connect to the system log
        unsafe {
            libc::openlog(
                std::ptr::null(),
                libc::LOG_CONS | libc::LOG_PID | libc::LOG_NDELAY,
                libc::LOG_DAEMON,
            );
            libc::setlogmask(LOG_UPTO!(libc::LOG_NOTICE));
        }
        Self {}
    }
    /// Enable the Log debug
    ///
    pub fn enable_debug() {
        unsafe {
            libc::setlogmask(LOG_UPTO!(libc::LOG_INFO));
        }
    }

    /// Wrapper function that log error or info message to the
    /// connected syslog server
    ///
    /// # Arguments
    ///
    /// * `prefix` - Prefix of the log message
    /// * `level` - Log level
    /// * `args` - Arguments object representing a format string and its arguments
    ///
    /// # Errors
    ///
    /// * `std error` - All errors related to formatted and C string manipulation
    pub fn log(prefix: &str, level: &LogLevel, args: Arguments<'_>) -> Result<(), Error> {
        use std::fmt::Write;
        let sysloglevel = match level {
            LogLevel::ERROR => libc::LOG_ERR,
            LogLevel::WARN => libc::LOG_WARNING,
            LogLevel::INFO => libc::LOG_NOTICE,
            _ => libc::LOG_INFO,
        };
        let mut output = String::new();
        if output.write_fmt(args).is_err() {
            return Err(ERR!("Unable to create format string from arguments"));
        }
        let log_fmt = format!("{}(v{}){}%s\n", DAEMON_NAME, APP_VERSION, prefix);
        let fmt = CString::new(log_fmt.as_bytes())?;
        let c_msg = CString::new(output.as_bytes())?;
        unsafe {
            libc::syslog(sysloglevel, fmt.as_ptr(), c_msg.as_ptr());
        }
        Ok(())
    }
}

impl Drop for LOG {
    /// The connection to the syslog will be closed
    /// automatically when the log object is drop
    fn drop(&mut self) {
        // Close the current connection to the system logger
        unsafe {
            libc::closelog();
        }
    }
}

/// Protocol goes here
#[derive(Debug)]
enum FCGIHeaderType {
    BeginRequest,
    AbortRequest,
    EndRequest,
    Params,
    Stdin,
    Stdout,
    Stderr,
    Data,
    GetValues,
    GetValuesResult,
    Unknown,
}

impl FCGIHeaderType {
    /// convert a u8 value to `FCGIHeaderType` value
    ///
    /// # Arguments
    ///
    /// * `value` - u8 header value
    fn from_u8(value: u8) -> Self {
        match value {
            1 => FCGIHeaderType::BeginRequest,
            2 => FCGIHeaderType::AbortRequest,
            3 => FCGIHeaderType::EndRequest,
            4 => FCGIHeaderType::Params,
            5 => FCGIHeaderType::Stdin,
            6 => FCGIHeaderType::Stdout,
            7 => FCGIHeaderType::Stderr,
            8 => FCGIHeaderType::Data,
            9 => FCGIHeaderType::GetValues,
            10 => FCGIHeaderType::GetValuesResult,
            _ => FCGIHeaderType::Unknown,
        }
    }
    /// convert an `FCGIHeaderType` value to u8
    ///
    /// # Arguments
    ///
    /// * `value` - `FCGIHeaderType` header value
    fn as_u8(&self) -> u8 {
        match self {
            FCGIHeaderType::BeginRequest => 1,
            FCGIHeaderType::AbortRequest => 2,
            FCGIHeaderType::EndRequest => 3,
            FCGIHeaderType::Params => 4,
            FCGIHeaderType::Stdin => 5,
            FCGIHeaderType::Stdout => 6,
            FCGIHeaderType::Stderr => 7,
            FCGIHeaderType::Data => 8,
            FCGIHeaderType::GetValues => 9,
            FCGIHeaderType::GetValuesResult => 10,
            FCGIHeaderType::Unknown => 11,
        }
    }
}

impl std::fmt::Display for FCGIHeaderType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let s = match self {
            FCGIHeaderType::BeginRequest => "FCGI_BEGIN_REQUEST",
            FCGIHeaderType::AbortRequest => "FCGI_ABORT_REQUEST",
            FCGIHeaderType::EndRequest => "FCGI_END_REQUEST",
            FCGIHeaderType::Params => "FCGI_PARAMS",
            FCGIHeaderType::Stdin => "FCGI_STDIN",
            FCGIHeaderType::Stdout => "FCGI_STDOUT",
            FCGIHeaderType::Stderr => "FCGI_STDERR",
            FCGIHeaderType::Data => "FCGI_DATA",
            FCGIHeaderType::GetValues => "FCGI_GET_VALUES",
            FCGIHeaderType::GetValuesResult => "FCGI_GET_VALUES_RESULT",
            FCGIHeaderType::Unknown => "FCGI_UNKNOWN_TYPE",
        };
        write!(f, "{}", s)
    }
}

enum EndRequestStatus {
    Complete,
    // CantMaxMPXConn,
    // Overloaded,
    UnknownRole,
}

impl EndRequestStatus {
    /// convert an `EndRequestStatus` value to u8
    ///
    /// # Arguments
    ///
    /// * `value` - `EndRequestStatus` header value
    fn as_u8(&self) -> u8 {
        match self {
            EndRequestStatus::Complete => 0,
            //EndRequestStatus::CantMaxMPXConn => 1,
            //EndRequestStatus::Overloaded => 2,
            EndRequestStatus::UnknownRole => 3,
        }
    }
}

#[derive(Debug, PartialEq)]
enum FCGIRole {
    Responder,
    Authorizer,
    Filter,
    Unknown,
}

impl FCGIRole {
    /// convert a u8 value to `FCGIRole` value
    ///
    /// # Arguments
    ///
    /// * `value` - u16 header value
    fn from_u16(value: u16) -> Self {
        match value {
            1 => FCGIRole::Responder,
            2 => FCGIRole::Authorizer,
            3 => FCGIRole::Filter,
            _ => FCGIRole::Unknown,
        }
    }
}

impl std::fmt::Display for FCGIRole {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let s = match self {
            FCGIRole::Responder => "FCGI_RESPONDER",
            FCGIRole::Authorizer => "FCGI_AUTHORIZER",
            FCGIRole::Filter => "FCGI_FILTER",
            FCGIRole::Unknown => "FCGI_UNKNOWN_ROLE",
        };
        write!(f, "{}", s)
    }
}
#[derive(Debug)]
struct FCGIBeginRequestBody {
    role: FCGIRole,
    flags: u8,
}

impl FCGIBeginRequestBody {
    pub fn from_bytes(data: &[u8]) -> Self {
        Self {
            role: FCGIRole::from_u16(((data[0] as u16) << 8) | (data[1] as u16)),
            flags: data[2],
        }
    }
}

impl std::fmt::Display for FCGIBeginRequestBody {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "role: {} \n", self.role)?;
        write!(f, "flags: {} \n", self.flags)
    }
}

#[derive(Debug)]
struct FcgiHeader {
    version: u8,
    kind: FCGIHeaderType,
    id: u16,
    padding: u8,
    length: u16,
}

impl FcgiHeader {
    pub fn from_bytes(data: &[u8]) -> Self {
        Self {
            version: data[0],
            kind: FCGIHeaderType::from_u8(data[1]),
            id: ((data[2] as u16) << 8) | (data[3] as u16),
            length: ((data[4] as u16) << 8) | (data[5] as u16),
            padding: data[6],
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        vec![
            self.version,
            self.kind.as_u8(),
            (self.id >> 8) as u8,
            (self.id & 0xFF) as u8,
            (self.length >> 8) as u8,
            (self.length & 0xFF) as u8,
            self.padding,
            0,
        ]
    }
}

impl std::fmt::Display for FcgiHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Version: {} \n", self.version)?;
        write!(f, "Kind: {} \n", self.kind)?;
        write!(f, "ID: {} \n", self.id)?;
        write!(f, "Data length: {} \n", self.length)?;
        write!(f, "Padding: {} \n", self.padding)
    }
}

#[derive(Debug)]
enum FCGIRequestState {
    WaitForParams,
    WaitForStdin(FCGIRequestBodyState),
    WaitForStdout,
}

impl std::fmt::Display for FCGIRequestState {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let s = match self {
            FCGIRequestState::WaitForParams => "WaitForParams",
            FCGIRequestState::WaitForStdin(_) => "WaitForStdin",
            FCGIRequestState::WaitForStdout => "WaitForStdout",
        };
        write!(f, "{}", s)
    }
}

struct FGCIRequest {
    /// FastCGI params
    params: HashMap<String, String>,
    /// current request ID
    id: u16,
    /// current request socket
    fd: RawFd,
    /// Request data buffer
    data: Option<Vec<u8>>,
    /// current request state
    state: FCGIRequestState,
    /// pending data length
    pending_dlen: isize,
}

#[derive(Debug)]
enum WSHeaderOpcode {
    Data,
    Text,
    Bin,
    Close,
    Ping,
    Pong,
    Unknown,
}

impl std::fmt::Display for WSHeaderOpcode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let s = match self {
            WSHeaderOpcode::Text => "WSHeaderOpcode::Text",
            WSHeaderOpcode::Bin => "WSHeaderOpcode::Bin",
            WSHeaderOpcode::Close => "WSHeaderOpcode::Close",
            WSHeaderOpcode::Ping => "WSHeaderOpcode::Ping",
            WSHeaderOpcode::Pong => "WSHeaderOpcode::Pong",
            WSHeaderOpcode::Unknown => "WSHeaderOpcode::Unknown",
            WSHeaderOpcode::Data => "WSHeaderOpcode::Data",
        };
        write!(f, "{}", s)
    }
}

impl WSHeaderOpcode {
    fn from_u8(v: u8) -> WSHeaderOpcode {
        match v {
            0x0 => WSHeaderOpcode::Data,
            0x1 => WSHeaderOpcode::Text,
            0x2 => WSHeaderOpcode::Bin,
            0x8 => WSHeaderOpcode::Close,
            0x9 => WSHeaderOpcode::Ping,
            0xA => WSHeaderOpcode::Pong,
            _ => WSHeaderOpcode::Unknown,
        }
    }
    fn as_u8(&self) -> u8 {
        match self {
            WSHeaderOpcode::Text => 0x1,
            WSHeaderOpcode::Bin => 0x2,
            WSHeaderOpcode::Close => 0x8,
            WSHeaderOpcode::Ping => 0x9,
            WSHeaderOpcode::Pong => 0xA,
            WSHeaderOpcode::Unknown => 0xFF,
            WSHeaderOpcode::Data => 0x0,
        }
    }
}

#[derive(Debug)]
struct WSHeader {
    fin: u8,
    opcode: WSHeaderOpcode,
    len: usize,
    mask: u8,
    mask_key: Vec<u8>,
}

impl mlua::UserData for WSHeader {
    fn add_fields<'lua, F: mlua::UserDataFields<'lua, Self>>(fields: &mut F) {
        fields.add_field_method_get("fin", |_, this| Ok(this.fin));
        fields.add_field_method_get("opcode", |_, this| Ok(this.opcode.as_u8()));
        fields.add_field_method_get("len", |_, this| Ok(this.len));
        fields.add_field_method_get("mask", |_, this| Ok(this.mask));
    }
}
impl WSHeader {
    fn read_from(stream: &mut FCGIOStream) -> Result<WSHeader, std::io::Error> {
        let mut header = WSHeader {
            fin: 0,
            opcode: WSHeaderOpcode::Close,
            len: 0,
            mask: 0,
            mask_key: vec![0; 4],
        };
        let mut bytes = stream.stdin_read_exact(2)?;
        if BITV!(bytes[0], 6) == 1 || BITV!(bytes[0], 5) == 1 || BITV!(bytes[0], 4) == 1 {
            return Err(ERR!("Reserved bits 4,5,6 must be 0"));
        }
        header.fin = BITV!(bytes[0], 7);
        header.opcode = WSHeaderOpcode::from_u8(bytes[0] & 0x0F);
        header.mask = BITV!(bytes[1], 7);
        let len = bytes[1] & 0x7F;
        if len <= 125 {
            header.len = len as usize;
        } else if len == 126 {
            bytes = stream.stdin_read_exact(2)?;
            header.len = ((bytes[0] as usize) << 8) + (bytes[1] as usize);
        } else {
            bytes = stream.stdin_read_exact(8)?;
            // TODO we only support up to 4 bytes len
            header.len = ((bytes[4] as usize) << 24)
                + ((bytes[5] as usize) << 16)
                + ((bytes[6] as usize) << 8)
                + (bytes[7] as usize);
        }
        header.mask_key = stream.stdin_read_exact(4)?;
        DEBUG!("Read WS header: {:?}", header);
        match header.opcode {
            WSHeaderOpcode::Ping => {
                DEBUG!("Receive PING from client, send PONG");
                let data = header.read_data_from(stream)?;
                let mut respond_header = WSHeader {
                    fin: 1,
                    opcode: WSHeaderOpcode::Pong,
                    len: data.len(),
                    mask: !header.mask,
                    mask_key: Vec::new(),
                };
                respond_header.send_to(stream, &data)?;
            }
            WSHeaderOpcode::Pong => {}
            _ => {}
        };
        Ok(header)
    }

    fn read_data_from(&mut self, stream: &mut FCGIOStream) -> Result<Vec<u8>, std::io::Error> {
        let mut vec = stream.stdin_read_exact(self.len)?;
        if self.mask == 1 {
            for i in 0..vec.len() {
                vec[i] = vec[i] ^ self.mask_key[i % 4];
            }
        }
        Ok(vec)
    }

    fn send_to(&mut self, stream: &mut FCGIOStream, data: &[u8]) -> Result<(), std::io::Error> {
        let mut frame: Vec<u8>;
        if self.mask == 1 {
            let mut rng = rand::thread_rng();
            let r = rng.gen::<u32>();
            self.mask_key = vec![0, 4];
            self.mask_key[0] = ((r >> 24) & 0xFF) as u8;
            self.mask_key[1] = ((r >> 16) & 0xFF) as u8;
            self.mask_key[2] = ((r >> 8) & 0xFF) as u8;
            self.mask_key[3] = (r & 0xFF) as u8;
            let mut masked_data = data.to_vec();
            for i in 0..data.len() {
                masked_data[i] = masked_data[i] ^ self.mask_key[i % 4];
            }
            // send out header + data
            frame = self.as_bytes();
            if masked_data.len() > 0 {
                frame.append(&mut masked_data);
            }
        } else {
            frame = self.as_bytes();
            if data.len() > 0 {
                frame.extend(data);
            }
        }
        stream.write_record(frame)?;
        Ok(())
    }

    fn as_bytes(&self) -> Vec<u8> {
        let mut vec: Vec<u8> = Vec::new();
        vec.push((self.fin << 7) | self.opcode.as_u8());
        if self.len <= 125 {
            vec.push((self.mask << 7) | (self.len as u8));
        } else if self.len < 65536 {
            vec.extend([
                (self.mask << 7) | 126,
                ((self.len) >> 8) as u8,
                ((self.len) & 0x00FF) as u8,
            ]);
        } else {
            vec.extend([
                (self.mask << 7) | 127,
                0,
                0,
                0,
                0,
                ((self.len) >> 24) as u8,
                (((self.len) >> 16) & 0x00FF) as u8,
                (((self.len) >> 8) & 0x00FF) as u8,
                ((self.len) & 0x00FF) as u8,
            ]);
        }
        if self.mask == 1 {
            vec.extend(&self.mask_key);
        }
        return vec;
    }
}

struct FCGIOStream {
    fd: RawFd,
    id: u16,
    ws: bool,
    stdin_buffer: Vec<u8>,
}

impl FCGIOStream {
    fn read_stdin_record(&mut self) -> Result<(), std::io::Error> {
        if !self.ws {
            WARN!("read_stdin_record is only active when the current connection is websocket");
            return Ok(());
        }
        let header = fcgi_read_header(self)?;
        match header.kind {
            FCGIHeaderType::Stdin => {
                let body = fcgi_read_body(self, &header)?;
                self.stdin_buffer.extend(body);
            }
            _ => {
                WARN!(
                    "Expect FCGIHeaderType::Stdin record, received {}. Ignore it",
                    header.kind
                );
            }
        }
        Ok(())
    }

    fn stdin_read_exact(&mut self, len: usize) -> Result<Vec<u8>, std::io::Error> {
        while self.stdin_buffer.len() < len {
            self.read_stdin_record()?;
        }
        // consume first n bytes of the buffer vector
        Ok(self.stdin_buffer.drain(0..len).collect::<Vec<u8>>())
    }

    fn write_record(&mut self, buf: Vec<u8>) -> Result<(), std::io::Error> {
        let mut buf_reader = BufReader::with_capacity(2048, Cursor::new(buf));
        loop {
            let length = {
                let buffer = buf_reader.fill_buf()?;
                if buffer.len() > 0 {
                    fcgi_send_stdout(self, self.id, Some(buffer.to_vec()))?;
                }
                buffer.len()
            };
            if length == 0 {
                break;
            }
            buf_reader.consume(length);
        }
        Ok(())
    }
}

fn vec_from_variadic(
    values: mlua::Variadic<LuaValue>,
    bin_only: bool,
) -> Result<Vec<u8>, std::io::Error> {
    let mut output: Vec<u8> = Vec::new();
    let error = ERR!("Unsupported data type");
    for value in values {
        match &value {
            LuaNil => {}
            LuaValue::Boolean(v) => {
                if bin_only {
                    return Err(error);
                }
                output.extend(v.to_string().as_bytes());
            }
            LuaValue::Integer(v) => {
                if bin_only {
                    return Err(error);
                }
                output.extend(v.to_string().as_bytes());
            }
            LuaValue::Number(v) => {
                if bin_only {
                    return Err(error);
                }
                output.extend(v.to_string().as_bytes());
            }
            LuaValue::String(v) => {
                output.extend(v.as_bytes());
            }
            LuaValue::LightUserData(_)
            | LuaValue::Table(_)
            | LuaValue::Function(_)
            | LuaValue::Thread(_) => {
                return Err(error);
            }
            LuaValue::UserData(v) => {
                if v.is::<LuabyteArray>() {
                    let arr = v
                        .borrow::<LuabyteArray>()
                        .map_err(|e| ERR!(e.to_string()))?;
                    output.extend(&arr.0);
                } else {
                    let st = value.to_pointer() as *const LuaSlice;
                    if unsafe { (*st).magic } != LUA_SLICE_MAGIC {
                        return Err(error);
                    }
                    let data_slice = unsafe { std::slice::from_raw_parts((*st).data, (*st).len) };
                    output.extend(data_slice);
                }
            }
            LuaValue::Error(e) => {
                return Err(ERR!(e.to_string()));
            }
        }
    }
    Ok(output)
}

impl Write for FCGIOStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let ret = unsafe { libc::write(self.fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
        if ret != buf.len() as isize {
            let msg = format!(
                "Unable to write data to {}: only {} out of {} bytes have been written",
                self.fd,
                ret,
                buf.len()
            );
            return Err(ERR!(msg));
        }
        Ok(ret as usize)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        todo!()
    }
}

impl Read for FCGIOStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let ret = unsafe { libc::read(self.fd, buf.as_ptr() as *mut libc::c_void, buf.len()) };
        if ret < 0 {
            let msg = format!("Unable to read data from {}: return {}", self.fd, ret);
            return Err(ERR!(msg));
        }
        Ok(ret as usize)
    }
}

impl mlua::UserData for FCGIOStream {
    fn add_methods<'lua, M: mlua::UserDataMethods<'lua, Self>>(methods: &mut M) {
        methods.add_method_mut(
            "echo",
            |_, this: &mut FCGIOStream, values: mlua::Variadic<_>| {
                let output = vec_from_variadic(values, false)
                    .map_err(|e| mlua::Error::external(ERR!(e.to_string())))?;
                if output.len() > 0 {
                    this.write_record(output)
                        .map_err(|e| mlua::Error::external(ERR!(e.to_string())))?;
                }
                Ok(())
            },
        );
        methods.add_method_mut("send_file", |_, this: &mut FCGIOStream, path: String| {
            let file = std::fs::File::open(path)?;
            let mut buf_reader = BufReader::with_capacity(2048, file);
            loop {
                let length = {
                    let buffer = buf_reader.fill_buf()?;
                    fcgi_send_stdout(this, this.id, Some(buffer.to_vec()))
                        .map_err(|e| mlua::Error::external(ERR!(e.to_string())))?;
                    buffer.len()
                };
                if length == 0 {
                    break;
                }
                buf_reader.consume(length);
            }
            Ok(())
        });

        methods.add_method_mut(
            "print",
            |_, this: &mut FCGIOStream, values: mlua::Variadic<_>| {
                let output = vec_from_variadic(values, false)
                    .map_err(|e| mlua::Error::external(ERR!(e.to_string())))?;
                if output.len() > 0 {
                    this.write_record(output)
                        .map_err(|e| mlua::Error::external(ERR!(e.to_string())))?;
                }
                Ok(())
            },
        );
        methods.add_method("is_ws", |_, this: &FCGIOStream, ()| Ok(this.ws));
        methods.add_method("fd", |_, this: &FCGIOStream, ()| Ok(this.fd));
        methods.add_method("id", |_, this: &FCGIOStream, ()| Ok(this.id));

        // websocket specific methods
        methods.add_method_mut("ws_header", |_, this: &mut FCGIOStream, ()| {
            let header = WSHeader::read_from(this)
                .map_err(|e| mlua::Error::external(ERR!(e.to_string())))?;
            Ok(header)
        });

        methods.add_method_mut(
            "ws_read",
            |_, this: &mut FCGIOStream, value: mlua::Value| match value {
                LuaValue::UserData(v) => {
                    if v.is::<WSHeader>() {
                        let mut header = v.borrow_mut::<WSHeader>()?;
                        let vec = header
                            .read_data_from(this)
                            .map_err(|e| mlua::Error::external(ERR!(e.to_string())))?;
                        return Ok(LuabyteArray(vec));
                    }

                    Err(mlua::Error::external(ERR!(
                        "Invalid user-data used as websocket header"
                    )))
                }
                _ => Err(mlua::Error::external(ERR!(
                    "Invalid data used as websocket header"
                ))),
            },
        );

        methods.add_method_mut(
            "ws_send",
            |_, this: &mut FCGIOStream, (is_bin, values): (bool, Variadic<mlua::Value>)| {
                let output = vec_from_variadic(values, is_bin)
                    .map_err(|e| mlua::Error::external(ERR!(e.to_string())))?;
                if output.len() > 0 {
                    let mut header = WSHeader {
                        fin: 1,
                        opcode: WSHeaderOpcode::Text,
                        len: output.len(),
                        mask: 0,
                        mask_key: Vec::new(),
                    };
                    header
                        .send_to(this, &output)
                        .map_err(|e| mlua::Error::external(ERR!(e.to_string())))?
                }
                Ok(())
            },
        );

        methods.add_method_mut("ws_close", |_, this: &mut FCGIOStream, code: u32| {
            let mut header = WSHeader {
                fin: 1,
                opcode: WSHeaderOpcode::Close,
                len: 2,
                mask: 0,
                mask_key: Vec::new(),
            };
            header
                .send_to(this, &[(code >> 8) as u8, (code & 0xFF) as u8])
                .map_err(|e| mlua::Error::external(ERR!(e.to_string())))?;
            Ok(())
        });

        methods.add_method_mut("ws_send_file", |_, this: &mut FCGIOStream, path: String| {
            let file = std::fs::File::open(path)?;
            let mut buf_reader = BufReader::with_capacity(2048, file);
            let mut is_first = true;

            loop {
                let buffer = buf_reader.fill_buf()?;
                let length = buffer.len();
                let mut header = WSHeader {
                    fin: if length == 0 { 1 } else { 0 },
                    opcode: WSHeaderOpcode::Data,
                    len: length,
                    mask: 0,
                    mask_key: Vec::new(),
                };
                if is_first {
                    header.opcode = WSHeaderOpcode::Bin;
                    is_first = false;
                }
                header
                    .send_to(this, &buffer)
                    .map_err(|e| mlua::Error::external(ERR!(e.to_string())))?;
                if length == 0 {
                    break;
                }
                buf_reader.consume(length);
            }
            Ok(())
        });

        methods.add_method("log_info", |_, _: &FCGIOStream, string: String| {
            INFO!("{}", string);
            Ok(())
        });
        methods.add_method("log_error", |_, _: &FCGIOStream, string: String| {
            ERROR!("{}", string);
            Ok(())
        });
        methods.add_method("log_debug", |_, _: &FCGIOStream, string: String| {
            DEBUG!("{}", string);
            Ok(())
        });
        methods.add_method("log_warn", |_, _: &FCGIOStream, string: String| {
            WARN!("{}", string);
            Ok(())
        });
    }
}

fn fcgi_execute_request_handle(rq: &mut FGCIRequest) -> Result<(), Box<dyn std::error::Error>> {
    let lua = unsafe { mlua::Lua::unsafe_new() };
    lua.load_from_std_lib(mlua::StdLib::ALL)?;
    let global = lua.globals();
    let request = lua.create_table()?;

    for (k, v) in &rq.params {
        request.set(String::from(k), String::from(v))?;
    }
    if let Some(data) = rq.data.take() {
        let data_arr = LuabyteArray(data);
        request.set("RAW_DATA", data_arr)?;
    }
    // request params stored in _SERVER table
    global.set("_SERVER", request)?;

    // put the fcgio object
    let mut fcgio = FCGIOStream {
        fd: rq.fd,
        id: rq.id,
        ws: false,
        stdin_buffer: Vec::new(),
    };

    // check if the connection is upgraded as websocket
    if let Some(header) = rq.params.get("HTTP_UPGRADE") {
        if header == "websocket" {
            INFO!("Websocket is enabled on the current connection {}", rq.id);
            fcgio.ws = true;
        }
    }

    global.set("fcgio", fcgio)?;

    // support for byte array
    let bytes = lua.create_table()?;
    bytes.set(
        "from_string",
        lua.create_function(lua_new_bytes_from_string)?,
    )?;

    bytes.set("new", lua.create_function(lua_new_bytes)?)?;
    bytes.set("from_slice", lua.create_function(lua_new_from_slice)?)?;
    global.set("bytes", bytes)?;

    let path = rq
        .params
        .get("SCRIPT_FILENAME")
        .ok_or(ERR!("No SCRIPT_FILENAME found"))?;
    let source = std::fs::read_to_string(path)?;
    lua.load(&source).exec()?;
    Ok(())
}

fn fcgi_send_stderr<T: Write>(
    stream: &mut T,
    id: u16,
    eopt: Option<Box<dyn std::error::Error>>,
) -> Result<(), std::io::Error> {
    let mut header = FcgiHeader {
        version: FCGI_VERSION,
        kind: FCGIHeaderType::Stderr,
        id: id,
        length: 0,
        padding: 0,
    };
    if let Some(error) = eopt {
        let err_str = error.to_string();
        let str_len = err_str.len();
        let mut padding = (8 - str_len % 8) as u8;
        if padding == 8 {
            padding = 0;
        }
        let mut body = err_str.as_bytes().to_vec();
        let pad = vec![0; padding as usize];
        header.length = str_len as u16;
        header.padding = padding;
        body.extend(pad);
        stream.write_all(&header.as_bytes())?;
        stream.write_all(&body)?;
    } else {
        stream.write_all(&header.as_bytes())?;
    }
    Ok(())
}

fn fcgi_send_stdout<T: Write>(
    stream: &mut T,
    id: u16,
    dopt: Option<Vec<u8>>,
) -> Result<(), std::io::Error> {
    let mut header = FcgiHeader {
        version: FCGI_VERSION,
        kind: FCGIHeaderType::Stdout,
        id: id,
        length: 0,
        padding: 0,
    };
    if let Some(data) = dopt {
        header.length = data.len() as u16;
        header.padding = (8 - header.length % 8) as u8;
        if header.padding == 8 {
            header.padding = 0;
        }
        let mut body = data;
        let pad = vec![0; header.padding as usize];
        body.extend(pad);
        stream.write_all(&header.as_bytes())?;
        stream.write_all(&body)?;
    } else {
        stream.write_all(&header.as_bytes())?;
    }
    Ok(())
}

fn fcgi_send_end_request<T: Read + Write>(
    stream: &mut T,
    id: u16,
    status: EndRequestStatus,
) -> Result<(), std::io::Error> {
    let header = FcgiHeader {
        version: FCGI_VERSION,
        kind: FCGIHeaderType::EndRequest,
        id: id,
        length: 8,
        padding: 0,
    };
    let body = vec![0, 0, 0, 0, status.as_u8(), 0, 0, 0];
    stream.write_all(&header.as_bytes())?;
    stream.write_all(&body)?;
    Ok(())
}

#[derive(Debug)]
struct FCGIFilePart {
    name: String,
    tmp_path: String,
    handle: std::fs::File,
}
#[derive(Debug)]
enum FCGIRequestBodyState {
    FindBoundary(String),
    HeaderDecoding(String),
    DataDecoding {
        boundary: String,
        name: String,
        file: Option<FCGIFilePart>,
        vec: Vec<u8>,
    },
    BinaryData,
}

fn fcgi_read_stdin<T: Read + Write>(
    stream: &mut T,
    rq: &mut FGCIRequest,
    header: &FcgiHeader,
) -> Result<bool, Error> {
    match &mut rq.state {
        FCGIRequestState::WaitForStdin(body_state) => {
            if header.length == 0 {
                match body_state {
                    FCGIRequestBodyState::BinaryData => {}
                    __ => {
                        return Err(ERR!("Invalid body data"));
                    }
                }
                DEBUG!(
                    "All stdin records read, now wait for stdout data on request: {}",
                    header.id
                );
                rq.state = FCGIRequestState::WaitForStdout;
                if let Err(error) = fcgi_execute_request_handle(rq) {
                    // send stderror
                    fcgi_send_stderr(stream, header.id, Some(error))?;
                }
                fcgi_send_stderr(stream, header.id, None)?;
                fcgi_send_stdout(stream, header.id, None)?;
                // send end connection
                fcgi_send_end_request(stream, header.id, EndRequestStatus::Complete)?;
                return Ok(true);
            } else {
                let body = fcgi_read_body(stream, &header)?;
                rq.pending_dlen -= body.len() as isize;
                if rq.pending_dlen < 0 {
                    return Err(ERR!(
                        "Request body is bigger than request content-length header"
                    ));
                }
                if let None = rq.data {
                    rq.data = Some(Vec::new());
                }
                match rq.data.take() {
                    Some(mut data) => {
                        let mut stateopt = None;
                        data.extend(body);
                        loop {
                            let curr_state = match &mut stateopt {
                                Some(st) => st,
                                None => body_state,
                            };
                            // decode stdin data
                            match fcgi_decode_stdin_data(curr_state, &mut data, &mut rq.params)? {
                                Some(st) => {
                                    stateopt = Some(st);
                                    if data.len() == 0 {
                                        break;
                                    }
                                }
                                None => {
                                    break;
                                }
                            }
                        }
                        if let Some(state) = stateopt {
                            rq.state = FCGIRequestState::WaitForStdin(state);
                        }
                        rq.data = if data.len() == 0 { None } else { Some(data) };
                    }
                    None => {}
                }
            }
        }
        _ => {
            WARN!(
                "Should not receive a stdin record as the request is in {} state",
                rq.state
            );
        }
    }
    Ok(false)
}

fn fcgi_read_params<T: Read + Write>(
    stream: &mut T,
    rq: &mut FGCIRequest,
    header: &FcgiHeader,
) -> Result<(), std::io::Error> {
    match &mut rq.state {
        FCGIRequestState::WaitForParams => {
            if header.length == 0 {
                DEBUG!(
                    "All param records read, now wait for stdin data on request: {}",
                    header.id
                );
                // get the content length
                if let Some(text) = rq.params.get("CONTENT_LENGTH") {
                    if text.len() > 0 {
                        rq.pending_dlen = text.parse::<isize>().map_err(|e| ERR!(e.to_string()))?;
                    }
                }
                if let Some(text) = rq.params.get("CONTENT_TYPE") {
                    // check if this is a multipart/form-data request
                    if let Some(_) = text.find("multipart/form-data") {
                        let split: Vec<&str> = text.split("boundary=").collect();
                        if split.len() != 2 {
                            return Err(ERR!("No boundary found in multipart/form-data body"));
                        }
                        DEBUG!("multipart/form-data boundary: {}", split[1].trim());
                        let mut boundary = "--".to_owned();
                        boundary.push_str(split[1].trim());
                        rq.state = FCGIRequestState::WaitForStdin(
                            FCGIRequestBodyState::FindBoundary(boundary),
                        );
                    } else {
                        rq.state = FCGIRequestState::WaitForStdin(FCGIRequestBodyState::BinaryData);
                    }
                } else {
                    return Err(ERR!("No content type header found in the request"));
                }
            } else {
                fcgi_decode_params(rq, &fcgi_read_body(stream, &header)?)?;
            }
        }
        __ => {
            WARN!(
                "Should not receive a param record as the request is in {} state",
                rq.state
            );
        }
    }
    Ok(())
}

pub fn process_request<T: Read + Write + AsRawFd>(stream: &mut T) -> Result<(), std::io::Error> {
    let mut requests: HashMap<u16, FGCIRequest> = HashMap::new();
    loop {
        let header = fcgi_read_header(stream)?;
        match header.kind {
            FCGIHeaderType::BeginRequest => {
                let body = FCGIBeginRequestBody::from_bytes(&fcgi_read_body(stream, &header)?);
                DEBUG!("Begin Request: {:?}, with body {:?}", header, body);
                if body.role != FCGIRole::Responder {
                    fcgi_send_end_request(stream, header.id, EndRequestStatus::UnknownRole)?;
                    return Err(ERR!("Only Responder role is supported"));
                }
                // check if we have already request of this kind
                if let Some(_) = requests.get(&header.id) {
                    WARN!("Request {} already exists, ignore this message", header.id);
                } else {
                    let rq: FGCIRequest = FGCIRequest {
                        id: header.id,
                        params: HashMap::new(),
                        data: None,
                        state: FCGIRequestState::WaitForParams,
                        fd: stream.as_raw_fd(),
                        pending_dlen: 0,
                    };
                    requests.insert(header.id, rq);
                }
            }
            FCGIHeaderType::Params => {
                if let Some(rq) = requests.get_mut(&header.id) {
                    fcgi_read_params(stream, rq, &header).map_err(|e| {
                        let _ =
                            fcgi_send_end_request(stream, header.id, EndRequestStatus::Complete);
                        e
                    })?;
                } else {
                    WARN!("Uknown request {}, ignore param record", header.id);
                }
            }
            FCGIHeaderType::Stdin => {
                if let Some(rq) = requests.get_mut(&header.id) {
                    if fcgi_read_stdin(stream, rq, &header).map_err(|e| {
                        let _ =
                            fcgi_send_end_request(stream, header.id, EndRequestStatus::Complete);
                        e
                    })? {
                        break;
                    }
                } else {
                    WARN!("Uknow request {}, ignore stdin record", header.id);
                }
            }
            _ => {
                WARN!(
                    "Unsupported record type: {} on request {}",
                    header.kind,
                    header.id
                );
            }
        }
    }
    Ok(())
}

fn fcgi_decode_stdin_data(
    state: &mut FCGIRequestBodyState,
    buffer: &mut Vec<u8>,
    params: &mut HashMap<String, String>,
) -> Result<Option<FCGIRequestBodyState>, Error> {
    match state {
        FCGIRequestBodyState::FindBoundary(boundary) => {
            let mut pattern = boundary.to_string();
            pattern.push_str("\r\n");
            if let Some(index) = twoway::find_bytes(buffer, pattern.as_bytes()) {
                let _ = buffer.drain(0..index + pattern.len());
                DEBUG!("Boundary found, decoding header");
                return Ok(Some(FCGIRequestBodyState::HeaderDecoding(
                    boundary.to_string(),
                )));
            }
            Ok(None)
        }
        FCGIRequestBodyState::HeaderDecoding(boundary) => {
            if let Some(end_index) = twoway::find_bytes(buffer, "\r\n\r\n".as_bytes()) {
                let pattern = "Content-Disposition:";
                if let Some(index) = twoway::find_bytes(&buffer[0..end_index], pattern.as_bytes()) {
                    // got content-disposition, get the line
                    let start_lime_index = index + pattern.len();
                    let offset = twoway::find_bytes(
                        &buffer[start_lime_index..end_index + 2],
                        "\r\n".as_bytes(),
                    )
                    .ok_or(ERR!("Unknown ending of Content-Disposition line"))?;
                    let line = String::from_utf8(
                        buffer[start_lime_index..start_lime_index + offset].to_vec(),
                    )
                    .map_err(|e| ERR!(e.to_string()))?;
                    DEBUG!("Content-Disposition: {}", line);
                    // parsing content disposition for `name` and `file`
                    // name is obliged, so find it first
                    let mut name: Option<&str> = None;
                    let mut fileopt: Option<&str> = None;

                    for text in line.trim().split(";") {
                        let trimmed = text.trim();
                        if let Some(index) = trimmed.find("filename=") {
                            fileopt = Some(&text[index + 11..trimmed.len()]);
                            DEBUG!("Part filename = [{}]", fileopt.unwrap());
                        } else if let Some(index) = trimmed.find("name=") {
                            name = Some(&text[index + 7..trimmed.len()]);
                            DEBUG!("Part name = [{}]", name.unwrap());
                        } else {
                            DEBUG!("Ignore part: {}", text);
                        }
                    }
                    if let None = name {
                        return Err(ERR!("No name attribut found in multi-part part"));
                    }
                    let mut file = None;
                    if let Some(filename) = fileopt {
                        let tmp_path = format!(
                            "{}/{}.{}",
                            TMP_DIR,
                            filename,
                            SystemTime::now()
                                .duration_since(SystemTime::UNIX_EPOCH)
                                .map_err(|e| ERR!(e.to_string()))?
                                .as_millis()
                        );
                        DEBUG!("Part will be saved to: {}", &tmp_path);
                        file = Some(FCGIFilePart {
                            name: filename.to_owned(),
                            handle: std::fs::File::create(&tmp_path)?,
                            tmp_path,
                        });
                    }
                    let part_state = FCGIRequestBodyState::DataDecoding {
                        boundary: boundary.to_string(),
                        name: name.unwrap().to_owned(),
                        file: file,
                        vec: Vec::new(),
                    };
                    DEBUG!("Header decoding finished, go to data-decoding");
                    let _ = buffer.drain(0..end_index + 4);
                    return Ok(Some(part_state));
                }
                let _ = buffer.drain(0..end_index + 4);
            }
            Ok(None)
        }
        FCGIRequestBodyState::DataDecoding {
            boundary,
            name,
            file,
            vec,
        } => {
            loop {
                match twoway::find_bytes(buffer, "\r\n".as_bytes()) {
                    Some(index) => {
                        let mut pattern_len = boundary.len();
                        let mut content_data = &buffer[0..index + 2];
                        let mut remaining = &buffer[index + 2..];
                        if remaining.len() > pattern_len {
                            //DEBUG!("content : {:?}", content_data);
                            //DEBUG!("boundary: {:?}", boundary.as_bytes());
                            //DEBUG!("remaining : {:?}", remaining);
                            if remaining.starts_with(boundary.as_bytes()) {
                                remaining = &remaining[pattern_len..];
                                let state;
                                if remaining.starts_with("\r\n".as_bytes()) {
                                    state = Some(FCGIRequestBodyState::HeaderDecoding(
                                        boundary.to_owned(),
                                    ));
                                    DEBUG!("Part Boundary end found, decoding next header");
                                } else if remaining.starts_with("--".as_bytes()) {
                                    pattern_len += 2;
                                    state = Some(FCGIRequestBodyState::BinaryData);
                                    DEBUG!("Request Boundary end found, finish stdin read");
                                } else {
                                    return Err(ERR!("Invalid boundary ending"));
                                }
                                // ignore or write to file
                                content_data = &buffer[0..index];
                                let value;
                                if let Some(part) = file {
                                    value = format!(
                                        "{{\"file\":\"{}\",\"tmp\":\"{}\"}}",
                                        part.name, part.tmp_path
                                    );
                                    part.handle.write_all(content_data)?;
                                } else {
                                    vec.extend(content_data);
                                    // collect the data
                                    value = String::from_utf8(vec.to_vec())
                                        .map_err(|e| ERR!(e.to_string()))?;
                                    DEBUG!("part data: {}", &value);
                                }
                                let _ = params.insert(format!("MULTIPART[{}]", name), value);
                                let _ = buffer.drain(0..content_data.len() + pattern_len + 4);
                                return Ok(state);
                            } else {
                                // ignore or write to file
                                if let Some(part) = file {
                                    part.handle.write_all(content_data)?;
                                } else {
                                    vec.extend(content_data);
                                }
                                let _ = buffer.drain(0..content_data.len());
                            }
                        } else {
                            break;
                        }
                    }
                    None => {
                        // ignore or write to file
                        if let Some(part) = file {
                            part.handle.write_all(buffer)?;
                            buffer.clear();
                        }
                        break;
                    }
                }
            }

            Ok(None)
        }
        FCGIRequestBodyState::BinaryData => Ok(None),
    }
    //Ok(())
}

fn fcgi_read_header<T: Read + Write>(stream: &mut T) -> Result<FcgiHeader, Error> {
    let mut buf = vec![0; FCGI_HEADER_LEN];
    stream.read_exact(&mut buf)?;
    let header: FcgiHeader = FcgiHeader::from_bytes(&buf);
    Ok(header)
}

fn fcgi_read_body<T: Read + Write>(stream: &mut T, header: &FcgiHeader) -> Result<Vec<u8>, Error> {
    let mut buf = vec![0; header.length as usize];
    stream.read_exact(&mut buf)?;
    let mut pad: Vec<u8> = vec![0; header.padding as usize];
    stream.read_exact(&mut pad)?;

    Ok(buf.to_vec())
}

fn fcgi_decode_strlen(data: &[u8]) -> usize {
    let b0 = data[0];
    if b0 >> 7 == 0 {
        b0 as usize
    } else {
        return (((data[0] as usize) & 0x7f) << 24)
            + ((data[1] as usize) << 16)
            + ((data[2] as usize) << 8)
            + (data[3] as usize);
    }
}

fn fcgi_decode_params(rq: &mut FGCIRequest, vec: &Vec<u8>) -> Result<(), std::io::Error> {
    let mut pos = 0;
    while pos < vec.len() {
        let data = &vec[pos..];
        let mut index: usize = 1;
        let key_len = fcgi_decode_strlen(data);
        if key_len > 127 {
            index = 4;
        }
        let value_len = fcgi_decode_strlen(&data[index..]);
        //INFO!("Key len {}, value len {}", key_len, value_len);
        if value_len > 127 {
            index += 4;
        } else {
            index += 1;
        }
        //DEBUG!("data: {:?}", data);
        //DEBUG!("key: {:?}", data[index..index + key_len].to_vec());
        //DEBUG!("Value: {:?}", data[index+key_len..index+key_len+value_len].to_vec());
        let key = String::from_utf8(data[index..index + key_len].to_vec())
            .map_err(|e| ERR!(e.to_string()))?;
        let value: String =
            String::from_utf8(data[index + key_len..index + key_len + value_len].to_vec())
                .map_err(|e| ERR!(e.to_string()))?;
        DEBUG!("PARAM: [{}] -> [{}]", key, value);
        pos = pos + index + key_len + value_len;

        let _ = rq.params.insert(key, value);
    }
    Ok(())
}

fn lua_new_bytes(_: &mlua::Lua, size: usize) -> LuaResult<LuabyteArray> {
    let arr = LuabyteArray(vec![0; size]);
    Ok(arr)
}

fn lua_new_from_slice(_: &mlua::Lua, value: mlua::Value) -> LuaResult<LuabyteArray> {
    let st = value.to_pointer() as *const LuaSlice;
    if unsafe { (*st).magic } != LUA_SLICE_MAGIC {
        return Err(mlua::Error::external(ERR!("Unsupported data type")));
    }
    let data_slice = unsafe { std::slice::from_raw_parts((*st).data, (*st).len) };
    Ok(LuabyteArray(data_slice.to_vec()))
}

fn lua_new_bytes_from_string(_: &mlua::Lua, string: String) -> LuaResult<LuabyteArray> {
    let arr = LuabyteArray(string.as_bytes().to_vec());
    Ok(arr)
}

struct LuabyteArray(Vec<u8>);

impl mlua::UserData for LuabyteArray {
    fn add_methods<'lua, M: mlua::UserDataMethods<'lua, Self>>(methods: &mut M) {
        methods.add_method("size", |_, this: &LuabyteArray, ()| Ok(this.0.len()));

        methods.add_method("into", |_, this: &LuabyteArray, value: mlua::Value| {
            let st = value.to_pointer() as *mut LuaSlice;
            if unsafe { (*st).magic } != LUA_SLICE_MAGIC {
                return Err(mlua::Error::external(ERR!("Unsupported data type")));
            }
            unsafe {
                (*st).data = this.0.as_ptr() as *const u8;
                (*st).len = this.0.len();
            }
            Ok(())
        });

        methods.add_method("fileout", |_, this: &LuabyteArray, path: String| {
            match std::fs::File::create(&path) {
                Ok(mut file) => {
                    if let Err(error) = file.write_all(&this.0) {
                        ERROR!("Unable to write byte array to file {}: {}", &path, error);
                        return Ok(0);
                    }
                }
                Err(error) => {
                    ERROR!("Unable open file {}: {}", path, error);
                    return Ok(0);
                }
            }
            Ok(1)
        });
        methods.add_meta_method(mlua::MetaMethod::Index, |_, this, index: isize| {
            if index < 1 || index > this.0.len() as isize {
                let error = ERR!(format!(
                    "Index {} out of bound, array size is {}",
                    index,
                    this.0.len()
                ));
                ERROR!("{}", error);
                return Ok(None);
            }
            Ok(Some(this.0[index as usize - 1]))
        });

        methods.add_meta_method(
            mlua::MetaMethod::ToString,
            |_, this, ()| match String::from_utf8(this.0.clone()) {
                Err(error) => {
                    let err = format!("Unable to convert byte array to string: {}", error);
                    ERROR!("{}", err);
                    return Ok(None);
                }
                Ok(string) => Ok(Some(string)),
            },
        );
        methods.add_method_mut("extend", |_, this, values: Variadic<mlua::Value>| {
            let mut output = vec_from_variadic(values, true)
                .map_err(|e| mlua::Error::external(ERR!(e.to_string())))?;
            this.0.append(&mut output);
            Ok(())
        });

        methods.add_meta_method_mut(
            mlua::MetaMethod::NewIndex,
            |_, this, (index, value): (isize, u8)| {
                if index < 1 || index > this.0.len() as isize {
                    let error = ERR!(format!(
                        "Index {} out of bound, array size is {}",
                        index,
                        this.0.len()
                    ));
                    ERROR!("{}", error);
                } else {
                    this.0[index as usize - 1] = value;
                }
                Ok(())
            },
        );
        methods.add_meta_method(mlua::MetaMethod::Len, |_, this, ()| Ok(this.0.len()));
    }
}

#[repr(C)]
pub struct LuaSlice {
    magic: usize,
    len: usize,
    data: *const u8,
}

#[no_mangle]
pub extern "C" fn fcgi_send_slice(fd: RawFd, id: u16, ptr: *const u8, size: usize) -> isize {
    let data_slice = unsafe { std::slice::from_raw_parts(ptr, size) }.to_vec();
    let mut stream = FCGIOStream {
        fd,
        id,
        ws: false,
        stdin_buffer: Vec::new(),
    };

    if let Err(error) = fcgi_send_stdout(&mut stream, id, Some(data_slice)) {
        ERROR!("Unable to send data slice: {}", error);
        return -1;
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn lua_slice_magic() -> usize {
    return LUA_SLICE_MAGIC;
}
