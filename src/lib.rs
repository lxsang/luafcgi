use libc;
use mlua::prelude::*;
use nix;
use std::collections::HashMap;
use std::ffi::CString;
use std::fmt::Arguments;
use std::io::{Error, ErrorKind, Read, Write};
use std::os::fd::RawFd;
use std::os::unix::io::AsRawFd;

/// app author
pub const APP_AUTHOR: &str = "Dany LE <mrsang@iohub.dev>";

/// app version
pub const APP_VERSION: &str = "0.1.0";

/// Application name
pub const DAEMON_NAME: &str = "luad";

fn is_debug_enable() -> bool {
    match std::env::var("debug") {
        Ok(value) => return value == "1" || value == "true",
        Err(_) => {}
    }
    false
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

/// Different Logging levels for `LOG`
pub enum LogLevel {
    /// Error conditions
    ERROR,
    /// Normal, but significant, condition
    INFO,
    /// Warning conditions
    WARN,
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
        }
        Self {}
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
            _ => {
                if !is_debug_enable() {
                    return Ok(());
                }
                libc::LOG_NOTICE
            }
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

const FCGI_HEADER_LEN: usize = 8;
const FCGI_VERSION: u8 = 1;

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

#[derive(Debug, PartialEq)]
enum FCGIRequestState {
    WaitForParams,
    WaitForStdin,
    WaitForStdout,
}

impl std::fmt::Display for FCGIRequestState {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let s = match self {
            FCGIRequestState::WaitForParams => "WaitForParams",
            FCGIRequestState::WaitForStdin => "WaitForStdin",
            FCGIRequestState::WaitForStdout => "WaitForStdout",
        };
        write!(f, "{}", s)
    }
}

struct FGCIRequest {
    params: HashMap<String, String>,
    id: u16,
    fd: RawFd,
    data: Option<Vec<u8>>,
    state: FCGIRequestState,
}

struct FCGIOStream {
    fd: RawFd,
    id: u16,
}

impl FCGIOStream {
    fn write_record(&mut self, buf: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
        fcgi_send_stdout(self, self.id, Some(buf))?;
        Ok(())
    }
    fn write_variadic(
        &mut self,
        values: mlua::Variadic<LuaValue>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut output: Vec<u8> = Vec::new();

        for value in values {
            match value {
                LuaNil => {}
                LuaValue::Boolean(v) => output.extend(v.to_string().as_bytes()),
                LuaValue::Integer(v) => output.extend(v.to_string().as_bytes()),
                LuaValue::Number(v) => output.extend(v.to_string().as_bytes()),
                LuaValue::String(v) => output.extend(v.as_bytes()),
                LuaValue::LightUserData(_)
                | LuaValue::Table(_)
                | LuaValue::Function(_)
                | LuaValue::Thread(_) => {
                    return Err(Box::new(ERR!("Unsupported data type")));
                }
                LuaValue::UserData(v) => {
                    if !v.is::<LuabyteArray>() {
                        return Err(Box::new(ERR!("Unsupported data type")));
                    }
                    let arr = v.borrow::<LuabyteArray>()?;
                    output.extend(arr.0.clone());
                }
                LuaValue::Error(e) => {
                    fcgi_send_stderr(self, self.id, Some(e.to_string().into()))?;
                }
            }
        }
        if output.len() > 0 {
            self.write_record(output)?;
        }
        Ok(())
    }
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

impl mlua::UserData for FCGIOStream {
    fn add_methods<'lua, M: mlua::UserDataMethods<'lua, Self>>(methods: &mut M) {
        methods.add_method_mut(
            "echo",
            |_, this: &mut FCGIOStream, values: mlua::Variadic<_>| {
                this.write_variadic(values)
                    .map_err(|e| mlua::Error::external(ERR!(e.to_string())))
            },
        );
        methods.add_method_mut(
            "print",
            |_, this: &mut FCGIOStream, values: mlua::Variadic<_>| {
                this.write_variadic(values)
                    .map_err(|e| mlua::Error::external(ERR!(e.to_string())))
            },
        );
        methods.add_method("raw_fd", |_, this: &FCGIOStream, ()| Ok(this.fd));
        methods.add_method("id", |_, this: &FCGIOStream, ()| Ok(this.id));
    }
}

fn fcgi_execute_request_handle(rq: &mut FGCIRequest) -> Result<(), Box<dyn std::error::Error>> {
    let lua = mlua::Lua::new();
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
    let fcgio = FCGIOStream {
        fd: rq.fd,
        id: rq.id,
    };
    global.set("fcgio", fcgio)?;

    // support for byte array
    let bytes = lua.create_table()?;
    bytes.set(
        "from_string",
        lua.create_function(lua_new_bytes_from_string)?,
    )?;
    bytes.set("new", lua.create_function(lua_new_bytes)?)?;
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
) -> Result<(), Box<dyn std::error::Error>> {
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
) -> Result<(), Box<dyn std::error::Error>> {
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

fn fcgi_send_end_request<T: Read + Write + AsRawFd>(
    stream: &mut T,
    id: u16,
    status: EndRequestStatus,
) -> Result<(), Box<dyn std::error::Error>> {
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

pub fn process_request<T: Read + Write + AsRawFd>(
    stream: &mut T,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut requests: HashMap<u16, FGCIRequest> = HashMap::new();
    loop {
        let header = fcgi_read_header(stream)?;
        match header.kind {
            FCGIHeaderType::BeginRequest => {
                let body = FCGIBeginRequestBody::from_bytes(&fcgi_read_body(stream, &header)?);
                INFO!("Begin Request: {:?}, with body {:?}", header, body);
                if body.role != FCGIRole::Responder {
                    fcgi_send_end_request(stream, header.id, EndRequestStatus::UnknownRole)?;
                    return Err(Box::new(ERR!("Only Responder role is supported")));
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
                    };
                    requests.insert(header.id, rq);
                }
            }
            FCGIHeaderType::Params => {
                if let Some(rq) = requests.get_mut(&header.id) {
                    if rq.state != FCGIRequestState::WaitForParams {
                        WARN!(
                            "Should not receive a param record as the request is in {} state",
                            rq.state
                        );
                    } else {
                        if header.length == 0 {
                            INFO!(
                                "All param records read, now wait for stdin data on request: {}",
                                header.id
                            );
                            rq.state = FCGIRequestState::WaitForStdin;
                        } else {
                            fcgi_decode_params(rq, &fcgi_read_body(stream, &header)?)?;
                        }
                    }
                } else {
                    WARN!("Uknow request {}, ignore param record", header.id);
                }
            }
            FCGIHeaderType::Stdin => {
                if let Some(rq) = requests.get_mut(&header.id) {
                    if rq.state != FCGIRequestState::WaitForStdin {
                        WARN!(
                            "Should not receive a stdin record as the request is in {} state",
                            rq.state
                        );
                    } else {
                        if header.length == 0 {
                            INFO!(
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
                            break;
                        } else {
                            let body = fcgi_read_body(stream, &header)?;
                            if let None = rq.data {
                                rq.data = Some(Vec::new())
                            }
                            match rq.data.take() {
                                Some(mut data) => {
                                    data.extend(body);
                                    rq.data = Some(data);
                                }
                                None => {}
                            }
                        }
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

fn fcgi_read_header<T: Read + Write + AsRawFd>(stream: &mut T) -> Result<FcgiHeader, Error> {
    let mut buf = vec![0; FCGI_HEADER_LEN];
    stream.read_exact(&mut buf)?;
    let header: FcgiHeader = FcgiHeader::from_bytes(&buf);
    Ok(header)
}

fn fcgi_read_body<T: Read + Write + AsRawFd>(
    stream: &mut T,
    header: &FcgiHeader,
) -> Result<Vec<u8>, Error> {
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

fn fcgi_decode_params(
    rq: &mut FGCIRequest,
    data: &Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
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
    //INFO!("data: {:?}", data);
    //INFO!("key: {:?}", data[index..index + key_len].to_vec());
    //INFO!("Value: {:?}", data[index+key_len..index+key_len+value_len].to_vec());
    let key = String::from_utf8(data[index..index + key_len].to_vec())?;
    let value: String =
        String::from_utf8(data[index + key_len..index + key_len + value_len].to_vec())?;
    INFO!("PARAM: [{}] -> [{}]", key, value);
    let _ = rq.params.insert(key, value);
    Ok(())
}

fn lua_new_bytes(_: &mlua::Lua, size: usize) -> LuaResult<LuabyteArray> {
    let arr = LuabyteArray(vec![0; size]);
    Ok(arr)
}

fn lua_new_bytes_from_string(_: &mlua::Lua, string: String) -> LuaResult<LuabyteArray> {
    let arr = LuabyteArray(string.as_bytes().to_vec());
    Ok(arr)
}

struct LuabyteArray(Vec<u8>);

impl mlua::UserData for LuabyteArray {
    fn add_methods<'lua, M: mlua::UserDataMethods<'lua, Self>>(methods: &mut M) {
        methods.add_method("size", |_, this: &LuabyteArray, ()| Ok(this.0.len()));

        methods.add_method("write", |_, this: &LuabyteArray, path: String| {
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
        methods.add_meta_method_mut(mlua::MetaMethod::Len, |_, this, ()| Ok(this.0.len()));
    }
}
