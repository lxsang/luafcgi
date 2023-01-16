//! Lua FastCGI main application
//!
//! **Author**: "Dany LE <mrsang@iohub.dev>"
//!
//!
#![warn(
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_qualifications,
    unused_results,
    missing_docs,
    clippy::pedantic,
    clippy::missing_docs_in_private_items
)]
use clap;
use serde;
use toml;
//use std::fs::File;
use luad::*;
use std::io::Read;
use std::io::Write;
use std::net::TcpListener;
use std::os::fd::FromRawFd;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::thread;

/// Callback: clean up function
///
/// This function remove the unix socket file if
/// exist before quiting the program
///
/// # Arguments
///
/// * `n` - system exit code
fn clean_up(n: i32) {
    if let Ok(socket_name) = std::env::var("socket") {
        let file = socket_name.replace("unix:", "");
        let path = Path::new(&file);
        if path.exists() {
            std::fs::remove_file(path).unwrap();
        }
    }
    if n != 0 {
        ERROR!(
            "The LUA fastCGI daemon is terminated by system signal: {}",
            n
        );
        std::process::exit(0);
    }
}

fn handle_request<T: Read + Write + AsRawFd>(stream: &mut T) {
    if let Err(error) = process_request(stream) {
        ERROR!("Unable to process request: {}", error);
    }
    INFO!("Request on socket {} is processed", stream.as_raw_fd());
}

/// Start the `fastCGI` server
///
/// # Arguments
///
/// * `socket_opt` - The socket string that the server listens on
fn serve(config: &Config) {
    // bind to a socket if any
    if let Some(socket_name) = config.socket.as_deref() {
        // test if the socket name is an unix domain socket
        if socket_name.starts_with("unix:") {
            // e.g unix:/var/run/lighttpd/maint/efcgi.socket
            INFO!("Use unix domain socket: {}", socket_name);
            std::env::set_var("socket", socket_name);
            clean_up(0);
            let listener = UnixListener::bind(socket_name.replace("unix:", "")).unwrap();
            for client in listener.incoming() {
                let mut stream = client.unwrap();
                let _ = std::thread::spawn(move || {
                    handle_request(&mut stream);
                });
            }
        } else {
            // TCP socket eg. 127.0.0.1:9000
            INFO!("Use TCP socket: {}", socket_name);
            let listener = TcpListener::bind(socket_name).unwrap();
            for client in listener.incoming() {
                let mut stream = client.unwrap();
                let _ = thread::spawn(move || {
                    handle_request(&mut stream);
                });
            }
        }
    } else {
        // if there is no socket configuration, assume that the stdio is already mapped
        // to a socket. This is usually done by by the parent process (e.g. webserver) that launches efcgi
        INFO!("No socket specified! use stdin as listenning socket");
        let stdin = std::io::stdin();
        let fd = stdin.as_raw_fd();
        if is_unix_socket(fd).unwrap() {
            INFO!("Stdin is used as Unix domain socket");
            let listener = unsafe { UnixListener::from_raw_fd(stdin.as_raw_fd()) };
            for client in listener.incoming() {
                let mut stream = client.unwrap();

                let _ = thread::spawn(move || {
                    handle_request(&mut stream);
                });
            }
        } else {
            INFO!("Stdin is used as TCP Socket");
            let listener = unsafe { TcpListener::from_raw_fd(stdin.as_raw_fd()) };
            for client in listener.incoming() {
                let mut stream = client.unwrap();

                let _ = thread::spawn(move || {
                    handle_request(&mut stream);
                });
            }
        }
    }
}

#[derive(serde::Deserialize, Debug)]
struct Config {
    socket: Option<String>,
    pidfile: Option<String>,
    user: Option<String>,
    group: Option<String>,
    debug: bool,
}

/// Main application entry
///
/// Run a `fastCGI` server
fn main() {
    on_exit(clean_up);
    let _log = LOG::init_log();
    let matches = clap::App::new(DAEMON_NAME)
        .author(APP_AUTHOR)
        .about("Lua FastCGI daemon")
        .version(APP_VERSION)
        .arg(
            clap::Arg::with_name("file")
                .short("f")
                .long("file")
                .value_name("FILE")
                .help("Configuration file")
                .required(false)
                .takes_value(true),
        )
        .get_matches();
    let mut config = Config {
        socket: None,
        pidfile: None,
        user: None,
        group: None,
        debug: false,
    };
    match matches.value_of("file") {
        Some(path) => {
            INFO!("Configuration file: {}", path);
            let contents = std::fs::read_to_string(path).unwrap();
            config = toml::from_str(&contents).unwrap();
            if config.debug {
                std::env::set_var("luad_debug", "true");
            }
            // drop user privilege if only user and group available in
            // the configuration file, otherwise ignore
            privdrop(config.user.as_deref(), config.group.as_deref()).unwrap();

            // write pid file
            match &config.pidfile {
                Some(pidfile) => {
                    let mut f = std::fs::File::create(&pidfile).unwrap();
                    write!(f, "{}", std::process::id()).unwrap();
                    INFO!("PID file created at {}", pidfile);
                }
                None => {}
            }
        }
        None => {}
    }
    serve(&config);
}
