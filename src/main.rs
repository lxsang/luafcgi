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
use serde;
use toml;
use clap;
//use std::fs::File;
use std::io::Write;
use std::net::TcpListener;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixListener;
use std::panic;
use std::path::Path;
use std::os::fd::FromRawFd;
use std::thread;
use std::io::Read;
use luad::*;

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
        panic!("{}", format!("The LUA fastCGI daemon is terminated by system signal: {}", n));
    }
}



fn handle_request<T: Read + Write + AsRawFd >(stream: &mut T) {
    if let Err(error) = process_request(stream)
    {
        ERROR!("Unable to process request: {}", error);
    }
    INFO!("Request on socket {} is processed", stream.as_raw_fd());
}

/// Start the `fastCGI` server
///
/// # Arguments
///
/// * `socket_opt` - The socket string that the server listens on
fn serve(socket_opt: Option<&str>) {
    

    // bind to a socket if any
    if let Some(socket_name) = socket_opt {
        // test if the socket name is an unix domain socket
        if socket_name.starts_with("unix:")  {
            // e.g unix:/var/run/lighttpd/maint/efcgi.socket
            INFO!("Use unix domain socket: {}", socket_name);
            std::env::set_var("socket", socket_name);
            let listener = UnixListener::bind(socket_name.replace("unix:", "")).unwrap();
            on_exit(clean_up);
            for client in listener.incoming() {
                let mut stream = client.unwrap();
                let _= std::thread::spawn(move || {
                    handle_request(&mut stream);
                });
            }
        } else {
            // TCP socket eg. 127.0.0.1:9000
            INFO!("Use TCP socket: {}", socket_name);
            let listener = TcpListener::bind(socket_name).unwrap();
            for client in listener.incoming() {
                let mut stream = client.unwrap();
                let _= thread::spawn(move || {
                    handle_request(&mut stream);
                });
            }
        }
    } else {
        // if there is no socket configuration, assume that the stdio is already mapped
        // to a socket. This is usually done by by the parent process (e.g. webserver) that launches efcgi
        INFO!("No socket specified! use stdin as listenning socket");
        let stdin = std::io::stdin();
        let listener = unsafe{ UnixListener::from_raw_fd(stdin.as_raw_fd())};
        for client in listener.incoming() {
            let mut stream = client.unwrap();

            let _= thread::spawn(move || {
                handle_request(&mut stream);
            });
        }
    }
}

#[derive(serde::Deserialize, Debug)]
struct Config {
    socket: Option<String>,
    pidfile: Option<String>,
    user: Option<String>,
    group: Option<String>,
}



/// Main application entry
///
/// Run a `fastCGI` server
fn main() {
    let _log = LOG::init_log();

    let matches = clap::App::new(DAEMON_NAME)
        .author(APP_AUTHOR)
        .about("Lua general purpose socket handle daemon")
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

    match matches.value_of("file") {
        Some(path) => {
            INFO!("Configuration file: {}", path);
            let contents = std::fs::read_to_string(path).unwrap();
            let config: Config = toml::from_str(&contents).unwrap();

            // write pid file
            match config.pidfile {
                Some(pidfile) => {
                    let mut f = std::fs::File::create(&pidfile).unwrap();
                    write!(f, "{}", std::process::id()).unwrap();
                    INFO!("PID file created at {}", pidfile);
                },
                None => {}
            }
            // drop user privilege if only user and group available in
            // the configuration file, otherwise ignore
            privdrop(config.user.as_deref(), config.group.as_deref()).unwrap();
            serve(config.socket.as_deref());
        },
        None => {
            serve(None);
        }
    }
}
