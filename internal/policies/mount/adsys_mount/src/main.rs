use clap::Parser;
use gio::{
    self,
    traits::{FileExt, MountOperationExt},
};
use log::{debug, error, warn};
use std::{
    fs,
    sync::{Arc, Mutex},
};

mod logger; // Includes our logger implementation from the logger.rs file;
use logger::Logger;

mod error; // Includes our error implementation from the error.rs file;
use error::AdysMountError;

/// Arguments required to run this binary
#[derive(Debug, clap::Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path for the file containing the mounts for the user.
    mounts_file: String,
}

/// Represents a mount point read from the mounts file.
#[derive(Debug, PartialEq, Eq)]
struct MountEntry {
    mount_path: String,
    is_anonymous: bool,
}

/// Struct representing the message that is to be passed in the glib channel.
struct Msg {
    path: String,
    status: MountStatus,
}

/// Represents the status returned by a mount attempt.
#[derive(Debug)]
enum MountStatus {
    Done,
    Error(glib::Error),
}

fn main() -> Result<(), AdysMountError> {
    let args = Args::parse();

    if let Ok(()) = log::set_logger(&Logger {}) {
        log::set_max_level(log::LevelFilter::Debug);
    }

    debug!("Mounting entries listed in {}", args.mounts_file);

    let parsed_entries = match parse_entries(&args.mounts_file) {
        Ok(v) => v,
        Err(e) => {
            error!("Error when parsing entries: {}", e);
            return Err(AdysMountError::ParseError);
        }
    };

    // Setting up the channel used for communication between the mount operations and the main function.
    let g_ctx = glib::MainContext::default();
    let (tx, rx) = glib::MainContext::sync_channel(glib::PRIORITY_DEFAULT, parsed_entries.len());

    // Grabs the ammount of mounts to be done before passing the ownership of parsed_entries.
    let mut mounts_left = parsed_entries.len();

    for entry in parsed_entries {
        handle_mount(entry, tx.clone());
    }

    // Sets the main loop glib to be used by the mounts
    let g_loop = glib::MainLoop::new(Some(&g_ctx), false);

    // Creates a mutex to handle the exit status
    let mu: Arc<Mutex<Vec<Msg>>> = Arc::new(Mutex::new(Vec::new()));

    // Clones the variables that are going to be moved into the closure.
    let g_loop_clone = g_loop.clone();
    let mu_clone = mu.clone();

    // Attaches the receiver to the main context, along with a closure that is called everytime there is a new message in the channel.
    rx.attach(Some(&g_ctx), move |x| {
        match x.status {
            MountStatus::Done => debug!("Mounting of {} was successful", x.path),
            MountStatus::Error(_) => {
                warn!("Failed when mounting {}", x.path);
                mu_clone.lock().unwrap().push(x);
            }
        };
        mounts_left -= 1;
        glib::Continue(match mounts_left {
            0 => {
                g_loop_clone.quit();
                false
            }
            _ => true,
        })
    });

    g_loop.run();

    // Evaluates the arc content to check if at least one operation failed.
    if mu.lock().unwrap().len() != 0 {
        for err in mu.lock().unwrap().iter() {
            if let MountStatus::Error(e) = &err.status {
                warn!("Mount process for {} failed: {}", err.path, e)
            }
        }

        return Err(AdysMountError::MountError);
    }

    Ok(())
}

/// Reads the file and parses the mount points listed in it.
fn parse_entries(path: &String) -> Result<Vec<MountEntry>, std::io::Error> {
    debug!("Parsing file content");

    let mut parsed_entries: Vec<MountEntry> = Vec::new();

    // The ? operator tries to unwrap the result and, if there is an error, returns it to the caller of this function.
    let content = fs::read_to_string(path)?;

    for p in content.split_terminator('\n') {
        if p.is_empty() {
            continue;
        }

        parsed_entries.push(match p.strip_prefix("[anonymous]") {
            Some(s) => MountEntry {
                mount_path: s.to_string(),
                is_anonymous: true,
            },
            None => MountEntry {
                mount_path: p.to_string(),
                is_anonymous: false,
            },
        });
    }

    // The idiomatic way to return from a function in Rust is with tail expressions
    Ok(parsed_entries)
}

/// Handles the mount operation to mount the specified entry.
fn handle_mount(entry: MountEntry, tx: glib::SyncSender<Msg>) {
    debug!("Mounting entry {}", entry.mount_path);

    let f = gio::File::for_uri(&entry.mount_path);

    let mount_op = gio::MountOperation::new();
    if entry.is_anonymous {
        debug!("Anonymous mount requested");
        mount_op.set_anonymous(true);
    }

    mount_op.connect_ask_password(ask_password_callback);

    // Callback invoked by gio after setting up the mount.
    let callback = move |r: Result<(), glib::Error>| {
        let msg = match r {
            Ok(_) => Msg {
                path: entry.mount_path,
                status: MountStatus::Done,
            },
            Err(e) => Msg {
                path: entry.mount_path.clone(),
                status: MountStatus::Error(e),
            },
        };
        match tx.send(msg) {
            Ok(_) => {}
            Err(e) => error!("Failed to send message in the channel: {}", e),
        };
        drop(tx);
    };

    f.mount_enclosing_volume(
        gio::MountMountFlags::NONE,
        Some(&mount_op),
        gio::Cancellable::NONE,
        callback,
    );
}

/// Callback invoked by gio when mounting an entry.
fn ask_password_callback(
    mount_op: &gio::MountOperation,
    _: &str,
    _: &str,
    _: &str,
    flags: gio::AskPasswordFlags,
) {
    // Checks if anonymous mounts are supported by the provider.
    if !flags.contains(gio::AskPasswordFlags::ANONYMOUS_SUPPORTED) && mount_op.is_anonymous() {
        warn!("Anonymous mounts are not supported by the provider.");
        mount_op.reply(gio::MountOperationResult::Aborted);
        return;
    }

    // Checks if password authentication is required.
    if flags.contains(gio::AskPasswordFlags::NEED_PASSWORD) && !mount_op.is_anonymous() {
        warn!(
            "Password authentication is required by the provider, but is not supported by adsys."
        );
        mount_op.reply(gio::MountOperationResult::Aborted);
        return;
    }

    mount_op.reply(gio::MountOperationResult::Handled);
}

mod test;
