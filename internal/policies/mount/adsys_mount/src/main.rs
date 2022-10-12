use anyhow::{Context, Result}; // Error context handling
use clap::Parser; // Parser for CLI arguments
use gio::{
    // Gio library for handling the mounts
    self,
    traits::{FileExt, MountOperationExt},
};
use log::{debug, error, warn}; // Macro to use when logging messages
use std::fs; // Module to handle filesystems
use thiserror::Error; // Error wrapper to minimize boilerplate error impls {Display and Error}

mod logger; // Includes our logger implementation from logger.rs file;
use logger::Logger; // Specifies that we are using the Logger struct from ther logger module;

/// Our own error type
///
/// It's not good practice to return errors that are not from your own API
/// (unless they are from the std library, i.e. io or fmt errors).
#[non_exhaustive] // Blocks match expressions without wildcards (_) for this enum.
#[derive(Debug, Error)]
enum AdsysMountError {}

/// Arguments required to run this binary
#[derive(Debug, clap::Parser)]
struct Args {
    /// Path for the file containing the mounts for the user.
    mounts_file: String,
}

/// Represents a mount point read from the mounts file
#[derive(Debug, PartialEq, Eq)]
struct MountEntry {
    mount_path: String,
    is_anonymous: bool,
}

fn main() {
    if let Ok(()) = log::set_logger(&Logger {}) {
        log::set_max_level(log::LevelFilter::Debug);
    }

    let args = Args::parse();

    debug!("Mounting entries listed in {}", args.mounts_file);

    let parsed_entries = match parse_entries(&args.mounts_file) {
        Ok(v) => v,
        Err(e) => {
            error!("{:?}", e);
            return;
        }
    };

    for entry in parsed_entries {
        match handle_mount(&entry) {
            Ok(_) => {}
            Err(e) => warn!("Not possible to mount {}: {}", entry.mount_path, e),
        }
    }

    let g_loop = glib::MainLoop::new(Some(&glib::MainContext::new()), false);
    g_loop.run();
}

/// Reads the file and parses the mount points listed in it.
fn parse_entries(path: &String) -> Result<Vec<MountEntry>> {
    debug!("Parsing file content");

    let mut parsed_entries: Vec<MountEntry> = Vec::new();

    let content =
        fs::read_to_string(path).with_context(|| format!("failed to open requested {}", path))?;

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

    Ok(parsed_entries)
}

/// Handles the mount operation to mount the specified entry.
fn handle_mount(entry: &MountEntry) -> Result<(), AdsysMountError> {
    debug!("Mounting entry {}", entry.mount_path);

    let f = gio::File::for_uri(&entry.mount_path);

    let mount_op = gio::MountOperation::new();
    if entry.is_anonymous {
        debug!("Anonymous mount requested");
        mount_op.set_anonymous(true);
    }

    debug!("Connecting passwd callback");
    mount_op.connect_ask_password(ask_password_callback);

    debug!("Mounting the volume");
    f.mount_enclosing_volume(
        gio::MountMountFlags::NONE,
        Some(&mount_op),
        gio::Cancellable::NONE,
        mount_handled_callback,
    );

    debug!("Leaving the function");
    Ok(())
}

/// Callback invoked by gio when mounting an entry.
fn ask_password_callback(
    mount_op: &gio::MountOperation,
    msg: &str,
    username: &str,
    password: &str,
    flags: gio::AskPasswordFlags,
) {
    debug!("Callback was called");
    println!(
        "{:#?}\n{:#?}\n{:#?}\n{:#?}\n{:#?}\n",
        mount_op, msg, username, password, flags
    );
    mount_op.reply(gio::MountOperationResult::Handled);
}

/// Callback invoked by gio when a mount process ends.
fn mount_handled_callback(res: Result<(), glib::Error>) {
    match res {
        Ok(_) => debug!("Mount successful"),
        Err(e) => debug!("Failed when handling mount: {}", e),
    }
}
