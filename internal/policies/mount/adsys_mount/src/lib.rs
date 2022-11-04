use gio::{
    self,
    traits::{FileExt, MountOperationExt},
};
use glib::ObjectExt;
use log::{debug, error, warn};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    sync::{Arc, Mutex},
};

mod errors;
pub use errors::AdsysMountError;

/// Represents a mount point read from the mounts file.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct MountEntry {
    mount_path: String,
    is_anonymous: bool,
}

/// Struct representing the message that is to be passed in the glib channel.
pub struct Msg {
    path: String,
    status: MountStatus,
}

/// Represents the status returned by a mount attempt.
#[derive(Debug)]
#[non_exhaustive]
pub enum MountStatus {
    Done,
    Asked,
    Error(glib::Error),
}

pub fn handle_user_mounts(mounts_file: &str) -> Result<(), AdsysMountError> {
    debug!("Mounting entries listed in {}", mounts_file);

    let parsed_entries = match parse_entries(mounts_file) {
        Ok(v) => v,
        Err(e) => {
            error!("Error when parsing entries: {}", e);
            return Err(AdsysMountError::ParseError);
        }
    };

    // Setting up the channel used for communication between the mount operations and the main function.
    let g_ctx = glib::MainContext::default();
    let (tx, rx) = glib::MainContext::channel(glib::PRIORITY_DEFAULT);

    // Grabs the ammount of mounts to be done before passing the ownership of parsed_entries.
    let mut mounts_left = parsed_entries.len();
    if mounts_left < 1 {
        return Ok(());
    }

    for entry in parsed_entries {
        handle_mount(entry, tx.clone());
    }

    // Sets the main loop glib to be used by the mounts
    let g_loop = glib::MainLoop::new(Some(&g_ctx), false);

    // Creates a mutex to handle the exit status
    let mu: Arc<Mutex<Vec<Msg>>> = Arc::new(Mutex::new(Vec::new()));

    // Clones the variables that are going to be moved into the closure.
    let g_loop_clone = g_loop.clone();
    let mu_clone = Arc::clone(&mu);

    // Attaches the receiver to the main context, along with a closure that is called everytime there is a new message in the channel.
    rx.attach(Some(&g_ctx), move |x| {
        match x.status {
            MountStatus::Done => debug!("Mounting of {} was successful", x.path),
            MountStatus::Error(_) => {
                warn!("Failed when mounting {}", x.path);
                mu_clone.lock().unwrap().push(x);
            }
            _ => error!("Unexpected return status: {:?}", x.status),
        };
        mounts_left -= 1;
        glib::Continue(match mounts_left {
            0 => {
                // Ends the main loop if there are no more mounts left.
                g_loop_clone.quit();
                false
            }
            _ => true,
        })
    });

    g_loop.run();

    // Evaluates the arc content to check if at least one operation failed.
    let errors = mu.lock().unwrap();
    if errors.len() == 0 {
        return Ok(());
    }

    let mut had_error = false;
    for err in errors.iter() {
        if let MountStatus::Error(e) = &err.status {
            warn!("Mount process for {} failed: {}", err.path, e);

            // Ensures that the function will not error out if the location was already mounted.
            if !e.matches(gio::IOErrorEnum::AlreadyMounted) {
                had_error = true;
            }
        }
    }

    if had_error {
        return Err(AdsysMountError::MountError);
    }
    Ok(())
}

/// Reads the file and parses the mount points listed in it.
fn parse_entries(path: &str) -> Result<Vec<MountEntry>, std::io::Error> {
    debug!("Parsing file {} content", path);

    let mut parsed_entries: Vec<MountEntry> = Vec::new();

    // The ? operator tries to unwrap the result and, if there is an error, returns it to the caller of this function.
    let content = fs::read_to_string(path)?;

    for p in content.lines() {
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
fn handle_mount(entry: MountEntry, tx: glib::Sender<Msg>) {
    debug!("Mounting entry {}", entry.mount_path);

    let f = gio::File::for_uri(&entry.mount_path);

    let mount_op = gio::MountOperation::new();

    if entry.is_anonymous {
        debug!("Anonymous mount requested for {}", entry.mount_path);
        mount_op.set_anonymous(true);
    }

    mount_op.connect_ask_password(ask_password_cb);

    // Callback invoked by gio after setting up the mount.
    let mount_handled_cb = move |r: Result<(), glib::Error>| {
        let msg = match r {
            Ok(_) => Msg {
                path: entry.mount_path,
                status: MountStatus::Done,
            },
            Err(e) => Msg {
                path: entry.mount_path,
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
        mount_handled_cb,
    );
}

/// Callback that is invoked by gio when prompted for password.
fn ask_password_cb(
    mount_op: &gio::MountOperation,
    _: &str,
    _: &str,
    _: &str,
    flags: gio::AskPasswordFlags,
) {
    if mount_op.is_anonymous() && flags.contains(gio::AskPasswordFlags::ANONYMOUS_SUPPORTED) {
        // Unsafe block is needed for data and set_data implementations in glib.
        unsafe {
            if let Some(data) = mount_op.data("state") {
                // Ensures that we only try anonymous access once.
                if let MountStatus::Asked = *(data.as_ptr()) {
                    warn!("Anonymous access denied.");
                    mount_op.reply(gio::MountOperationResult::Aborted);
                }
            } else {
                debug!("Anonymous is supported by the provider.");
                mount_op.set_data("state", MountStatus::Asked);
                mount_op.reply(gio::MountOperationResult::Handled);
            }
        }
        return;
    }

    // Checks if the machine has a kerberos ticket defined.
    if std::env::var("KRB5CCNAME").is_ok() {
        debug!("Kerberos ticket found on the machine.");
        mount_op.reply(gio::MountOperationResult::Handled);
        return;
    }

    warn!("Kerberos ticket not available on the machine.");
    mount_op.reply(gio::MountOperationResult::Aborted);
}

mod test;
mod test_utils;
