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

/// Represents a mount point parsed from the mounts file.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Entry {
    path: String,
    is_anonymous: bool,
}

/// Struct representing the message that is to be passed in the glib channel.
pub struct Msg {
    path: String,
    status: MountResult,
}

/// Represents the result of a mount operation.
type MountResult = Result<(), glib::Error>;

/// Struct representing an error returned from trying to mount a path.
struct MountError {
    path: String,
    error: glib::Error,
}

/// Mount the entries that are specified in the file.
pub fn mount(mounts_file: &str) -> Result<(), AdsysMountError> {
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
        mount_entry(entry, tx.clone());
    }

    // Sets the main loop glib to be used by the mounts
    let g_loop = glib::MainLoop::new(Some(&g_ctx), false);

    // Creates a mutex to handle the exit status
    let errors = Arc::new(Mutex::new(Vec::new()));

    // Attaches the receiver to the main context, along with a closure that is called everytime there is a new message in the channel.
    {
        let errors = errors.clone();
        let g_loop = g_loop.clone();
        rx.attach(Some(&g_ctx), move |msg| {
            msg_handler(msg, &errors, &g_loop, &mut mounts_left)
        });
    }

    g_loop.run();

    // Evaluates the arc content to check if at least one operation failed.
    let errors = errors.lock().unwrap();
    for MountError { path, error } in errors.iter() {
        warn!("Mount process for {} failed: {}", path, error);
    }

    let error = errors
        .iter()
        .any(|MountError { error, .. }| !error.matches(gio::IOErrorEnum::AlreadyMounted));

    if error {
        return Err(AdsysMountError::MountError);
    }

    Ok(())
}

fn msg_handler(
    msg: Msg,
    errors: &Mutex<Vec<MountError>>,
    main_loop: &glib::MainLoop,
    mounts_left: &mut usize,
) -> glib::Continue {
    let Msg { path, status } = msg;
    match status {
        Err(error) => {
            warn!("Failed when mounting {}", path);
            errors.lock().unwrap().push(MountError { path, error });
        }
        Ok(_) => debug!("Mounting of {} was successful", path),
    };
    *mounts_left -= 1;

    // Ends the main loop if there are no more mounts left.
    if *mounts_left == 0 {
        main_loop.quit();
    }
    glib::Continue(*mounts_left != 0)
}

/// Reads the file and parses the mount points listed in it.
fn parse_entries(path: &str) -> Result<Vec<Entry>, std::io::Error> {
    debug!("Parsing file {} content", path);

    let mut parsed_entries: Vec<Entry> = Vec::new();

    let content = fs::read_to_string(path)?;
    for line in content.lines() {
        if line.is_empty() {
            continue;
        }

        parsed_entries.push(match line.strip_prefix("[anonymous]") {
            Some(s) => Entry {
                path: s.to_string(),
                is_anonymous: true,
            },
            None => Entry {
                path: line.to_string(),
                is_anonymous: false,
            },
        });
    }

    Ok(parsed_entries)
}

/// Handles the mount operation to mount the specified entry.
fn mount_entry(entry: Entry, tx: glib::Sender<Msg>) {
    debug!("Mounting entry {}", entry.path);

    let f = gio::File::for_uri(&entry.path);

    let mount_op = gio::MountOperation::new();

    if entry.is_anonymous {
        debug!("Anonymous mount requested for {}", entry.path);
        mount_op.set_anonymous(true);
    }

    mount_op.connect_ask_password(ask_password_cb);

    // Callback invoked by gio after setting up the mount.
    let mount_handled_cb = move |r: Result<(), glib::Error>| {
        let msg = Msg {
            path: entry.path,
            status: r,
        };

        if let Err(e) = tx.send(msg) {
            error!("Failed to send message in the channel: {}", e);
        }
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
            if let Some(data) = mount_op.data::<bool>("state") {
                // Ensures that we only try anonymous access once.
                if *(data.as_ref()) {
                    warn!("Anonymous access denied.");
                    mount_op.reply(gio::MountOperationResult::Aborted);
                }
            } else {
                debug!("Anonymous is supported by the provider.");
                mount_op.set_data("state", true);
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

mod unit_tests;
