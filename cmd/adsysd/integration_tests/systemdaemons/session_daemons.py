# TiCS: disabled # session daemons mocks.

import os
import tempfile

import dbus
import dbus.service
import dbus.mainloop.glib
import dbusmock
import dbusmock.mockobject

from vfs_mocks import VfsMountTrackerMock

DBUS_SESSION_SOCKET_PATH = '/dbus/session_bus_socket'
# For testing purposes
# DBUS_SESSION_SOCKET_PATH = '/tmp/session_bus_socket'


def start_session_bus(conf_template: str) -> dbus.Bus:
    """Creates and starts a session bus

    Args:
        conf_template (str): Template to be used as the dbus config.

    Returns:
        dbus.Bus: Session bus created accordingly to the config provided.
    """

    conf = tempfile.NamedTemporaryFile(prefix='dbusmock_cfg')
    conf.write(conf_template.format('session', DBUS_SESSION_SOCKET_PATH).encode())

    conf.flush()

    (_, addr) = dbusmock.DBusTestCase.start_dbus(conf=conf.name)
    os.environ['DBUS_SESSION_BUS_ADDRESS'] = addr
    return dbusmock.DBusTestCase.get_dbus(system_bus=False)


def run_session_mocks(session_bus: dbus.Bus, mode: str):
    """Starts the session dbus mocks.

    Args:
        session_bus (dbus.Bus): Bus in which the mocks will run.
    """
    if mode == "gvfs_no_vfs_bus":
        return

    vfs_service = dbus.service.BusName('org.gtk.vfs.Daemon', session_bus, allow_replacement=True,
                                       replace_existing=True, do_not_queue=True)

    VfsMountTrackerMock(
        session_bus,
        mode,
        vfs_service,
        '/org/gtk/vfs/mounttracker',
        'org.gtk.vfs.MountTracker',
        {},
        '/tmp/mount_tracker_mock.log',
        True
    )
