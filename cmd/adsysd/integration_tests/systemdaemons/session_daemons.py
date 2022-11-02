"""
This script is used to mock the session bus and some of its objects that
are used by adsys.
"""
import os
import tempfile

import dbus
import dbus.service
import dbus.mainloop.glib
import dbusmock
import dbusmock.mockobject

from gi.repository import GLib

from vfs_mocks import VfsMountTrackerMock

DBUS_SESSION_SOCKET_PATH = '/dbus/session_bus_socket'
# For testing purposes
# DBUS_SESSION_SOCKET_PATH = '/tmp/session_bus_socket'


def start_session_bus() -> dbus.Bus:
    """ starts system bus and returned the new bus """

    conf = tempfile.NamedTemporaryFile(prefix='dbusmock_cfg')
    conf.write('''<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <keep_umask/>
  <listen>unix:path={}</listen>
  <policy context="default">
    <allow user="*"/>
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
'''.format(DBUS_SESSION_SOCKET_PATH).encode())

    conf.flush()

    (_, addr) = dbusmock.DBusTestCase.start_dbus(conf=conf.name)
    os.environ['DBUS_SESSION_BUS_ADDRESS'] = addr
    return dbusmock.DBusTestCase.get_dbus(system_bus=False)


def run_session_mocks(session_bus: dbus.Bus):
    vfs_service = dbus.service.BusName('org.gtk.vfs.Daemon', session_bus, allow_replacement=True,
                                       replace_existing=True, do_not_queue=True)

    VfsMountTrackerMock(
        session_bus,
        vfs_service,
        '/org/gtk/vfs/mounttracker',
        'org.gtk.vfs.MountTracker',
        {},
        '/tmp/mount_tracker_mock.log',
        True
    )
