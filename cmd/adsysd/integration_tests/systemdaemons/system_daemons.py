"""
This script is used to mock the systemd daemon and several system services used by adsysd
"""

from argparse import Namespace
import os
import sys
from subprocess import Popen
import tempfile

import dbus
import dbus.mainloop.glib
import dbusmock
from dbusmock.templates import systemd

from gi.repository import GLib

DBUS_SYSTEM_SOCKET_PATH = "/dbus/system_bus_socket"
# For testing purpose
# DBUS_SYSTEM_SOCKET_PATH = "/tmp/system_bus_socket"


def start_system_bus() -> dbus.Bus:
    """ starts system bus and returned the new bus """

    conf = tempfile.NamedTemporaryFile(prefix='dbusmock_cfg')
    conf.write('''<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>system</type>
  <keep_umask/>
  <listen>unix:path={}</listen>

  <policy context="default">
    <allow user="*"/>
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>

</busconfig>
'''.format(DBUS_SYSTEM_SOCKET_PATH).encode())

    conf.flush()

    (_, addr) = dbusmock.DBusTestCase.start_dbus(conf=conf.name)
    os.environ['DBUS_SYSTEM_BUS_ADDRESS'] = addr
    return dbusmock.DBusTestCase.get_dbus(True)


def run_system_mocks(bus: dbus.Bus, mode: str) -> None:
    systemd_on_bus(bus, mode)
    sssd_on_bus(bus)
    ubuntu_advantage_on_bus(bus, mode)


def systemd_on_bus(bus: dbus.Bus, mode: str) -> None:
    """ Installs systemd mock on dbus and sets up the adsys scripts and refresh timer services """
    service = dbus.service.BusName(systemd.BUS_NAME,
                                   bus,
                                   allow_replacement=False,
                                   replace_existing=False,
                                   do_not_queue=True)
    main_object = dbusmock.mockobject.DBusMockObject(service, systemd.PATH_PREFIX,
                                                     systemd.MAIN_IFACE, {},
                                                     "/tmp/systemd-mock.log",
                                                     False)
    main_object.AddTemplate("systemd", "")

    # startup time and adsys timer
    startup_time = dbus.UInt64(1621860927000000)
    next_refresh_time = dbus.UInt64(86400000000)
    if mode == "no_startup_time":
        startup_time = ""
    elif mode == "invalid_startup_time":
        startup_time = dbus.String("invalid")
    elif mode == "no_nextrefresh_time":
        next_refresh_time = ""
    elif mode == "invalid_nextrefresh_time":
        next_refresh_time = dbus.String("invalid")

    main_object.AddProperty(
        systemd.MAIN_IFACE, "GeneratorsStartTimestamp", startup_time)

    main_object.AddObject(
        "/org/freedesktop/systemd1/unit/adsys_2dgpo_2drefresh_2etimer",
        "org.freedesktop.systemd1.Timer",
        {
            "NextElapseUSecMonotonic": next_refresh_time,
        },
        [])

    # our script unit
    main_object.AddMockUnit("adsys-machine-scripts.service")


def sssd_on_bus(bus: dbus.Bus) -> None:
    """ Installs sssd mock on the bus """
    service = dbus.service.BusName(
        "org.freedesktop.sssd.infopipe",
        bus,
        allow_replacement=True,
        replace_existing=True,
        do_not_queue=True)

    # Create sssd domain, with online and active server status
    main_object = dbusmock.mockobject.DBusMockObject(
        service, "/org/freedesktop/sssd/infopipe/Domains/example_2ecom",
        "org.freedesktop.sssd.infopipe.Domains.Domain", {},
        "/tmp/sssd-mock.log",
        False)
    main_object.AddMethods("", [
        ("IsOnline", "", "b", "ret = True"),
        ("ActiveServer", "s", "s", 'ret = "adc.example.com"'),
    ])

    main_object.AddObject(
        "/org/freedesktop/sssd/infopipe/Domains/offline",
        "org.freedesktop.sssd.infopipe.Domains.Domain",
        {},
        [
            ("IsOnline", "", "b", "ret = False"),
            ("ActiveServer", "s", "s", 'ret = ""'),
        ])

    main_object.AddObject(
        "/org/freedesktop/sssd/infopipe/Domains/online_no_active_server",
        "org.freedesktop.sssd.infopipe.Domains.Domain",
        {},
        [
            ("IsOnline", "", "b", "ret = True"),
            ("ActiveServer", "s", "s", 'ret = ""'),
        ])


def ubuntu_advantage_on_bus(bus: dbus.bus, mode: str) -> None:
    """ Installs ubuntu_advantage mock on the bus """

    # Ubuntu Advantage subscription state
    subscription_state = dbus.Boolean(True)
    if mode == "subscription_disabled":
        subscription_state = dbus.Boolean(False)

    service = dbus.service.BusName(
        "com.canonical.UbuntuAdvantage",
        bus,
        allow_replacement=True,
        replace_existing=True,
        do_not_queue=True)

    dbusmock.mockobject.DBusMockObject(
        service, "/com/canonical/UbuntuAdvantage/Manager",
        "com.canonical.UbuntuAdvantage.Manager",
        {"Attached": subscription_state},
        "/tmp/ubuntu-advantage-mock.log",
        False)
