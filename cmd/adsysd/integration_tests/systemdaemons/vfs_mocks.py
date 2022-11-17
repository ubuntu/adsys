import dbus
import dbusmock


class VfsMountTrackerMock(dbusmock.DBusMockObject):

    def __init__(self, bus: dbus.Bus, bus_name: str, path: str, interface: str, props: dbusmock.mockobject.PropsType,
                 logfile: dbusmock.mockobject.Optional[str] = None, is_object_manager: bool = False) -> None:
        super().__init__(bus_name, path, interface, props, logfile, is_object_manager)
        self.bus = bus

    @dbus.service.method(dbus_interface='org.gtk.vfs.MountTracker', out_signature='a(ssasib)')
    def ListMountableInfo(self):
        # Add service not available case
        return [('smb-share', 'smb', [], 0, False), ('nfs', 'nfs', [], 0, False)]

    @dbus.service.method(dbus_interface='org.gtk.vfs.MountTracker', in_signature='(aya{say})(so)')
    def MountLocation(self,
                      mount_spec: tuple[list[bytes], dict[str, list[bytes]]],
                      mount_source: tuple[str, dbus.ObjectPath]):
        res = self.bus.call_blocking(
            mount_source[0],
            mount_source[1],
            'org.gtk.vfs.MountOperation',
            'AskPassword',
            'sssu',
            ('message', 'ubuntu', 'WORKGROUP', 31)
        )

        if res[1] == dbus.Boolean(True):
            raise (dbus.DBusException('Authentication failed'))

        protocol = ''.join([dbus.String(x) for x in mount_spec[1].get("type")]).replace('\0', '')
        server, share = self.get_spec_values(protocol, mount_spec)

        # Forces a failure if the protocol is not supported by adsys
        if server == '' and share == '':
            raise (dbus.DBusException('Unsupported protocol'))

        # Forces a failure if the server is marked as an errored one
        if 'error' in server:
            raise (dbus.DBusException('Error during mount process'))

        display_name = f'{share} on {server}'
        stable_name = f'{protocol}:{server},share={share}'
        mount_location = f'/run/user/1000/gvfs/{stable_name}'

        self.Mounted(
            mount_source[0],
            mount_source[1],
            display_name.encode(),
            stable_name.encode(),
            '',
            '. GThemedIcon folder-remote folder folder-remote-symbolic folder-symbolic',
            '. GThemedIcon folder-remote-symbolic folder-symbolic folder-remote folder',
            '',
            True,
            mount_location.encode(),
            mount_spec,
            b'/'
        )

    @dbus.service.signal(dbus_interface='org.gtk.vfs.MountTracker', signature='sossssssbay(aya{sv})ay')
    def Mounted(self, bus_name: str, obj_path: dbus.ObjectPath, display_name: str, stable_name: str,
                x_content_types: str, icon: str, symbolic_icon: str, prefered_filename_encoding: str,
                user_visible: bool, mount_location: list[bytes], mount_spec: tuple[list[bytes], dict[str, list[bytes]]],
                default_location: list[bytes]):
        return

    def get_spec_values(self, protocol: str, mount_spec: tuple[list[bytes], dict[str, list[bytes]]]) -> tuple[str, str]:
        server, share = '', ''

        if protocol == 'smb-share':
            server = ''.join([dbus.String(x) for x in mount_spec[1].get("server")])
            share = ''.join([dbus.String(x) for x in mount_spec[1].get("share")])

        elif protocol == 'nfs':
            server = ''.join([dbus.String(x) for x in mount_spec[1].get("host")])
            share = ''.join([dbus.String(x) for x in mount_spec[0]])

        # Removes the null characters from the string
        share = share.replace('\0', '')
        server = server.replace('\0', '')

        return server, share
