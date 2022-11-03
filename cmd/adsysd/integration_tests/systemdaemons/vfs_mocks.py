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
        _ = self.bus.call_blocking(
            mount_source[0],
            mount_source[1],
            'org.gtk.vfs.MountOperation',
            'AskPassword',
            'sssu',
            ('message', 'ubuntu', 'WORKGROUP', 31)
        )

        self.Mounted(
            mount_source[0],
            mount_source[1],
            'anon_share on localhost',  # Should be dynamic
            'smb-share:server=localhost,share=anon_share',  # Should be dynamic
            '',
            '. GThemedIcon folder-remote folder folder-remote-symbolic folder-symbolic',
            '. GThemedIcon folder-remote-symbolic folder-symbolic folder-remote folder',
            '',
            True,
            b'/run/user/1000/gvfs/smb-share:server=localhost,share=anon_share',  # Should be dynamic
            mount_spec,
            b'/'
        )

    @dbus.service.signal(dbus_interface='org.gtk.vfs.MountTracker', signature='sossssssbay(aya{sv})ay')
    def Mounted(self, bus_name: str, obj_path: dbus.ObjectPath, display_name: str, stable_name: str,
                x_content_types: str, icon: str, symbolic_icon: str, prefered_filename_encoding: str,
                user_visible: bool, mount_location: list[bytes], mount_spec: tuple[list[bytes], dict[str, list[bytes]]],
                default_location: list[bytes]):
        return
