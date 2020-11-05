# adsys
Active Directory bridging toolset

## Usage

### User commands

#### adsysctl

AD integration client

##### Synopsis

Active Directory integration bridging toolset command line tool.

```
adsysctl COMMAND [flags]
```

##### Options

```
  -h, --help            help for adsysctl
  -s, --socket string   socket path to use between daemon and client. Can be overriden by systemd socket activation. (default "/tmp/socket.default")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

#### adsysctl completion

Generates bash completion scripts

##### Synopsis

To load completion run

. <(adsysctl completion)

To configure your bash shell to load completions for each session add to your ~/.bashrc or ~/.profile:

. <(adsysctl completion)


```
adsysctl completion [flags]
```

##### Options

```
  -h, --help   help for completion
```

##### Options inherited from parent commands

```
  -s, --socket string   socket path to use between daemon and client. Can be overriden by systemd socket activation. (default "/tmp/socket.default")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

#### adsysctl service

Service management

##### Synopsis

Service management

```
adsysctl service COMMAND [flags]
```

##### Options

```
  -h, --help   help for service
```

##### Options inherited from parent commands

```
  -s, --socket string   socket path to use between daemon and client. Can be overriden by systemd socket activation. (default "/tmp/socket.default")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

#### adsysctl version

Returns version of client and service

##### Synopsis

Returns version of client and service

```
adsysctl version [flags]
```

##### Options

```
  -h, --help   help for version
```

##### Options inherited from parent commands

```
  -s, --socket string   socket path to use between daemon and client. Can be overriden by systemd socket activation. (default "/tmp/socket.default")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

#### adsysd

AD integration daemon

##### Synopsis

Active Directory integration bridging toolset daemon.

```
adsysd COMMAND [flags]
```

##### Options

```
  -h, --help            help for adsysd
  -s, --socket string   socket path to use between daemon and client. Can be overriden by systemd socket activation. (default "/tmp/socket.default")
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

#### adsysd completion

Generates bash completion scripts

##### Synopsis

To load completion run

. <(adsysd completion)

To configure your bash shell to load completions for each session add to your ~/.bashrc or ~/.profile:

. <(adsysd completion)


```
adsysd completion [flags]
```

##### Options

```
  -h, --help   help for completion
```

##### Options inherited from parent commands

```
  -s, --socket string   socket path to use between daemon and client. Can be overriden by systemd socket activation. (default "/tmp/socket.default")
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

#### adsysd version

Returns version of service and exits

##### Synopsis

Returns version of service and exits

```
adsysd version [flags]
```

##### Options

```
  -h, --help   help for version
```

##### Options inherited from parent commands

```
  -s, --socket string   socket path to use between daemon and client. Can be overriden by systemd socket activation. (default "/tmp/socket.default")
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### System commands

Those commands are hidden from help and should primarily be used by the system itself.

