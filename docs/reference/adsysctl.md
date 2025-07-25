# The adsysctl command

`adsysctl` is a command line utility to request actions from the daemon and query its current status. You can get more verbose output with the `-v` accumulative flags, which will stream all logs from the service corresponding to your specific request.

As a general rule, favor shell completion and the help command for discovering various parts of the adsysctl user interface. It will help you by completing subcommands, flags, users and pages of the offline documentation.

## Checking which policies are applied

To check which policies are currently applied to the current AD user, run `adsysctl policy applied`:

```{terminal}
   :input: adsysctl policy applied
   :dir: 
Policies from machine configuration:
- MainOffice Policy 2 ({B8D10A86-0B78-4899-91AF-6F0124ECEB48})
- MainOffice Policy ({C4F393CA-AD9A-4595-AEBC-3FA6EE484285})
- Default Domain Policy ({31B2F340-016D-11D2-945F-00C04FB984F9})

Policies from user configuration:
- RnD Policy 3 ({073AA7FC-5C1A-4A12-9AFC-42EC9C5CAF04})
- RnD Policy 2 ({83A5BD5B-1D5D-472D-827F-DE0E6F714300})
- RnD Policy ({5EC4DF8F-FF4E-41DE-846B-52AA6FFAF242})
- IT Policy ({75545F76-DEC2-4ADA-B7B8-D5209FD48727})
- Default Domain Policy ({31B2F340-016D-11D2-945F-00C04FB984F9})
```

```{note}
The order of policies is top-down, with higher GPOs having priority over lower ones on the stack (e.g., respecting OU order, GPO enforcement, GPO block instructions on your AD setup).
```

A `username` can be passed to request other users, if you have the right permissions:

```{terminal}
   :input: adsysctl policy applied tina
   :dir: 
Policies from machine configuration:
- MainOffice Policy ({A2F393CA-AD9A-4595-AEBC-3FA6EE484285})
- Default Domain Policy ({31B2F340-016D-11D2-945F-00C04FB984F9})

Policies from user configuration:
- RnD Policy 4 ({25A5BD5B-1D5D-472D-827F-DE0E6F714300})
- IT Policy ({75545F76-DEC2-4ADA-B7B8-D5209FD48727})
- Default Domain Policy ({31B2F340-016D-11D2-945F-00C04FB984F9})
```

```{tip}
Use shell completion to get the list of active users that you can request which policies are applied on.
```

The `--details` flag can be used to check which policies are set to a given value or disabled by which key:

```{terminal}
   :input: adsysctl policy applied --details
   :dir: 
Policies from machine configuration:
- MainOffice Policy 2 ({B8D10A86-0B78-4899-91AF-6F0124ECEB48})
    - gdm:
        - dconf/org/gnome/desktop/notifications/show-banners: Locked to system default
- MainOffice Policy ({C4F393CA-AD9A-4595-AEBC-3FA6EE484285})
    - gdm:
        - dconf/org/gnome/desktop/interface/clock-format: 24h
        - dconf/org/gnome/desktop/interface/clock-show-date: false
        - dconf/org/gnome/desktop/interface/clock-show-weekday: true
        - dconf/org/gnome/desktop/screensaver/picture-uri: 'file:///usr/share/backgrounds/ubuntu-default-greyscale-wallpaper.png'
- Default Domain Policy ({31B2F340-016D-11D2-945F-00C04FB984F9})

Policies from user configuration:
- RnD Policy 3 ({073AA7FC-5C1A-4A12-9AFC-42EC9C5CAF04})
    - dconf:
        - org/gnome/desktop/media-handling/automount: Locked to system default
- RnD Policy 2 ({83A5BD5B-1D5D-472D-827F-DE0E6F714300})
- RnD Policy ({5EC4DF8F-FF4E-41DE-846B-52AA6FFAF242})
    - dconf:
        - org/gnome/shell/favorite-apps: libreoffice-writer.desktop\nsnap-store_ubuntu-software.desktop\nyelp.desktop
- IT Policy ({75545F76-DEC2-4ADA-B7B8-D5209FD48727})
    - dconf:
        - org/gnome/desktop/background/picture-options: stretched
        - org/gnome/desktop/background/picture-uri: file:///usr/share/backgrounds/canonical.png
- Default Domain Policy ({31B2F340-016D-11D2-945F-00C04FB984F9})
```

The `--all` flag lists every key set by a given GPO, including the ones that are redefined by another GPO with a higher priority. This is can be helpful for debugging your GPO stack and discovering where a given value is defined:

```{terminal}
   :input: adsysctl policy applied --all
   :dir: 
Policies from machine configuration:
- MainOffice Policy 2 ({B8D10A86-0B78-4899-91AF-6F0124ECEB48})
    - gdm:
        - dconf/org/gnome/desktop/notifications/show-banners: Locked to system default
- MainOffice Policy ({C4F393CA-AD9A-4595-AEBC-3FA6EE484285})
    - gdm:
        - dconf/org/gnome/desktop/interface/clock-format: 24h
        - dconf/org/gnome/desktop/interface/clock-show-date: false
        - dconf/org/gnome/desktop/interface/clock-show-weekday: true
        - dconf/org/gnome/desktop/screensaver/picture-uri: 'file:///usr/share/backgrounds/ubuntu-default-greyscale-wallpaper.png'
- Default Domain Policy ({31B2F340-016D-11D2-945F-00C04FB984F9})

Policies from user configuration:
- RnD Policy 3 ({073AA7FC-5C1A-4A12-9AFC-42EC9C5CAF04})
    - dconf:
        - org/gnome/desktop/media-handling/automount: Locked to system default
- RnD Policy 2 ({83A5BD5B-1D5D-472D-827F-DE0E6F714300})
- RnD Policy ({5EC4DF8F-FF4E-41DE-846B-52AA6FFAF242})
    - dconf:
        - org/gnome/shell/favorite-apps: libreoffice-writer.desktop\nsnap-store_ubuntu-software.desktop\nyelp.desktop
- IT Policy ({75545F76-DEC2-4ADA-B7B8-D5209FD48727})
    - dconf:
        - org/gnome/desktop/background/picture-options: stretched
        - org/gnome/desktop/background/picture-uri: file:///usr/share/backgrounds/canonical.png
        - org/gnome/shell/favorite-apps: 'firefox.desktop'\n'thunderbird.desktop'\n'org.gnome.Nautilus.desktop'
- Default Domain Policy ({31B2F340-016D-11D2-945F-00C04FB984F9})
```

## Refreshing the policies

The command `adsysctl policy update` is used to refresh the policies. By default only the policy of the current user is updated. It can also refresh only the policy of the machine with the flag `-m`, or the machine and all the active users with the flag `-a`. On success nothing is displayed.

For example, refreshing the policy for all the objects:

```{terminal}
   :input: adsysctl policy update --all -v
   :dir: 
INFO No configuration file: Config File "adsys" Not Found in "[/home/warthogs.biz/b/bob /etc]".
We will only use the defaults, env variables or flags. 
INFO Apply policy for adclient04 (machine: true)  
INFO Apply policy for bob@warthogs.biz (machine: false) 
```

You can provide the name of a user and the path to its Kerberos ticket to refresh a given user.

For example for user `bob@warthogs.biz`

```{terminal}
   :input: adsysctl update bob@warthogs.biz /tmp/krb5cc_1899001102_wBlbck -vv
   :dir: 
INFO No configuration file: Config File "adsys" Not Found in "[/home/warthogs.biz/b/bob /etc]".
We will only use the defaults, env variables or flags. 
DEBUG Connecting as [[26812:519495]]               
DEBUG New request /service/UpdatePolicy            
DEBUG Requesting with parameters: IsComputer: false, All: false, Target: bob@warthogs.biz, Krb5Cc: /tmp/krb5cc_1899001102_wBlbck 
DEBUG Check if grpc request peer is authorized     
DEBUG Polkit call result, authorized: true         
DEBUG GetPolicies for "bob@warthogs.biz", type "user" 
DEBUG GPO "RnD Policy 3" for "bob@warthogs.biz" available at "smb://warthogs.biz/SysVol/warthogs.biz/Policies/{073AA7FC-5C1A-4A12-9AFC-42EC9C5CAF04}" 
DEBUG GPO "RnD Policy 2" for "bob@warthogs.biz" available at "smb://warthogs.biz/SysVol/warthogs.biz/Policies/{83A5BD5B-1D5D-472D-827F-DE0E6F714300}" 
DEBUG GPO "RnD Policy" for "bob@warthogs.biz" available at "smb://warthogs.biz/SysVol/warthogs.biz/Policies/{5EC4DF8F-FF4E-41DE-846B-52AA6FFAF242}" 
DEBUG GPO "IT Policy" for "bob@warthogs.biz" available at "smb://warthogs.biz/SysVol/warthogs.biz/Policies/{75545F76-DEC2-4ADA-B7B8-D5209FD48727}" 
DEBUG GPO "Default Domain Policy" for "bob@warthogs.biz" available at "smb://warthogs.biz/sysvol/warthogs.biz/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}" 
DEBUG Analyzing GPO "Default Domain Policy"        
DEBUG Analyzing GPO "IT Policy"                    
DEBUG Analyzing GPO "RnD Policy 2"                 
DEBUG Analyzing GPO "RnD Policy 3"                 
DEBUG Analyzing GPO "RnD Policy"                   
DEBUG Policy "RnD Policy 2" doesn't have any policy for class "user" open /var/cache/adsys/gpo_cache/{83A5BD5B-1D5D-472D-827F-DE0E6F714300}/User/Registry.pol: no such file or directory 
DEBUG Policy "Default Domain Policy" doesn't have any policy for class "user" open /var/cache/adsys/gpo_cache/{31B2F340-016D-11D2-945F-00C04FB984F9}/User/Registry.pol: no such file or directory 
INFO Apply policy for bob@warthogs.biz (machine: false) 
DEBUG ApplyPolicy dconf policy to bob@warthogs.biz 
DEBUG Update user profile /etc/dconf/profile/bob@warthogs.biz 
DEBUG Analyzing entry {Key:org/gnome/desktop/background/picture-options Value:stretched Disabled:false Meta:s} 
DEBUG Analyzing entry {Key:org/gnome/desktop/background/picture-uri Value:file:///usr/share/backgrounds/canonical.png Disabled:false Meta:s} 
DEBUG Analyzing entry {Key:org/gnome/desktop/media-handling/automount Value: Disabled:true Meta:} 
DEBUG Analyzing entry {Key:org/gnome/shell/favorite-apps Value:libreoffice-writer.desktop
snap-store_ubuntu-software.desktop
yelp.desktop
 Disabled:false Meta:as} 
```

## Getting the status of the service

The command `adsysctl service status` can be used to get the status:

```{terminal}
   :input: adsysctl service status
   :dir: 
Machine, updated on Tue May 18 12:15
Connected users:
  bob@warthogs.biz, updated on Tue May 18 12:15

Active Directory:
  Server: ldap://adc01.warthogs.biz
  Domain: warthogs.biz

SSS:
  Configuration: /etc/sssd/sssd.conf
  Cache directory: /var/lib/sss/db

Daemon:
  Timeout after 2m0s
  Listening on: /run/adsysd.sock
  Cache path: /var/cache/adsys
  Run path: /run/adsys
  Dconf path: /etc/dconf
```

The information includes connected users, when users last refreshed, when the next refresh is scheduled and various service configuration options (static or dynamically configured).

## Debugging

The `cat` command has already been described in [the adsys-daemon reference](adsys-daemon.md).

You can display logs with debugging levels independent of daemon and clients debugging levels. Local printing will also be forwarded.

For example, running `cat` while the command `version` and `applied` are executed:

```{terminal}
   :input: adsysctl service cat -vv
   :dir: 
INFO No configuration file: Config File "adsys" Not Found in "[/root /etc]".
We will only use the defaults, env variables or flags. 
DEBUG Connecting as [[29220:823925]]               
DEBUG New request /service/Cat                     
DEBUG Requesting with parameters:                  
DEBUG Check if grpc request peer is authorized     
DEBUG Authorized as being administrator            
INFO New connection from client [[29302:462445]]  
DEBUG [[29302:462445]] New request /service/Version 
DEBUG [[29302:462445]] Requesting with parameters:  
DEBUG [[29302:462445]] Check if grpc request peer is authorized 
DEBUG [[29302:462445]] Any user always authorized  
DEBUG Request /service/Version done                
INFO New connection from client [[29455:217212]]  
DEBUG [[29455:217212]] New request /service/DumpPolicies 
DEBUG [[29455:217212]] Requesting with parameters: Target: bob@warthogs.biz, Details: false, All: false 
DEBUG [[29455:217212]] Check if grpc request peer is authorized 
DEBUG [[29455:217212]] Polkit call result, authorized: true 
INFO [[29455:217212]] Dumping policies for bob@warthogs.biz 
DEBUG Request /service/DumpPolicies done 
```

## Other commands

### Versions

You can get the current service and client versions with the `version` command to check you are running with latest version on both sides:

```{terminal}
   :input: adsysctl version
   :dir: 
adsysctl        0.5
adsysd          0.5
```

### Documentation

An offline version of this documentation is available in the daemon. It will render the documentation on the command line.

You can get a list of all chapters with their titles:

```{terminal}
   :input: adsysctl doc
   :dir: 

   Table of content                                                           

  1. [Welcome] ADSys: Active Directory Group Policy integration               
  2. [Prerequisites] Prerequisites and installation                           
[…]
```

And render a given chapter by requesting it:

```{terminal}
   :input: adsysctl doc Welcome
   :dir: 
                                                                                                                                      
   ADSys: Active Directory Group Policy integration                                                                                   
                                                                                                                                      
  ADSys is the Active Directory Group Policy client for Ubuntu. It allows
[…]

```

Finally, there are different rendering modes for the documentation.

You can dump documentation in html --- for example --- with the `--format` flag.

### Admx generation

The `policy admx` command dumps pre-built Active Directory administrative templates that can be deployed on the Active Directory server.

For more information, check the [AD setup documentation](../how-to/set-up-ad.md)

### Stopping the service

If you do not wish to wait for the idling timeout to stop the server, you can request graceful shutdown with `adsysctl service stop`.

This will first wait for all active connections to ends before shutting down.

The `-force` flag ends the service immediately.
