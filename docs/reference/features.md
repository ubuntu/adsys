# Feature availability


All users of ADSys can join client machines to Active Directory and manage
desktop settings with dconf.

Some additional ADSys features require an {term}`Ubuntu Pro` subscription, which  is
free for up to five machines.

| Features                           | Standard           | Pro                | Documentation					    |
|------------------------------------|--------------------|--------------------|----------------------------------------------------|
| Join AD from Desktop installer     | {bdg-success}`Yes` | {bdg-success}`Yes` | {ref}`howto::join-installer`			    |
| Join AD from the command line      | {bdg-success}`Yes` | {bdg-success}`Yes` | {ref}`howto::join-manually`  			    |
| Manage desktop settings with dconf | {bdg-success}`Yes` | {bdg-success}`Yes` | {ref}`howto::use-gpo`        			    |
| Privileges management              | {bdg-danger}`No`   | {bdg-success}`Yes` | {ref}`exp::privileges`       			    |
| Script execution through ADSys     | {bdg-danger}`No`   | {bdg-success}`Yes` | [Scripts execution](/explanation/scripts)          |
| AppArmor profiles                  | {bdg-danger}`No`   | {bdg-success}`Yes` | {ref}`exp::apparmor`				    |
| Network shares                     | {bdg-danger}`No`   | {bdg-success}`Yes` | {ref}`exp::network-shares`   			    |
| Network proxy                      | {bdg-danger}`No`   | {bdg-success}`Yes` | {ref}`exp::network-proxy`    			    |
| Certificate auto-enrollment        | {bdg-danger}`No`   | {bdg-success}`Yes` | {ref}`howto::certificates`     			    |


```{tip}
An Ubuntu Pro subscription also offers security and support benefits for your
Ubuntu machines.

For more information, read this [overview of Ubuntu Pro](https://ubuntu.com/pro).
```

