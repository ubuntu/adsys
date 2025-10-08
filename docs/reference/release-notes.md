(ref::release-notes)=
# Release notes for ADSys

This page includes release notes for recent version of ADSys.

(ref::upgrade-instructions)=
## Upgrade instructions for ADSys

Ensure that you are using up-to-date packages:

```{code-block} text
sudo apt update && sudo apt upgrade -y
```

To check your version of ADSys, run:

```{code-block} text
adsysctl version
```

## Highlights from recent releases

In this section, a major release is shown first, followed by its corresponding
point releases from most recent to least recent.

### ADSys 0.16.0

* Add support for Polkit \>= 124
* Make certificates auto enroll script run with debug enabled based on daemon verbosity
* Refresh policy definition files

#### Point releases for ADSys 0.16

##### **ADSys 0.16.3**

* Fix to vendored code for certificate auto-enrollment
* Fix to the GPO parser
* Add glossary to the documentation
* Refresh documentation homepage and landing page

##### **ADSys 0.16.2**

Fixes and improvements to certificate autoenrollment:

* Implement better log messages
* Fix LDAP queries on multiple domain environments
* Improve control over default behavior to get supported certificate templates

##### **ADSys 0.16.1**

* Add architecture diagrams to documentation

```{dropdown} Older ADSys releases (expand to view)

### ADSys 0.15

#### 0.15.0

* Fix DCONF policy manager removing the user database on empty policy
* Ignore casing in domain/ section of `sssd.conf`
* Fix parsing of slash usernames (e.g., domain\\user)
* Fix `errno` in get_ticket_path()
* Remove XML declaration from glib schemas

#### 0.15.1

No changes affecting user functionality.
```
