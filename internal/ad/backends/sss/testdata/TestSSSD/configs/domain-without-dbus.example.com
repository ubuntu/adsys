[sssd]
domains = domain-without-dbus.example

[domain/domain-without-dbus.example]
ad_domain = domain-without-dbus.example
