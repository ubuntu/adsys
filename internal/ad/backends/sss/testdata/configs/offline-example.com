[sssd]
domains = offline.example.com

[domain/offline.example.com]
ad_domain = offline.example.com
