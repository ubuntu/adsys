[sssd]
domains = example.com

[domain/EXAMPLE.COM]
ad_domain = example.com
