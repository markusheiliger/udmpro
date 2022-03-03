# Sync Aliases

The script uses the name you could give each device in Unifi's management UI as a source for aliases / cnames. Means; for every name (comma separated) you put into the name field of the device the script will create a cname record pointing to the device's hostname.

The generated cname records are stored in file called aliases.confg that is uploaded to the UDMPRO directory /run/dnsmasq.conf.d where it will be processed by the dnsmarq daemon. Unfortunately this requires the dnsmasq deamon to be restarted.

## Examples

Assuming the client devices belong to a network with the domain name 'domain.com'.

| Hostname | Name (alias)    | CName 
| -------- | --------------- | ----- 
| pc01     | foo             | foo.domain.com -> pc01 
| pc01     | foo, bar        | foo.domain.com -> pc01 / bar.domain.com -> pc01
| pc01     | foo (bar, test) | foo.domain.com -> pc01 / bar.domain.com -> pc01 / test.domain.com -> pc01

## Limitations

* The script has to be executed manually (after you changed a device name) or using a cron job. If you go with the latter; keep in mind that the script enforces a restart of the dnsmasq daemon. Even if this restart happens super fast, the dns forwarder service won't be available at that time.


