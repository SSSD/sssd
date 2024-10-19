
"""
:TODO:
SSSDTestFramework
host...backup dns server
host...restore dns server 
client...backup ethernet interfaces ? 
client...restore ethernet interfaces ?


# Class to manage, create interfaces
NIC(BaseObject[BaseHost, role])
  self.name: str
  self.ip: list[str]
  self.gw: str
  self.netmask: str
  self.nameservers: list[str]


  client.nic.create
  client.nic.delete
  client.nic.get() -> list[str]
  client.nic.modify


# class to manage AD/Samba/IPA DNS servers
DNS(BaseObject[ADHost, AD])
  __init__(self, role, name)
  self.name: str 
  if x.x.x.x append in-addr.arpa to name


  role.ad.dns.create(self) # create zone -> None
  role.ad.dns.delete(self) # delete zone -> None
  role.ad.dns.add(record: dict[type: str, name: str]) - None 
  role.ad.dns.remove(record: list[str]) -> None
  role.ad.dns.get(record: str) -> tuple(bool, bool) # A, AAAA
  role.ad.dns.check(record: str) -> bool # for assertions
  role.ad.dns.print(zone: str) -> SSHProcess
  role.ad.dns.forwarders(disable: bool | None = False, nameservers: list[str] | None)  
# in our existing tests we had to disable forwarders in AD otherwise the internal rh corp ptr record would resolve
  role.ad.dns.zone(name: str | None = domain, secure_updates: bool | None = True)
"""

def test_dns__dynamic_updates_using_default_configuration():
    """
    :title: Dynamic DNS updates A/AAAA/PTR records on all interfaces
    :description: By default, SSSD will create and update its A/AAAA/PTR records of the joined domain
    :setup:
       1. Create PTR zone
       2. Start SSSD
    :steps:
       1. Check forward zone for client’s A record
       2. Check forward zone for client’s AAAA record
       3. Check reverse zone for client’s pointer record
    :expectedresults:
       1. Client A record exists in the zone file
       2. Client AAAA record exists in the zone file
       3. Client PTR record exists
    :customerscenario: True
    """


def test_dns__dynamic_update_creates_forward_ipv4_records():
   """
   :title: Dynamic DNS updates IPV4 address only
   :description: SSSD should create records for network addresses that are on the client
   :setup:
      1. Remove IPV6 address from ethernet interface
      2. Create PTR zone for default network
      3. Start SSSD
   :steps:
      1. Check forward zone for client’s A record
   :expectedresults:
      1. Client A record exists and is the only client record in the zone file
   :customerscenario: True
   """


def test_dns__dynamic_updates_all_forward_records():
   """
   :title: Dynamic DNS updates AAAA records on all interfaces
   :description: SSSD should update all records if the IP changes
   :setup:
      1. Create PTR zone
      2.  A/AAAA/PTR records that DO NOT match the client’s IP Address
      3. Start SSSD
   :steps:
      1. Check forward zone for client’s A record
      2. Check forward zone for client’s AAAA record
      3. Check reverse zone for client’s pointer record
   :expectedresults:
      1. Client A record exists in the zone file
      2. Client AAAA record exists in the zone file
      3. Client PTR record exists and points to the latest IP
   :customerscenario: True
   """


def test_dns__dynamic_update_is_disabled():
   """
   :title: Dynamic DNS is disabled
   :description: SSSD will not create any records on the DNS server
   :setup:
      1. Create PTR zone
      2. Set dyndns_update_ptr = false and dyndns_update = false in sssd.conf
      3. Start SSSD
   :steps:
      1. Check forward zone for client’s A record
      2. Check reverse zone for client’s PTR record
   :expectedresults:
      1. Client A record does not exist
      2. Client PTR record does not exist
   :customerscenario: True
   """


def test_dns__dynamic_update_updates_ttl_settings_when_configured():
   """
   :title: Dynamic DNS will set the configured TTL value with the forward records
   :description: SSSD can update the DNS records with a custom Time-To-Live value
   :setup:
      1. Create PTR zone
      2. Set dyndns_ttl = 9200
      3. Start SSSD
   :steps:
      1. Check forward zone for client’s forward record
   :expectedresults:
      1. Client forward exists with the TTL set to 9200
   :customerscenario: true
   """


def test_dns__dynamic_updates_multiple_interfaces():
   """
   :title: Dynamic DNS supports multiple interfaces
   :description: SSSD will update all available interfaces
   :setup:
      1. Create PTR zone
      2. Create bogus network interface on client
      3. Create PTR zone for bogus network matching bogus client interface
      4. Start SSSD
   :steps:
      1. Check forward zone for client’s forward record
      2. Check reverse zone for client’s pointer record
      3. Check reverse zone for client’s bogus interface pointer record
   :expectedresults:
      1. Client forward exists
      2. Client pointer record exist in zone file
      3. Client bogus pointer record exists in bogus network zone file
   :customerscenario: true
   """


def test_dns__dynamic_updates_specific_interface():
   """
   :title: Dynamic DNS update specific interface
   :description: SSSD will update the DNS with the configured interface
   :setup:
      1. Create PTR zone
      2. Create bogus network interface on client
      3. Create PTR zone for bogus network matching bogus client interface
      4. Configure sssd with ‘dyndns_iface = bogus interface’
      5. Start SSSD
   :steps:
      1. Check forward zone for client’s forward record
      2. Check reverse zone for client’s pointer record
      3. Check reverse zone for client’s bogus interface pointer record
   :expectedresults:
      1. Client forward exists
      2. Client pointer record does not exist in primary network zone file
      3. Client bogus pointer record exists in bogus network zone file
   :customerscenario: true
"""


def test_dns__dynamic_updates_at_configured_interval():
   """
   :title: Dynamic DNS updates at configured interval
   :description: SSSD will update the DNS server at the configured timed interval
   :setup:
      1. Create PTR zone
      2. Configure sssd with ‘dyndns_refresh_interval = X’
      3. Start SSSD
   :steps:
      1. Check forward zone for client’s forward record
      2. Delete A record
      3. Check forward zone for client’s A record
      4. Wait X seconds and check for client’s A record
   :expectedresults:
      1. Client A record exists
      2. A record is deleted
      3. Client A record does not exist
      4. Client’s A record exists
   :customerscenario: true
   """


def test_dns__dynamic_updates_works_over_tcp_only():
   """
   :title: Dynamic DNS updates works with TCP only
   :description: SSSD will update the DNS server using TCP only, instead requiring UDP as well
   :setup:
      1. Create PTR zone
      2. Configure SSSD with ldap_purge_cache_timeout = 0, krb5_auth_timeout = 12, dyndns_force_tcp = true
      3. Block all UDP traffic from client
      4. Start SSSD
   :steps:
      1. Check forward zone for client’s forward record
      2. Check reverse zone for client’s pointer record
   :expectedresults:
      1. Client A record exists
      2. Client PTR record exists
   :customerscenario: true
   """


def test_dns__dynamic_updates_works_using_insecure_nsupdate():
   """
   :title: Dynamic DNS updates using nsupdate instead of gss-tsig
   :description: SSSD can update DNS using insecure nsupdate
   :setup:
      1. Create PTR zone
      2. Disable secure updates for forward and reverse zones
      3. Configure sssd with dyndns_auth = None
      4. Start SSSD
   :steps:
      1. Check forward zone for client’s forward record
      2. Check reverse zone for client’s pointer record
   :expectedresults:
      1. Client A record exists
      2. Client PTR record exists
   :customerscenario: true
   """


def test_dns__dynamic_secure_updates_works_using_tsig():
   """
   :title: Dynamic DNS updates using gss-tsig only
   :description: SSSD can update DNS using tsig
   :setup:
      1. Create PTR zone
      2. Disable secure updates for forward and reverse zones
      3. Configure sssd zone allowing tsig updates only
      4. Start SSSD
   :steps:
      1. Check forward zone for client’s forward record
      2. Check reverse zone for client’s pointer record
   :expectedresults:
      1. Client A record exists
      2. Client PTR record exists
   :customerscenario: true
   """


def test_dns__dynamic_insecure_updates_do_not_work_using_tsig():
   """
   :title: Insecure dynamic DNS updates do not work using gss-tsig
   :description: SSSD cannot update DNS using nsupdate when the server only expects tsig
   :setup:
      1. Create PTR zone
      2. Disable secure updates for forward and reverse zones
      3. Configure sssd zone allowing tsig updates only
      4. Start SSSD
   :steps:
      1. Check forward zone for client’s forward record
      2. Check reverse zone for client’s pointer record
   :expectedresults:
      1. Client records do not exist
      2. Client records do not exist
   :customerscenario: true
   """


def test_dns__dynamic_updates_an_external_dns_server_with_a_non_integrated_zone_file():
   """
   :TODO: Not supported ATM
   :title: Dynamic DNS updates an external DNS server
   :description: SSSD updates a third-party DNS server with a non-integrated zone file

   A lot of customers use a third-party DNS like infoblox. I’m not that familiar with the product to determine,
   if we setup a test to update bind/dnsmasq or even IPA, just not the realm DNS server

   :setup:
   :steps:
   :expectedresults:
   :customerscenario: true
   """