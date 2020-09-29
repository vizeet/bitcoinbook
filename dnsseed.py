import dns.name
import dns.message
import dns.query
import dns.flags
import json

domain = 'seed.tbtc.petertodd.org'
name_server = '8.8.8.8'
ADDITIONAL_RDCLASS = 65535

domain = dns.name.from_text(domain)
if not domain.is_absolute():
    domain = domain.concatenate(dns.name.root)

request = dns.message.make_query(domain, dns.rdatatype.A, dns.rdataclass.IN)
request.flags |= dns.flags.RD|dns.flags.RA|dns.flags.AD
request.find_rrset(request.additional, dns.name.root, ADDITIONAL_RDCLASS,
                   dns.rdatatype.OPT, create=True, force_unique=True)
responseudp = dns.query.udp(request, name_server)


rrset = responseudp.answer

rrset_l = []
for rrset_val in rrset:
    rrset_l.extend(str(rrset_val).split("\n"))

for rrset_s in rrset_l:
    print(rrset_s.split(" ")[4])
