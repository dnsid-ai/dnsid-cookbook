"""DNSid-gated SPIFFE federation (DNSid cookbook recipe 16).

controller  — Acme side: decides whether Acme's SPIRE may hold Rackloria's federation bundle, based on
              Rackloria's DNSid identity, a DNSid-signed binding statement and fresh C2SP evidence.
publisher   — Rackloria side: signs and serves the binding statement for its current CA authorities.

Layers kept distinct: [DNSid] organizational trust (this package) / [SPIFFE] workload authentication
(SPIRE + mTLS) / [AuthZ] workload authorization (each application's allow-list).
"""

BINDING_TYPE = "dnsid-spiffe-federation+v0"
