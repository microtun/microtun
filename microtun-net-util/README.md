# microtun-net-util

`microtun-net-util` contains networking helpers shared by microtun host tools and
embedded targets.

The default `std` feature provides provisioning-mode mDNS/DNS-SD discovery and
responder support. Embedded users can disable default features and enable
`embassy-net` for the Embassy mDNS implementation. The `ping` feature provides
an Embassy-net ICMP ping runner that writes to `embedded_io_async::Write`.
