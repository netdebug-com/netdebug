# Reminders

CTR+SHIFT+V to preview markdown in VSCODE!

# Features

* figure out BSD-compat endhost probing
* add RR and find place to run it from - can ping IPs found to fake latency info for non-ttl exceeded sourcing routers
* track user-agent on request
* Look at cellphone sourced traffic
    * no NAT, weak end-host probe replies - no SACK!?
* Track drop packets and expose to GUI
* Pretty up the probe report into nested tables
* Add DNS lookups for ProbeReports
* build a "CLI Client" for testing and general usefulness
* multiple-parallel ws connections
* HTTPS! to try to improve performance:now() time
  * blocks Geolocation

# Coverage
* By OS: Linux, MacOS, Windows, IOS, Android
* By network: cell, home wifi, vpn, direct

# Nagging
* need to do more IPv6 testing!  Just had a regression vs. localhost traffic with IPv6
* Add ARIA/Accessiblilty features to the GUI, ala https://www.chartjs.org/docs/latest/general/accessibility.html
* Re-test app with Oracle cloud to see if new packets get past the connection tracking damage
* Calculate explicit per-hop processing time delays to deconfuse data
* Lots of polish on the GUI

# Minor:
* too many to count
* test with Azure