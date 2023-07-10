# Reminders

CTR+SHIFT+V to preview markdown in VSCODE!

# Features

* serialize a probe report to disk and use it as test data!
  * Can calculate explicit processing time delays as well
* create "note from user" input dialog
* Look at cellphone sourced traffic
    * no NAT, weak end-host probe replies - no SACK!?
* Track drop packets and expose to GUI
* Pretty up the probe report into nested tables
* Seeing lost outbound probes - figure out how to get out of the stream and get pcap::Capture::stats access
* deleting old connections after FIN/RST
* Add DNS lookups for ProbeReports
* build a "CLI Client" for testing and general usefulness
* multiple-parallel ws connections
* HTTPS! to try to improve performance:now() time
  * blocks Geolocation

# Nagging
* need to do more IPv6 testing!  Just had a regression vs. localhost traffic with IPv6
* Add ARIA/Accessiblilty features to the GUI, ala https://www.chartjs.org/docs/latest/general/accessibility.html
* Re-test app with Oracle cloud to see if new packets get past the connection tracking damage

# Minor:
* too many to count
* test with Azure