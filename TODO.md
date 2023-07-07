# Reminders

CTR+SHIFT+V to preview markdown in VSCODE!

# Features

* Fix the main plot - just use the data from the probe summaries... 
  * Can calculate explicit processing time delays as well
* Seeing lost outbound probes - figure out how to get out of the stream and get pcap::Capture::stats access
* deleting old connections after FIN/RST
* move to LRUHashMap for connections in case they go away ungracefully
* Add DNS lookups for ProbeReports
* build a "CLI Client" for testing and general usefulness

# Nagging
* need to do more IPv6 testing!  Just had a regression vs. localhost traffic with IPv6
* Add ARIA/Accessiblilty features to the GUI, ala https://www.chartjs.org/docs/latest/general/accessibility.html

# Minor:
