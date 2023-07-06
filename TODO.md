# Reminders

CTR+SHIFT+V to preview markdown in VSCODE!

# Features

* Plot the endhost and the nat datapoints!
* Figure out why(if!?) we're seeing multiple hopcounts/pathsin the same TCP stream - route flaps?
  * make sure we're plotting the same points in the same ttl!
* Seeing lost outbound probes - figure out how to get out of the stream and get pcap::Capture::stats access
* deleting old connections after FIN/RST
* move to LRUHashMap for connections in case they go away ungracefully
* Add DNS lookups for ProbeReports
* build a "CLI Client" for testing and general usefulness

# Nagging
* need to do more IPv6 testing!  Just had a regression vs. localhost traffic with IPv6

# Minor:
* figure out why http GETs log four (!!) times for a single get!? Once per route? Which routes?  What results?
```
 INFO  http         > 127.0.0.1:41098 "GET /static/tabs.css HTTP/1.1" 404 "-" "curl/8.0.1" 36.972µs
 INFO  http         > 127.0.0.1:41098 "GET /static/tabs.css HTTP/1.1" 404 "-" "curl/8.0.1" 25.494µs
 INFO  http         > 127.0.0.1:41098 "GET /static/tabs.css HTTP/1.1" 404 "-" "curl/8.0.1" 3.427µs
 INFO  http         > 127.0.0.1:41098 "GET /static/tabs.css HTTP/1.1" 200 "-" "curl/8.0.1" 547.442µs
 ```
