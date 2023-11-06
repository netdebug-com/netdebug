# IP to AS lookup stuff

## IP to prefix to origin AS mapping

### Getting the data

This data is from https://routeviews.org, specifically their MRT
dumps. (Note that the first collector in their list (`route-views2....` has only IPv4 prefixes).

Example download link: https://routeviews.org/route-views3/bgpdata/2023.11/RIBS/

Uncompressed MRT files can be processed by `mrt2csv` tool. It will out a CSV file with all prefixes and their origin ASN. It takes a couple of seconds to run.

### Lookup

Use the `lookup-ip` binary.
Interestingly, reading the CSV with the full routing table takes milli-seconds while reading and parsing the MRT dump takes seconds. ¯\_(ツ)_/¯


### ASN to AS / organization name.

Caida appears to have a dataset that maps ASN to inferred organizations. But it requires filling out a public access form first.

https://www.caida.org/catalog/datasets/as-organizations/

Similar for ARIN.
