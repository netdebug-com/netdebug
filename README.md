Netdebug.com
=================

Network debugging as a service.  There is a desktop-side client and a remote server that share a common
set of libraries.  These libraries are open-source (under dual-licensed MIT and APACHE licenses) and
both collect network data from the opererating system and actively track and probe live connections.


Embedded Probes
===================
One of the interesting/novel techniques that NetDebug uses is an extension of Rob's TCP Sidecar
work (https://dl.acm.org/doi/10.1145/1177080.1177093) where we replay old packets in a 
five-tuple stream (e.g., TCP, UDP, etc.) so that we can send network probes on the exact 
same path (including through ECMP, firewalls, non-terminating load-balancers, etc.) and get
end-to-end deterministic measurements per-flow and per-hop.


Getting Started
===============

* Desktop product --> ./desktop
* Web product --> ./webserver
* Developer docs --> ./docs
* Quick start desktop: 
    * Build debug and run webserver binding localhost:3030 : 
    ```
    ./build.sh && sudo ./target/debug/desktop
    xdg-open http://localhost:33434
    ```
* Quick start webserver: 
    * Build debug and run webserver binding localhost:3030 : 
    ```
    cargo build && sudo ./target/debug/webserver
    ``` 
    * Run production server binding ephemeral port: 
    ```
    cargo build --release && sudo ./target/release/webserver --production
    ```
    * Run unittests
    ```
    cargo test
    ```
