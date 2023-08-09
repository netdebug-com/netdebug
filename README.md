Netdebug.com
=================

Network debugging as a service.  We help our customers help their customers solve their joint networking problems.

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
