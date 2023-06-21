Netdebug.com
=================

Network debugging as a service.  We help our customers help their customers solve their joint networking problems.

* Web product --> ./webserver
* Developer docs --> ./docs
* Quick start: 
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