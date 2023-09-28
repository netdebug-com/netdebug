extern crate utils;

use log::error;
use log::info;

mod foo {
    pub mod bar {
        pub fn xxx() {
            log::info!("Foo bar");
        }
    }
}

fn main() {
    utils::init::netdebug_init();
    info!("Hello, World!");
    error!("Hello, World!");
    foo::bar::xxx();
}
