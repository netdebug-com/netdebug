extern crate common;

fn main() {
    common::init::netdebug_init();
    println!("Hello, World!");

    let _ = std::thread::spawn(|| {
        println!("In a separate thread. We are about to...");
        panic!(" P-A-N-I-C ");
    })
    .join();

    println!("This line is never reached, due to the panic hook");
}
