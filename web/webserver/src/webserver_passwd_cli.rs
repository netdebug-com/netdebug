use clap::Parser;
use libwebserver::context::UserDb;

#[derive(Parser, Debug)]
struct Args {
    /// Output a new password hash
    #[arg(long)]
    plaintext: String,
}

/**
 * Picked this hashing algorithm based on :
 * https://blog.logrocket.com/rust-cryptography-libraries-a-comprehensive-list/#hashing
 *
 * But in reality, unless the webserver is compromised, these should be
 * privately held passwords so it's a smaller attack surface.
 */
fn main() {
    let args = Args::parse();

    let hash = UserDb::new_password(&args.plaintext).unwrap();
    println!("Hash of that password is: {}", hash);
}

#[cfg(test)]
mod test {
    use libwebserver::context::UserDb;
    use tokio::test;

    #[test]
    async fn passwd_verify() {
        let silly_passwd = "silly".to_string();
        let hash = UserDb::new_password(&silly_passwd).unwrap();
        assert!(pwhash::sha512_crypt::verify(silly_passwd, hash.as_str()));
    }
}
