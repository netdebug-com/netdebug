use std::{fmt::Display, fs::File, io::Read, net::IpAddr};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteEntry {
    pub prefix: IpAddr,
    pub prefix_len: u8,
    pub origin_as: u32,
}

impl Display for RouteEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{} {}", self.prefix, self.prefix_len, self.origin_as)?;
        Ok(())
    }
}

/// Return a `dyn Read` instance for the given filename. If the filename
/// is `-` then `stdin` is read instead.
pub fn input_reader(fname: &str) -> Result<Box<dyn Read>, std::io::Error> {
    let ret: Box<dyn Read> = if fname == "-" {
        Box::new(std::io::stdin())
    } else {
        Box::new(File::open(fname)?)
    };
    Ok(ret)
}
