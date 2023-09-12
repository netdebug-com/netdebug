extern crate prost_types;

include!(concat!(env!("OUT_DIR"), "/conntrack.rs"));

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn use_symbols_from_protobuf() {
        let _ = IpAddr::default();
        let _ = ConnectionStorageEntry::default();
    }
}
