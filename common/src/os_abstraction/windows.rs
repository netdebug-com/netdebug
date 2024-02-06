/// ! Read https://learn.microsoft.com/en-us/windows/win32/network-interfaces to understand
/// ! the various windows interface naming schemes (GUID, LUID, 'name', 'Alias', etc.)
/// ! Confusing AF ... hate this shit.
///
/// More stupidity: the pcap-style interface name (as explained https://daveurrutiablog.wordpress.com/2016/05/03/tshark-network-interface-names-mystery-guid/)
/// is formatted as "\Device\NPF_{GUID}" where "GUID" is used in lots of places in the code
/// Took FOREVER to reverse engineer this
use crate::os_abstraction::NetworkInterface;
use windows::core::GUID;
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceGuidToLuid, GET_ADAPTERS_ADDRESSES_FLAGS, IP_ADAPTER_ADDRESSES_LH,
};
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::{
    NetworkManagement::IpHelper::{ConvertInterfaceLuidToIndex, GetAdaptersAddresses},
    Networking::WinSock::AF_UNSPEC,
};

/// Take an interface name from pcap and convert it to an if_index
/// Such a mess to figure out
pub(crate) fn pcap_ifname_to_ifindex(ifname: String) -> Result<u32, std::io::Error> {
    // first, if the ifname is named 'pcap' style (e.g.,  \Device\NPF_{B261D603-2099-43FB-97CC-826C57581AF9})
    // then trim the pcap "\Device\NPF_{" bits so windows can recognize it
    let guid_str = ifname.replace("\\Device\\NPF_{", "").replace('}', "");
    if guid_str.len() != 36 {
        // magic number from GUID::from(&str)
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("String not a GUID: {}", guid_str),
        ));
    }
    let guid = GUID::from(guid_str.as_str());
    // second, convert the interface name to an LUID
    let mut luid = NET_LUID_LH::default();
    unsafe {
        if let Err(e) = ConvertInterfaceGuidToLuid(&guid, &mut luid) {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, e));
        }
        let mut if_index: u32 = 0;
        if let Err(e) = ConvertInterfaceLuidToIndex(&luid, &mut if_index) {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, e));
        }
        Ok(if_index)
    }
}

pub(crate) fn list_network_interfaces() -> Result<Vec<super::NetworkInterface>, std::io::Error> {
    let mut buf_len = 0;

    // This will get the number of bytes we need to allocate for all devices
    unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC.0 as u32,
            GET_ADAPTERS_ADDRESSES_FLAGS(0),
            None,
            None,
            &mut buf_len,
        );
    }

    if buf_len == 0 {
        return Ok(Vec::new()); // No adapters?
    }

    // Manually allocate `buf_len` bytes, and create a raw pointer to it with the correct alignment
    let adapters_list: *mut IP_ADAPTER_ADDRESSES_LH = unsafe {
        std::alloc::alloc(
            std::alloc::Layout::from_size_align(
                usize::try_from(buf_len)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
                core::mem::align_of::<IP_ADAPTER_ADDRESSES_LH>(),
            )
            .unwrap(),
        )
    } as *mut IP_ADAPTER_ADDRESSES_LH;

    // Get our list of adapters
    let result = unsafe {
        GetAdaptersAddresses(
            // [IN] Family
            0, // AF_UNSPEC
            // [IN] Flags
            GET_ADAPTERS_ADDRESSES_FLAGS(0),
            // [IN] Reserved
            None,
            // [INOUT] AdapterAddresses
            Some(adapters_list),
            // [INOUT] SizePointer
            &mut buf_len,
        )
    };

    let mut results = Vec::new();
    // Was the call successful?
    if result == ERROR_SUCCESS.0 {
        // Yes; walk the list and make our return type
        unsafe {
            // foreach adapter in the internally linked list
            let mut ptr = adapters_list;
            while !ptr.is_null() {
                results.push(NetworkInterface {
                    name: (*ptr).AdapterName.to_string().unwrap(),
                    // WEIRD: there is an IF_INDEX under ptr.Anonymous1.Anonymous.IfIndex, but is this a valid member?
                    // The C documentation says it's a union.. but keyed on what?  Just use IPv6 I guess...
                    ifindex: (*ptr).Ipv6IfIndex,
                    desc: (*ptr).Description.to_string().ok(),
                });
                ptr = (*ptr).Next; // next adapter
            }
        }
    }

    // manually deallocate mem whether successful or not
    unsafe {
        std::alloc::dealloc(
            adapters_list as *mut u8,
            std::alloc::Layout::from_size_align(
                buf_len as usize,
                core::mem::align_of::<IP_ADAPTER_ADDRESSES_LH>(),
            )
            .unwrap(),
        )
    };
    if result == ERROR_SUCCESS.0 {
        Ok(results)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("GetAdapterAddresses: error={}", result),
        ))
    }
    /* NOTE: tried to use GetIfTable2() instead of GetAdaptersAddresses but:
     * 1) The FreeMibTable() call to free the mem would always error out with "wrong function"
     * 2) It didn't have the IP addresses (which would be nice to use)
     * ... so think about it for later.
     */
}

#[cfg(test)]
mod test {
    use windows::{
        core::GUID,
        Win32::NetworkManagement::{
            IpHelper::{ConvertInterfaceGuidToLuid, ConvertInterfaceLuidToIndex},
            Ndis::NET_LUID_LH,
        },
    };

    #[ignore] // this only works on machines where there is a GUID exactly like so, e.g., Rob's laptop
    #[test]
    fn test_guid_luid_ifindex() {
        let pcap_dev = "\\Device\\NPF_{B261D603-2099-43FB-97CC-826C57581AF9}".to_string();
        let real_dev = "{B261D603-2099-43FB-97CC-826C57581AF9}".to_string();
        // no curly braces...
        let guid_name = "B261D603-2099-43FB-97CC-826C57581AF9".to_string();
        assert_eq!(pcap_dev.replace("\\Device\\NPF_", ""), real_dev);
        let guid = GUID::from(guid_name.as_str());
        println!("Parsed GUID={:?}", guid);
        let mut if_index = 0;
        unsafe {
            let mut luid = NET_LUID_LH::default();
            ConvertInterfaceGuidToLuid(&guid, &mut luid).unwrap();
            ConvertInterfaceLuidToIndex(&luid, &mut if_index).unwrap();
        }
        println!("If_index={}", if_index);
    }
}
