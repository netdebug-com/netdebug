use std::net::IpAddr;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DesktopToTopologyServer {
    Hello,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TopologyServerToDesktop {
    Hello {
        client_ip: IpAddr,
        user_agent: String,
    },
}
