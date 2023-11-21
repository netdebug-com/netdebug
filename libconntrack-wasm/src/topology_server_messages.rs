use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::ConnectionMeasurements;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DesktopToTopologyServer {
    Hello,
    StoreConnectionMeasurement {
        connection_measurements: Box<ConnectionMeasurements>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TopologyServerToDesktop {
    Hello {
        client_ip: IpAddr,
        user_agent: String,
    },
}
