// AUTO-GENERATED by typescript-type-def

export type U16 = number;
export type U8 = number;

/**
 * * A (hopefuly useful) subset of all of the possible IP Protocols
 *  * /// use IpProtocol::*;
 *  * ///  assert_eq!(TCP, IpProtocol::from_wire(TCP.to_wire()));
 *  
 */
export type IpProtocol = ("ICMP" | "TCP" | "UDP" | "ICMP6" | {
    "Other": U8;
});
export type ConnectionKey = {
    "local_ip": string;
    "remote_ip": string;

    /**
     * With ip_proto=TCP|UDP, this is the l4 local port
     * But with ICMP4|ICMP6, this is the ICMP_header.type
     */
    "local_l4_port": U16;

    /**
     * With ip_proto=TCP|UDP, this is the l4 remote port
     * But with ICMP4|ICMP6 echo request|echo reply, this is the IcmpEchoHeader.id
     */
    "remote_l4_port": U16;
    "ip_proto": IpProtocol;
};
export type F64 = number;
export type ProbeReportEntry = ({
    "RouterReplyFound": {
        "ttl": U8;
        "out_timestamp_ms": F64;
        "rtt_ms": F64;
        "src_ip": string;
        "comment": string;
    };
} | {
    "NatReplyFound": {
        "ttl": U8;
        "out_timestamp_ms": F64;
        "rtt_ms": F64;
        "src_ip": string;
        "comment": string;
    };
} | {
    "NoReply": {
        "ttl": U8;
        "out_timestamp_ms": F64;
        "comment": string;
    };
} | {
    "NoOutgoing": {
        "ttl": U8;
        "comment": string;
    };
} | {
    "RouterReplyNoProbe": {
        "ttl": U8;
        "in_timestamp_ms": F64;
        "src_ip": string;
        "comment": string;
    };
} | {
    "NatReplyNoProbe": {
        "ttl": U8;
        "in_timestamp_ms": F64;
        "src_ip": string;
        "comment": string;
    };
} | {
    "EndHostReplyFound": {
        "ttl": U8;
        "out_timestamp_ms": F64;
        "rtt_ms": F64;
        "comment": string;
    };
} | {
    "EndHostNoProbe": {
        "ttl": U8;
        "in_timestamp_ms": F64;
        "comment": string;
    };
});
export type U32 = number;
export type ProbeRoundReport = {

    /**
     * Time when the probe round was sent. Optional for backward compatibility
     */
    "probe_time": string;
    "probes": Record<U8, ProbeReportEntry>;
    "probe_round": U32;
    "application_rtt": (F64 | null);
};
export type ProbeReportSummaryNode = {
    "probe_type": ProbeReportEntry;
    "ttl": U8;
    "ip": (string | null);
    "rtts": (F64)[];
    "comments": (string)[];
};
export type ProbeReportSummary = {
    "raw_reports": (ProbeRoundReport)[];
    "summary": Record<U8, (ProbeReportSummaryNode)[]>;
};
export type U64 = number;
export type Usize = number;
export type ExportedSimpleStats = {
    "num_samples": Usize;
    "mean": F64;
    "variance": (F64 | null);
    "min": F64;
    "max": F64;
};

/**
 * Used for exported data (to UI, storage, etc.)
 * A summary of a unidirectional flow stats. A flow can be anything: A 5-tuple,
 * aggregated by IP, domain, whatever
 */
export type TrafficStatsSummary = {

    /**
     * total number of bytes
     */
    "bytes": U64;

    /**
     * total number of packets
     */
    "pkts": U64;

    /**
     * if the flow had enough packets and duration: the maximum
     * burst we observed (over the configured time window)
     */
    "burst_pkt_rate": (F64 | null);
    "burst_byte_rate": (F64 | null);
    "last_min_pkt_rate": (F64 | null);
    "last_min_byte_rate": (F64 | null);

    /**
     * Lost bytes, as indicated by SACK blocks.
     */
    "lost_bytes": (U64 | null);
    "rtt_stats_ms": (ExportedSimpleStats | null);
};

/**
 * The result of a single PingTree rund for a single IP.
 * The number of rounds is raw_rtts_micros.len()
 * NOTE: I considered using a `Duration` instead of u64's but eventually
 * decided against it: (a) pingtree uses tokio::Time::Duration which we can't use
 * here because wasm. (b) this struct is just use to serialize the results for
 * consumption by JS so we'd convert to an integer during serialization anyways.
 */
export type PingTreeIpReport = {
    "ip": string;

    /**
     * A list of (optional) RTTs values. One list item per round.
     */
    "raw_rtts_micros": ((U64 | null))[];
    "min_rtt_micros": (U64 | null);
    "max_rtt_micros": (U64 | null);
    "mean_rtt_micros": (U64 | null);
};
export type PingtreeUiResult = {

    /**
     * Time when the probe round was sent.
     */
    "probe_time": string;
    "hops_to_ips": Record<U8, (string)[]>;
    "ip_reports": Record<string, PingTreeIpReport>;
};
export type ConnectionMeasurements = {
    "key": ConnectionKey;
    "local_hostname": (string | null);
    "remote_hostname": (string | null);
    "probe_report_summary": ProbeReportSummary;
    "user_annotation": (string | null);
    "user_agent": (string | null);
    "associated_apps": (Record<U32, (string | null)> | null);

    /**
     * Whether this connection has been (partially) closed. I.e., at least on FIN of RST ]
     * was received.
     */
    "close_has_started": boolean;

    /**
     * Whether this connection has completed the 4-way TCP teardown (2 FINs that were
     * ACK'ed)
     */
    "four_way_close_done": boolean;
    "start_tracking_time_ns": F64;
    "last_packet_time_ns": F64;
    "rx_stats"?: TrafficStatsSummary;
    "tx_stats"?: TrafficStatsSummary;

    /**
     * Pingtrees, that have been iniated and run based on the routers discovered by this connection's
     * inband probes.
     */
    "pingtrees"?: (PingtreeUiResult)[];

    /**
     * Indicates if this connection measurement was generated due to eviction (idle / TIME_WAIT or
     * exceeding the connection limit)
     * or not (e.g., because the flow was still active but hit the active flow export interval)
     */
    "was_evicted"?: boolean;
};
export type I64 = number;
export type DnsTrackerEntry = {
    "ip": (string | null);
    "hostname": string;
    "created": string;
    "from_ptr_record": boolean;
    "rtt_usec"?: I64;
    "ttl_sec"?: I64;
};
export type ChartJsPoint = {

    /**
     * x-value. For bandwidth plots this is seconds in the past where the last bucket is `now`, i.e., 0.0
     * And a value of -2.5 is 2.5secs in the past. (Note these values are all <= 0)
     */
    "x": F64;

    /**
     * y-value. For bandwidth plots this is bit-per-second
     */
    "y": F64;
};

/**
 * Represents the data for a single bandwidth chart with data arranged for direct plotting
 * with `chart.js`.
 */
export type ChartJsBandwidth = {

    /**
     * The label of this chart. E.g., `Last 5 Seconds`
     */
    "label": string;

    /**
     * The total amount of time this Chart can hold, i.e., `bucket_time_window * num_buckets`.
     * This isn't necessarily the amount of data the chart is holding
     */
    "total_duration_sec": U64;

    /**
     * The maximum value of the y axis (which represents bits/s)
     */
    "y_max_bps": F64;

    /**
     * The received / download bandwidth history as chart.js points
     */
    "rx": (ChartJsPoint)[];

    /**
     * The sent / upload bandwidth history as chart.js points
     */
    "tx": (ChartJsPoint)[];
};
export type AggregateStatKind = ({
    "tag": "DnsDstDomain";
    "name": string;
} | {
    "tag": "Application";
    "name": string;
} | {
    "tag": "HostIp";
    "name": string;
} | {
    "tag": "ConnectionTracker";
});
export type BidirTrafficStatsSummary = {
    "rx": TrafficStatsSummary;
    "tx": TrafficStatsSummary;
};
export type AggregateStatEntry = {
    "kind": AggregateStatKind;

    /**
     * Additional information. We hack it by storing the hostname in the
     * the comment field for AggregateStatKind::Host
     */
    "comment"?: (string | null);
    "bandwidth": (ChartJsBandwidth)[];
    "summary": BidirTrafficStatsSummary;
    "connections": (ConnectionMeasurements)[];
};
export type CongestedLinkKey = {

    /**
     * The hop-count from the origin to the src_ip
     */
    "src_hop_count": U8;

    /**
     * The start of the link
     */
    "src_ip": string;

    /**
     * The other side/end of the 'link'
     */
    "dst_ip": string;

    /**
     * The number of router hops/ttl between the two
     */
    "src_to_dst_hop_count": U8;
};

/**
 * * A CongestedLink tracks the latency and latency variance
 *  * between two router/ttl hops.  They maybe directly
 *  * connected, e.g., src_to_dst_hop_count=1, or indirectly
 *  * connected (e.g., if we don't have data for routers inbetween).
 *  *
 *  * Higher variation in latency implies higher congestion!
 *  *
 *  * CongestedLink's are uni-directional: the link from A-->B may
 *  * be more or less congested than the link from B-->A
 *  *
 *  * NOTE: src_latencies and dst_latencies Vec<>'s will always have
 *  * the same size and are indexed so that src_latency[i] and dst_latency[i]
 *  * will come from the same packet train/time so that they can be compared
 *  * directly.
 *  *
 *  
 */
export type CongestionLatencyPair = {

    /**
     * Round-trip time from the origin to the first part of the link
     */
    "src_rtt_us": U64;

    /**
     * Round-trip time from the origin to the second part of the link
     */
    "dst_rtt_us": U64;

    /**
     * which connection did this come from?  Might want to include a
     * 'start_time' here as well to better uniquely identify it but
     * hopefully ok for now
     */
    "connection_key": ConnectionKey;

    /**
     * Which probe-round did this come from?
     */
    "probe_round": U32;
};
export type CongestedLink = {

    /**
     * The src + dst IPs and distance between them for this congested link
     */
    "key": CongestedLinkKey;

    /**
     * The latency measurements to the src_ip from a common origin, see Note above
     */
    "latencies": (CongestionLatencyPair)[];

    /**
     * The average latency from src to dst (subtracking src from dst latency)
     */
    "mean_latency_us"?: (U64 | null);

    /**
     * The peak latency from src to dst (subtracking src from dst latency)
     */
    "peak_latency_us"?: (U64 | null);
};

/**
 * * A collection of information about congested linked.  
 *  
 */
export type CongestionSummary = {
    "links": (CongestedLink)[];
};
export type CongestedLinksReply = {
    "congestion_summary": CongestionSummary;
    "connection_measurements": (ConnectionMeasurements)[];
};
export type NetworkGatewayPingType = ("IcmpEcho" | "ArpOrNdp");
export type NetworkGatewayPingProbe = {

    /**
     * When we send the ICMP echo request
     */
    "sent_time_utc_ns": (U64 | null);

    /**
     * When we got the ICMP echo reply (if we got it)
     */
    "recv_time_utc_ns": (U64 | null);

    /**
     * The sequence number of the probe
     */
    "seqno": U16;

    /**
     * DId we drop this probe?  Set to true if we got the next one in sequence
     */
    "dropped": boolean;

    /**
     * What type of ping should we send?
     */
    "ping_type": NetworkGatewayPingType;
};

/**
 * The state for when we ping the gateways local to our network interfaces
 */
export type NetworkGatewayPingState = {

    /**
     * The ConnectionKey that describes our ping's flow
     */
    "key": ConnectionKey;

    /**
     * When we send the next echo_request, what sequence number?
     * NOTE: needs to be Wrapping<u16> as rust will panic on overflow
     * But Typescript doesn't understand Wrapping<> so just recast to u16 for TS
     */
    "next_seq": U16;

    /**
     * State for the current outstanding probe; we only send one probe at a time
     */
    "current_probe": (NetworkGatewayPingProbe | null);

    /**
     * The local mac we put in the src field when we ping this gateway
     */
    "local_mac": [U8, U8, U8, U8, U8, U8];

    /**
     * The mac for the gateway that we put in the ether.dst field when we ping it
     */
    "gateway_mac": ([U8, U8, U8, U8, U8, U8] | null);

    /**
     * An array of Probe sent and received information
     */
    "historical_probes": (NetworkGatewayPingProbe)[];
};
export type NetworkInterfaceState = {

    /**
     * A random, unique id to identify this particular instance. We need/use
     * this on the DB backend. To match DB entries
     */
    "uuid": string;

    /**
     * The default gw IPs, if known/assigned.  Could be empty
     */
    "gateways": (string)[];

    /**
     * The name the OS gave to the interface, if exists/active
     * If this is None then there is no active network.
     */
    "interface_name": (string | null);

    /**
     * The list of IPs bound to the interface, if exists. Could be empty.
     */
    "interface_ips": (string)[];

    /**
     * A comment for when/how we got this info
     */
    "comment": string;

    /**
     * Does the Network interface have link and is admin UP?
     */
    "has_link": boolean;

    /**
     * Is this a wireless interface?
     */
    "is_wireless": boolean;

    /**
     * The first time this config was set.
     */
    "start_time": string;

    /**
     * If this is no longer the current config, when did it stop?
     */
    "end_time": (string | null);

    /**
     * Ping state for each of the gateways; we couple the ping
     * state to the interface state b/c if the interface state changes,
     * all of the ping state needs to change too
     */
    "gateways_ping": Record<string, NetworkGatewayPingState>;
};
export type ExportedNeighborState = {
    "ip": string;
    "mac": string;
    "learn_time": string;
    "vendor_oui": (string | null);
};
export type DesktopLogLevel = ("Error" | "Warn" | "Info" | "Debug");
export type AggregatedGatewayPingData = {

    /**
     * The UUID of the NetworkInterfaceState this ping data belongs to
     */
    "network_interface_uuid": string;

    /**
     * The gateway IP this ping data belongs to.
     */
    "gateway_ip": string;

    /**
     * The number of ping probes that were sent
     */
    "num_probes_sent": Usize;

    /**
     * The number of ping responses received.
     */
    "num_responses_recv": Usize;
    "rtt_mean_ns": U64;
    "rtt_variance_ns": (U64 | null);
    "rtt_min_ns": U64;

    /**
     * RTT median value in nanosecs
     */
    "rtt_p50_ns": U64;

    /**
     * RTT P75 value in nanosecs
     */
    "rtt_p75_ns": U64;

    /**
     * RTT P90 value in nanosecs
     */
    "rtt_p90_ns": U64;

    /**
     * RTT P99 value in nanosecs
     */
    "rtt_p99_ns": U64;
    "rtt_max_ns": U64;
};

/**
 * Messages sent over the websocket from the desktop app (both
 * rust and electron) to the topology server.
 */
export type DesktopToTopologyServer = ({
    "tag": "Hello";
} | {
    "tag": "StoreConnectionMeasurement";
    "data": {
        "connection_measurements": ConnectionMeasurements;
    };
} | {
    "tag": "InferCongestion";
    "data": {
        "connection_measurements": (ConnectionMeasurements)[];
    };
} | {
    "tag": "PushCounters";
    "data": {
        "timestamp": string;
        "counters": Record<string, U64>;
        "os": string;
        "version": string;
    };
} | {
    "tag": "PushLog";
    "data": {
        "timestamp": string;
        "level": DesktopLogLevel;
        "scope": string;
        "msg": string;
        "os": string;
        "version": string;
    };
} | {
    "tag": "PushNetworkInterfaceState";
    "data": {
        "network_interface_state": NetworkInterfaceState;
    };
} | {
    "tag": "PushGatewayPingData";
    "data": {
        "ping_data": (AggregatedGatewayPingData)[];
    };
} | {
    "tag": "PushDnsEntries";
    "data": {
        "dns_entries": (DnsTrackerEntry)[];
    };
} | {
    "tag": "Ping";
});

/**
 * The elements of OrganizationInfo that are safe for anyone to read
 * i.e., "public" in the GUI frontend
 */
export type PublicOrganizationInfo = {
    "id": I64;
    "name": (string | null);
    "description": (string | null);
    "admin_contact": (string | null);
};

/**
 * The elements of DeviceInfo that are safe for anyone to read
 * i.e., "public" in the GUI frontend
 */
export type PublicDeviceInfo = {

    /**
     * The unique ID of this device
     */
    "uuid": string;

    /**
     * E.g., hostname
     */
    "name": (string | null);

    /**
     * Which organization does this belong to by internal ID
     */
    "organization_id": I64;
    "description": (string | null);
    "created": string;
};
export type PublicDeviceDetails = {

    /**
     * Details is a superset of DeviceInfo
     */
    "device_info": PublicDeviceInfo;

    /**
     * Number of flows for this device in DB
     */
    "num_flows_stored": U64;

    /**
     * Number of with sent packet loss; None if No flows
     */
    "num_flows_with_send_loss": (U64 | null);

    /**
     * Number of with recv packet loss; None if No flows
     */
    "num_flows_with_recv_loss": (U64 | null);

    /**
     * Timestamp of the oldest flow; None if No flows
     */
    "oldest_flow_time": string;

    /**
     * Timestamp of the newest flow; None if No flows
     */
    "newest_flow_time": string;
};
