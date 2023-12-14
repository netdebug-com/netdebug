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
    "local_l4_port": U16;
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
};
export type I64 = number;
export type DnsTrackerEntry = {
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
    "tag": "ConnectionTracker";
});
export type BidirTrafficStatsSummary = {
    "rx": TrafficStatsSummary;
    "tx": TrafficStatsSummary;
};
export type AggregateStatEntry = {
    "kind": AggregateStatKind;
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
export type DesktopToGuiMessages = ({
    "tag": "VersionCheck";
    "data": string;
} | {
    "tag": "DumpFlowsReply";
    "data": (ConnectionMeasurements)[];
} | {
    "tag": "DumpDnsCache";
    "data": Record<string, DnsTrackerEntry>;
} | {
    "tag": "DumpAggregateCountersReply";
    "data": (ChartJsBandwidth)[];
} | {
    "tag": "DumpStatCountersReply";
    "data": Record<string, U64>;
} | {
    "tag": "DumpDnsAggregateCountersReply";
    "data": (AggregateStatEntry)[];
} | {
    "tag": "WhatsMyIpReply";
    "data": {
        "ip": string;
    };
} | {
    "tag": "CongestedLinksReply";
    "data": {
        "congestion_summary": CongestionSummary;
        "connection_measurements": (ConnectionMeasurements)[];
    };
});
export type GuiToDesktopMessages = ({
    "tag": "DumpFlows";
} | {
    "tag": "DumpDnsCache";
} | {
    "tag": "DumpAggregateCounters";
} | {
    "tag": "DumpStatCounters";
} | {
    "tag": "DumpDnsAggregateCounters";
} | {
    "tag": "WhatsMyIp";
} | {
    "tag": "CongestedLinksRequest";
});
