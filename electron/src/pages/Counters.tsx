import React, { useEffect, useRef, useState } from "react";
import useWebSocket from "react-use-websocket";
import { DnsTrackerEntry } from "../netdebug_types";
import { WS_URL } from "../App";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import Paper from "@mui/material/Paper";

function format_ips(ips: string[]) {
  if (ips.length <= 1) {
    return <div> {ips.join(",")} </div>;
  } else {
    return (
      <details>
        <summary>{ips.length} Addresses</summary>
        <ul>
          {ips.map((ip) => (
            <li key={ip}> {ip}</li>
          ))}
        </ul>
      </details>
    );
  }
}

function biggest_rtt(
  [, [dns1]]: [string, [DnsTrackerEntry, string[]]],
  [, [dns2]]: [string, [DnsTrackerEntry, string[]]],
): number {
  return dns2.rtt_usec - dns1.rtt_usec;
}

/*********************************************************** */

const Dns: React.FC = () => {
  const [dnsEntries, setDnsEntries] = useState(
    new Map<string, DnsTrackerEntry>(),
  );
  const min_time_between_requests = 500;
  const max_time_between_requests = 1000;
  const timeout_id = useRef(null);
  const last_send = useRef(null);
  const yellow_threshold = useRef(null);
  const red_threshold = useRef(null);

  const { sendMessage } = useWebSocket(WS_URL, {
    onOpen: () => {
      console.log("WebSocket connection established.");
    },

    onMessage: (msg) => {
      const data = JSON.parse(msg.data);
      console.log("Got message from websocket: ", typeof data, data);
      if ("DumpDnsCache" in data) {
        const cache = new Map<string, DnsTrackerEntry>(
          Object.entries(data.DumpDnsCache),
        );
        console.log("Got a DumpDnsCache message!", typeof cache, cache);
        setDnsEntries(cache);
        // check how long it's been since our last message and send now or later
        // depending on our SLAs
        const send_delta = performance.now() - last_send.current;
        if (send_delta <= min_time_between_requests) {
          timeout_id.current = setTimeout(
            sendRequest,
            min_time_between_requests - send_delta,
          );
        } else {
          timeout_id.current = null;
          sendRequest();
          if (send_delta > max_time_between_requests) {
            console.warn(
              "DumpDnsCache reply delayed beyond SLA " +
                max_time_between_requests +
                "ms",
            );
          }
        }
      }
    },
    onClose: () => {
      console.log("Closing websocket");
    },
  });

  function reindex_dns(
    dns_map: Map<string, DnsTrackerEntry>,
  ): Map<string, [DnsTrackerEntry, string[]]> {
    const new_map = new Map<string, [DnsTrackerEntry, string[]]>();
    dns_map.forEach((dns_entry, ip) => {
      if (new_map.has(dns_entry.hostname)) {
        const entry = new_map.get(dns_entry.hostname);
        entry[1].push(ip);
      } else {
        new_map.set(dns_entry.hostname, [dns_entry, [ip]]);
      }
    });
    [yellow_threshold.current, red_threshold.current] =
      calcThresholdStats(new_map);
    return new_map;
  }

  // send a DnsDump message one time on first load
  // TODO: why does it send @)(*%@)(% twice!? ANSWER: only in debug mode!
  useEffect(() => {
    sendRequest();
    return () => {
      // on unmount, clear the timeout, if it's set
      timeout_id && clearTimeout(timeout_id.current);
    };
  }, []);

  const sendRequest = () => {
    console.log("Sending DNS request");
    sendMessage(
      JSON.stringify({
        DumpDnsCache: [],
      }),
    );
    last_send.current = window.performance.now();
  };

  // which rtts do we color yellow and red?
  // calc avg ; yellow is avg *2 , red is avg * 4
  // NOTE: tried calculating yellow = avg + 1 stddev, red=avg + 2stddev but it
  //    made the thresholds too high!
  // becareful not to assume that all RTTs are defined and count != array.length
  const calcThresholdStats = (
    data: Map<string, [DnsTrackerEntry, string[]]>,
  ): [number, number] => {
    let sum = 0;
    let count = 0;
    // calc the avg
    data.forEach(([dns]) => {
      if (dns.rtt_usec !== null) {
        sum += dns.rtt_usec;
        count += 1;
      }
    });
    const avg = sum / count;
    return [avg * 2, avg * 4];
  };

  // Test the rtt vs. the yellow/red thresholds and return the matching style
  const calcStyleByRtt = (rtt_usec: number) => {
    if (rtt_usec >= red_threshold.current) {
      return (
        <div style={{ color: "red", backgroundColor: "black" }}>
          {rtt_usec / 1000}
        </div>
      );
    } else if (rtt_usec >= yellow_threshold.current) {
      return <div style={{ color: "orange" }}>{rtt_usec / 1000}</div>;
    } else {
      return <div>{rtt_usec / 1000}</div>;
    }
  };

  return (
    <TableContainer component={Paper}>
      <Table sx={{ minWidth: 650 }} aria-label="simple table">
        <TableHead>
          <TableRow>
            <TableCell>Hostname</TableCell>
            <TableCell align="right">IP(s)</TableCell>
            <TableCell align="right">TTL&nbsp;(secs)</TableCell>
            <TableCell align="right">RTT&nbsp;(millis)</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {[...reindex_dns(dnsEntries).entries()]
            .sort(biggest_rtt)
            .map(([hostname, [dns_entry, ips]]) => (
              <TableRow
                key={hostname}
                sx={{ "&:last-child td, &:last-child th": { border: 0 } }}
              >
                <TableCell component="th" scope="row">
                  {dns_entry.hostname}
                </TableCell>
                <TableCell align="right">{format_ips(ips)}</TableCell>
                <TableCell align="right">{dns_entry.ttl_sec}</TableCell>
                <TableCell align="right">
                  {calcStyleByRtt(dns_entry.rtt_usec)}
                </TableCell>
              </TableRow>
            ))}
        </TableBody>
      </Table>
    </TableContainer>
  );
};

export default Dns;
