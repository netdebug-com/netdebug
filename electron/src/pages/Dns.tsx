import React, { useEffect, useState } from "react";
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

/*
export default function BasicTable() {
  return (
    <TableContainer component={Paper}>
      <Table sx={{ minWidth: 650 }} aria-label="simple table">
        <TableHead>
          <TableRow>
            <TableCell>Dessert (100g serving)</TableCell>
            <TableCell align="right">Calories</TableCell>
            <TableCell align="right">Fat&nbsp;(g)</TableCell>
            <TableCell align="right">Carbs&nbsp;(g)</TableCell>
            <TableCell align="right">Protein&nbsp;(g)</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {rows.map((row) => (
            <TableRow
              key={row.name}
              sx={{ "&:last-child td, &:last-child th": { border: 0 } }}
            >
              <TableCell component="th" scope="row">
                {row.name}
              </TableCell>
              <TableCell align="right">{row.calories}</TableCell>
              <TableCell align="right">{row.fat}</TableCell>
              <TableCell align="right">{row.carbs}</TableCell>
              <TableCell align="right">{row.protein}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );
}
*/

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
  return new_map;
}

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

/*********************************************************** */

const Dns: React.FC = () => {
  const [dnsEntries, setDnsEntries] = useState(
    new Map<string, DnsTrackerEntry>(),
  );
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
      }
    },
    onClose: () => {
      console.log("Closing websocket");
    },
  });
  // send a DnsDump message one time on first load
  // TODO: why does it send @)(*%@)(% twice!? ANSWER: only in debug mode!
  useEffect(() => {
    console.log("Sending DNS request");
    sendMessage(
      JSON.stringify({
        DumpDnsCache: [],
      }),
    );
  }, []);
  return (
    <TableContainer component={Paper}>
      <Table sx={{ minWidth: 650 }} aria-label="simple table">
        <TableHead>
          <TableRow>
            <TableCell>Hostname (100g serving)</TableCell>
            <TableCell align="right">IP(s)</TableCell>
            <TableCell align="right">TTL&nbsp;(secs)</TableCell>
            <TableCell align="right">RTT&nbsp;(millis)</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {[...reindex_dns(dnsEntries).entries()].map(
            ([hostname, [dns_entry, ips]]) => (
              <TableRow
                key={hostname}
                sx={{ "&:last-child td, &:last-child th": { border: 0 } }}
              >
                <TableCell component="th" scope="row">
                  {dns_entry.hostname}
                </TableCell>
                <TableCell align="right">{format_ips(ips)}</TableCell>
                <TableCell align="right">{dns_entry.ttl_sec}</TableCell>
                <TableCell align="right">{dns_entry.rtt_usec / 1000}</TableCell>
              </TableRow>
            ),
          )}
        </TableBody>
      </Table>
    </TableContainer>
    /*
    <div>
      <h1>Dns Page: {dnsEntries && dnsEntries.size} </h1>
      <ul>
        {[...dnsEntries.entries()].map(([ip, entry]) => (
          <li key={ip}>{ip + "=>" + entry.hostname}</li>
        ))}
      </ul>
    </div> */
  );
};

export default Dns;
