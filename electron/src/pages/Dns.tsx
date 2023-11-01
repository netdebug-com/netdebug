import React, { useEffect, useState } from "react";
import useWebSocket from "react-use-websocket";
import {DnsTrackerEntry} from "../netdebug_types";
import { WS_URL } from "../App";

const Dns: React.FC = () => {
  let [dnsEntries, setDnsEntries] = useState(new Map<string, DnsTrackerEntry>());
  const { sendMessage, lastMessage, readyState } = useWebSocket(WS_URL, {
    onOpen: () => {
      console.log("WebSocket connection established.");
    },

    onMessage: (msg) => {
      let data = JSON.parse(msg.data);
      console.log("Got message from websocket: ", typeof data, data);
      if ("DumpDnsCache" in data) {
        const cache = new Map<string, DnsTrackerEntry>(Object.entries(data.DumpDnsCache));
        console.log("Got a DumpDnsCache message!", typeof cache, cache);
        setDnsEntries(cache);
      }
    },
    onClose: (msg) => {
      console.log("Closing websocket");
    },
  });
  // send a DnsDump message one time on first load
  // TODO: add the type information from rust
  // TODO: 
  useEffect(() => {
    console.log("Sending DNS request");
    sendMessage(
      JSON.stringify({
        DumpDnsCache: [],
      })
    );
  }, []);
  return (
    <div>
      <h1>Dns Page: {dnsEntries && dnsEntries.size} </h1>
      <ul>
        {[...dnsEntries.entries()].map(([ip, entry]) => (
          <li key={ip}>{ip + "=>" + entry.hostname}</li>
        ))}
      </ul>
    </div>
  );
};

export default Dns;
