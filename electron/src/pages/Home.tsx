import React, { useEffect, useRef, useState } from "react";
import useWebSocket from "react-use-websocket";
import { WS_URL } from "../App";
import { CongestedLink, ConnectionMeasurements } from "../netdebug_types";
import TableContainer from "@mui/material/TableContainer";
import Paper from "@mui/material/Paper";
import Table from "@mui/material/Table";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import TableCell from "@mui/material/TableCell";
import {
  calcStyleByThreshold,
  headerStyle,
  headerStyleWithWidth,
  prettyPrintSiUnits,
} from "../utils";

interface CongestionInfo {
  congestionSummary: Array<CongestedLink>;
  connectionMeasurements: Array<ConnectionMeasurements>;
}

const Home: React.FC = () => {
  const [myIp, setMyIp] = useState("Loading...");
  const [congestionInfo, setCongestionInfo] = useState<CongestionInfo | null>(
    null,
  );
  const last_send = useRef(null);
  useEffect(() => {
    sendRequest();
  }, []);

  const { sendMessage } = useWebSocket(WS_URL, {
    onOpen: () => {
      console.debug("WebSocket connection established.");
    },
    onMessage: (msg) => {
      const parsed = JSON.parse(msg.data);
      if (parsed.tag == "WhatsMyIpReply") {
        setMyIp(parsed.data.ip);
      } else if (parsed.tag == "CongestedLinksReply") {
        const congestionInfo: CongestionInfo = {
          congestionSummary: parsed.data.congestion_summary.links,
          connectionMeasurements: parsed.data.connection_measurements,
        };
        setCongestionInfo(congestionInfo);
      }
    },
    onClose: () => {
      console.debug("Closing websocket");
    },
  });

  const sendRequest = () => {
    console.debug("Sending WhatsMyIp request");
    sendMessage(
      JSON.stringify({
        tag: "WhatsMyIp",
      }),
    );
    console.debug("Sending InferCongestion request");
    sendMessage(
      JSON.stringify({
        tag: "CongestedLinksRequest",
      }),
    );
    last_send.current = window.performance.now();
  };

  function make_link_key(link: CongestedLink): string {
    return (
      link.key.src_ip +
      "..." +
      link.key.src_to_dst_hop_count +
      "..." +
      link.key.dst_ip
    );
  }

  function linkSortFnByCongestion(a: CongestedLink, b: CongestedLink) {
    // TODO: make this variable in how we can sort it
    const a_delta = a.peak_latency_us - a.mean_latency_us;
    const b_delta = b.peak_latency_us - b.mean_latency_us;
    return b_delta - a_delta;
  }

  return (
    <div>
      <h1>Home Page</h1>
      My external IP Address is <em>{myIp}</em>.
      <TableContainer component={Paper}>
        <Table
          sx={{ minWidth: 650 }}
          size="small"
          aria-label="Table of Connections"
        >
          <TableHead>
            <TableRow style={headerStyle}>
              <TableCell sx={headerStyleWithWidth(0.3)} align="left">
                TTL Distance
              </TableCell>
              <TableCell sx={headerStyleWithWidth(0.3)} align="left">
                Link
              </TableCell>
              <TableCell sx={headerStyleWithWidth(0.1)} align="right">
                Mean Latency
              </TableCell>
              <TableCell sx={headerStyleWithWidth(0.1)} align="right">
                Peak Latency
              </TableCell>
              <TableCell sx={headerStyleWithWidth(0.1)} align="right">
                # of Samples
              </TableCell>
              <TableCell sx={headerStyleWithWidth(0.1)} align="right">
                Max Congestion
              </TableCell>
            </TableRow>
            {congestionInfo &&
              congestionInfo.congestionSummary
                .sort(linkSortFnByCongestion)
                .map((link) => {
                  const linkKey = make_link_key(link);
                  const peak_mean_delta =
                    link.peak_latency_us - link.mean_latency_us;
                  return (
                    <TableRow key={linkKey}>
                      <TableCell>{link.key.src_hop_count}</TableCell>
                      <TableCell>{linkKey}</TableCell>
                      <TableCell align="right">
                        {prettyPrintSiUnits(
                          link.mean_latency_us * 1e-6,
                          "s",
                          2,
                        )}
                      </TableCell>
                      <TableCell align="right">
                        {prettyPrintSiUnits(
                          link.peak_latency_us * 1e-6,
                          "s",
                          2,
                        )}
                      </TableCell>
                      <TableCell align="right">
                        {link.latencies.length}
                      </TableCell>
                      <TableCell
                        align="right"
                        // 10ms is yellow, 50ms is red
                        sx={calcStyleByThreshold(peak_mean_delta, 10000, 50000)}
                      >
                        +{prettyPrintSiUnits(peak_mean_delta * 1e-6, "s", 2)}
                      </TableCell>
                    </TableRow>
                  );
                })}
          </TableHead>
        </Table>
      </TableContainer>
    </div>
  );
};

export default Home;
