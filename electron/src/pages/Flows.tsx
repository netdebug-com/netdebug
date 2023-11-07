import React, { useEffect, useRef, useState } from "react";
import { ConnectionMeasurements } from "../netdebug_types";
import useWebSocket from "react-use-websocket";
import { WS_URL } from "../App";
import {
  headerStyle,
  headerStyleWithWidth,
  periodic_with_sla,
  rateEstimatorPrettyRate,
} from "../utils";
import TableContainer from "@mui/material/TableContainer";
import Paper from "@mui/material/Paper";
import Table from "@mui/material/Table";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import TableCell from "@mui/material/TableCell";

// build a connection key
function getConnKey(conn: ConnectionMeasurements) {
  const remote =
    conn.remote_hostname !== null
      ? conn.remote_hostname
      : `[${conn.remote_ip}]`;
  return `${conn.ip_proto} ::${conn.local_l4_port} --> ${remote}:${conn.remote_l4_port}`;
}

function connSortFn(a: ConnectionMeasurements, b: ConnectionMeasurements) {
  const dt = b.last_packet_time_ms - a.last_packet_time_ms;
  return dt;
}

const Flows: React.FC = () => {
  const [flowEntries, setFlowEntries] = useState(
    new Array<ConnectionMeasurements>(),
  );
  const min_time_between_requests_ms = 1000;
  const max_time_between_requests_ms = 2000;
  const timeout_id = useRef(null);
  const last_send = useRef(null);

  const sendRequest = () => {
    console.log("Sending DNS request");
    sendMessage(
      JSON.stringify({
        DumpFlows: [],
      }),
    );
    last_send.current = window.performance.now();
  };
  const { sendMessage } = useWebSocket(WS_URL, {
    onOpen: () => {
      console.log("WebSocket connection established.");
    },

    onMessage: (msg) => {
      const data = JSON.parse(msg.data);
      console.log("Got message from websocket: ", typeof data, data);
      if ("DumpFlowsReply" in data) {
        setFlowEntries(data.DumpFlowsReply);
        periodic_with_sla(
          "DumpFlowsReply",
          timeout_id,
          last_send,
          min_time_between_requests_ms,
          max_time_between_requests_ms,
          sendRequest,
        );
      }
    },

    onClose: () => {
      console.log("Closing websocket");
    },
  });

  // send a DumFlows message one time on first load
  useEffect(() => {
    sendRequest();
    return () => {
      // on unmount, clear the timeout, if it's set
      timeout_id && clearTimeout(timeout_id.current);
    };
  }, []);

  return (
    <TableContainer component={Paper}>
      <Table sx={{ minWidth: 650 }} aria-label="simple table">
        <TableHead>
          <TableRow style={headerStyle}>
            <TableCell sx={headerStyleWithWidth(0.3)} align="left">
              Application(s)
            </TableCell>
            <TableCell sx={headerStyleWithWidth(0.1)} align="right">
              Send Bandwidth
            </TableCell>
            <TableCell sx={headerStyleWithWidth(0.1)} align="right">
              Recv Bandwidth
            </TableCell>
            <TableCell sx={headerStyleWithWidth(0.5)} align="left">
              Flow Key
            </TableCell>
          </TableRow>
          {flowEntries
            .sort(connSortFn)
            .filter((conn) => conn.ip_proto == "TCP")
            .map((conn) => {
              const key = getConnKey(conn);
              let app: string;
              if (conn.associated_apps === null) {
                app = "(unknown)";
              } else {
                app = "";
                Object.entries(conn.associated_apps).forEach(([x, y]) => {
                  app += y === null ? `(${x})` : y;
                });
              }
              const renderedKey = conn.four_way_close_done ? <s>{key}</s> : key;
              return (
                <TableRow key={key}>
                  <TableCell>{app}</TableCell>
                  <TableCell align="right">
                    {rateEstimatorPrettyRate(conn.tx_byte_rate, "Bytes/s")}
                  </TableCell>
                  <TableCell align="right">
                    {rateEstimatorPrettyRate(conn.rx_byte_rate, "Bytes/s")}
                  </TableCell>
                  <TableCell>{renderedKey}</TableCell>
                </TableRow>
              );
            })}
        </TableHead>
      </Table>
    </TableContainer>
  );
};

export default Flows;
