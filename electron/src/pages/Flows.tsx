import React, { useState } from "react";
import { ConnectionMeasurements } from "../netdebug_types";
import {
  headerStyle,
  headerStyleWithWidth,
  prettyPrintSiUnits,
} from "../utils";
import TableContainer from "@mui/material/TableContainer";
import Paper from "@mui/material/Paper";
import Table from "@mui/material/Table";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import TableCell from "@mui/material/TableCell";
import { SwitchHelper } from "../SwitchHelper";
import { useWebSocketGuiToServer } from "../useWebSocketGuiToServer";

// build a unique connection key, using the same fields the
// rust logic uses.
function getUniqueConnKey(conn: ConnectionMeasurements) {
  return (
    `${conn.ip_proto}-${conn.local_ip}:${conn.local_l4_port}` +
    `-[${conn.remote_ip}]:${conn.remote_l4_port}`
  );
}

// build a connection key for displaying in the table
// This key might not be unique. E.g., two different local IPs could
// have the same local port and remote pair.
// And/or a remote hostname might have to IPs.
// While this is very unlikely, react gets very angry of `key` attributes
// aren't unique.
function getConnKeyForDisplay(conn: ConnectionMeasurements) {
  const remote =
    conn.remote_hostname !== null
      ? conn.remote_hostname
      : `[${conn.remote_ip}]`;
  return `${conn.ip_proto} :${conn.local_l4_port} --> ${remote}:${conn.remote_l4_port}`;
}

function connSortFn(a: ConnectionMeasurements, b: ConnectionMeasurements) {
  const max_rate_fn = (conn: ConnectionMeasurements) => {
    return Math.max(
      conn.tx_stats.last_min_byte_rate,
      conn.rx_stats.last_min_byte_rate,
    );
  };
  return max_rate_fn(b) - max_rate_fn(a);
}

const Flows: React.FC = () => {
  const [flowEntries, setFlowEntries] = useState(
    new Array<ConnectionMeasurements>(),
  );
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [showUdp, setShowUdp] = useState(true);
  const [showTcp, setShowTcp] = useState(true);

  useWebSocketGuiToServer({
    autoRefresh: autoRefresh,
    reqMsgType: { DumpFlows: [] },
    respMsgType: "DumpFlowsReply",
    min_time_between_requests_ms: 1000,
    max_time_between_requests_ms: 2000,
    responseCb: setFlowEntries,
  });

  return (
    <>
      <SwitchHelper
        text={"Auto Refresh"}
        state={autoRefresh}
        updateFn={setAutoRefresh}
      />
      <SwitchHelper text={"Show UDP"} state={showUdp} updateFn={setShowUdp} />
      <SwitchHelper text={"Show TCP"} state={showTcp} updateFn={setShowTcp} />
      <TableContainer component={Paper}>
        <Table
          sx={{ minWidth: 650 }}
          size="small"
          aria-label="Table of Connections"
        >
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
              .filter((conn) => {
                return (
                  (showTcp && conn.ip_proto == "TCP") ||
                  (showUdp && conn.ip_proto == "UDP")
                );
              })
              .map((conn) => {
                let app: string;
                if (conn.associated_apps === null) {
                  app = "(unknown)";
                } else {
                  app = "";
                  Object.entries(conn.associated_apps).forEach(([x, y]) => {
                    app += y === null ? `(${x})` : y;
                  });
                }
                const displayedKey = getConnKeyForDisplay(conn);
                const renderedKey = conn.four_way_close_done ? (
                  <s>{displayedKey}</s>
                ) : (
                  displayedKey
                );
                return (
                  <TableRow key={getUniqueConnKey(conn)}>
                    <TableCell>{app}</TableCell>
                    <TableCell align="right">
                      {prettyPrintSiUnits(
                        conn.tx_stats?.last_min_byte_rate,
                        "Bytes/s",
                      )}
                    </TableCell>
                    <TableCell align="right">
                      {prettyPrintSiUnits(
                        conn.rx_stats?.last_min_byte_rate,
                        "Bytes/s",
                      )}
                    </TableCell>
                    <TableCell>{renderedKey}</TableCell>
                  </TableRow>
                );
              })}
          </TableHead>
        </Table>
      </TableContainer>
    </>
  );
};

export default Flows;
