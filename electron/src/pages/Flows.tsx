import React, {
  Dispatch,
  SetStateAction,
  useEffect,
  useRef,
  useState,
} from "react";
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
import { FormControlLabel, Switch } from "@mui/material";

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
  const dt = b.last_packet_time_ms - a.last_packet_time_ms;
  return dt;
}

type StateUpdateFn = Dispatch<SetStateAction<boolean>>;
interface SwitchHelperProps {
  text: string;
  state: boolean;
  updateFn: StateUpdateFn;
}
const SwitchHelper: React.FC<SwitchHelperProps> = (props) => {
  return (
    <FormControlLabel
      control={<Switch />}
      label={props.text}
      checked={props.state}
      onChange={() => {
        props.updateFn(!props.state);
      }}
    />
  );
};

const Flows: React.FC = () => {
  const [flowEntries, setFlowEntries] = useState(
    new Array<ConnectionMeasurements>(),
  );
  const [autoRefresh, setAutoRefresh] = React.useState(true);
  const [showUdp, setShowUdp] = React.useState(true);
  const [showTcp, setShowTcp] = React.useState(true);
  const min_time_between_requests_ms = 1000;
  const max_time_between_requests_ms = 2000;
  const timeout_id = useRef(null);
  const last_send = useRef(null);

  const sendRequest = () => {
    console.log("Sending DumpFlows request");
    sendMessage(
      JSON.stringify({
        DumpFlows: [],
      }),
    );
    last_send.current = window.performance.now();
  };
  const { sendMessage } = useWebSocket(WS_URL, {
    onOpen: () => {
      console.debug("WebSocket connection established.");
    },

    onMessage: (msg) => {
      const data = JSON.parse(msg.data);
      console.debug("Got message from websocket: ", typeof data);
      if ("DumpFlowsReply" in data) {
        if (autoRefresh) {
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
      }
    },

    onError: () => {
      // If this happens, something is seriously wrong since the desktop
      // process must not be running
      alert("Error connecting to websocket");
    },

    onClose: () => {
      console.debug("Closing websocket");
    },
  });

  // send a DumFlows message one time on first load
  // or if autoRefresh changes to "on"
  useEffect(() => {
    if (autoRefresh) {
      sendRequest();
    }
    return () => {
      // on unmount, clear the timeout, if it's set
      timeout_id && clearTimeout(timeout_id.current);
    };
  }, [autoRefresh]);

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
        <Table sx={{ minWidth: 650 }} aria-label="Table of Connections">
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
    </>
  );
};

export default Flows;
