import React, { useEffect, useRef, useState } from "react";
import useWebSocket from "react-use-websocket";
import { WS_URL } from "../App";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import Paper from "@mui/material/Paper";
import {
  formatValue,
  headerStyle,
  headerStyleWithWidth,
  periodic_with_sla,
  reshapeCounter,
} from "../utils";
import { SwitchHelper } from "../SwitchHelper";

const Counters: React.FC = () => {
  const [counters, setCounters] = useState(new Map<string, number>());
  const [thousandsSep, setThousandsSep] = useState(true);
  const min_time_between_requests_ms = 500;
  const max_time_between_requests_ms = 1000;
  const timeout_id = useRef(null);
  const last_send = useRef(null);

  const { sendMessage } = useWebSocket(WS_URL, {
    onOpen: () => {
      console.debug("WebSocket connection established.");
    },

    onMessage: (msg) => {
      const data = JSON.parse(msg.data);
      console.debug("Got message from websocket: ", typeof data, data);
      if ("DumpStatCountersReply" in data) {
        const counter_map = new Map<string, number>(
          Object.entries(data.DumpStatCountersReply),
        );
        console.debug(
          "Got a DumpStatCountersReply message!",
          typeof counter_map,
        );
        setCounters(counter_map);
        periodic_with_sla(
          "",
          timeout_id,
          last_send,
          min_time_between_requests_ms,
          max_time_between_requests_ms,
          sendRequest,
        );
      }
    },

    onError: () => {
      alert("Error connecting to websocket");
    },

    onClose: () => {
      console.debug("Closing websocket");
    },
  });

  // send a DumpStatCounters message one time on first load
  // TODO: why does it send @)(*%@)(% twice!? ANSWER: only in debug mode!
  useEffect(() => {
    sendRequest();
    return () => {
      // on unmount, clear the timeout, if it's set
      timeout_id && clearTimeout(timeout_id.current);
    };
  }, []);

  const sendRequest = () => {
    console.debug("Sending DumpStatCounters request");
    sendMessage(
      JSON.stringify({
        DumpStatCounters: [],
      }),
    );
    last_send.current = window.performance.now();
  };

  return (
    <>
      <SwitchHelper
        text="Thousands Seperator"
        state={thousandsSep}
        updateFn={setThousandsSep}
      />
      <TableContainer component={Paper}>
        <Table
          sx={{ minWidth: 650 }}
          size="small"
          aria-label="Table of Stat Counter enries"
        >
          <TableHead>
            <TableRow style={headerStyle}>
              <TableCell sx={headerStyleWithWidth(0.4)}>Name</TableCell>
              <TableCell sx={headerStyleWithWidth(0.15)} align="right">
                60sec
              </TableCell>
              <TableCell sx={headerStyleWithWidth(0.15)} align="right">
                600sec
              </TableCell>
              <TableCell sx={headerStyleWithWidth(0.15)} align="right">
                3600sec
              </TableCell>
              <TableCell sx={headerStyleWithWidth(0.15)} align="right">
                all
              </TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {[...reshapeCounter(counters).entries()]
              .sort((a, b) => {
                // because JS doesn't have strcmp. (only locale aware comparision)
                if (a[0] === b[0]) {
                  return 0;
                } else if (a[0] < b[0]) {
                  return -1;
                } else {
                  return 1;
                }
              })
              .map(([name, value]) => (
                <TableRow
                  key={name}
                  sx={{ "&:last-child td, &:last-child th": { border: 0 } }}
                  style={{ verticalAlign: "top" }}
                >
                  <TableCell component="th" scope="row">
                    {name}
                  </TableCell>
                  <TableCell align="right">
                    {formatValue(value.get(".60"), thousandsSep)}
                  </TableCell>
                  <TableCell align="right">
                    {formatValue(value.get(".600"), thousandsSep)}
                  </TableCell>
                  <TableCell align="right">
                    {formatValue(value.get(".3600"), thousandsSep)}
                  </TableCell>
                  <TableCell align="right">
                    {formatValue(value.get("all"), thousandsSep)}
                  </TableCell>
                </TableRow>
              ))}
          </TableBody>
        </Table>
      </TableContainer>
    </>
  );
};

export default Counters;
