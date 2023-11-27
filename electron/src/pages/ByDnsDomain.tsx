import React, { useState } from "react";
import { AggregateStatEntry } from "../netdebug_types";
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
import { SwitchHelper } from "../components/SwitchHelper";
import { useWebSocketGuiToServer } from "../useWebSocketGuiToServer";

function statSortFn(a: AggregateStatEntry, b: AggregateStatEntry) {
  const max_rate_fn = (entry: AggregateStatEntry) => {
    return Math.max(
      entry.summary.tx.last_min_byte_rate,
      entry.summary.rx.last_min_byte_rate,
    );
  };
  return max_rate_fn(b) - max_rate_fn(a);
}

const Flows: React.FC = () => {
  const [statEntries, setStatEntries] = useState(
    new Array<AggregateStatEntry>(),
  );
  const [autoRefresh, setAutoRefresh] = useState(true);

  useWebSocketGuiToServer({
    autoRefresh: autoRefresh,
    reqMsgType: { DumpDnsAggregateCounters: [] },
    respMsgType: "DumpDnsAggregateCountersReply",
    min_time_between_requests_ms: 1000,
    max_time_between_requests_ms: 2000,
    responseCb: setStatEntries,
  });

  return (
    <>
      <SwitchHelper
        text={"Auto Refresh"}
        state={autoRefresh}
        updateFn={setAutoRefresh}
      />
      <TableContainer component={Paper}>
        <Table
          sx={{ minWidth: 650 }}
          size="small"
          aria-label="Table of Connections"
        >
          <TableHead>
            <TableRow style={headerStyle}>
              <TableCell sx={headerStyleWithWidth(0.6)} align="left">
                DNS Destination Domain
              </TableCell>
              <TableCell sx={headerStyleWithWidth(0.1)} align="right">
                Send Bytes
              </TableCell>
              <TableCell sx={headerStyleWithWidth(0.1)} align="right">
                Recv Bytes
              </TableCell>
              <TableCell sx={headerStyleWithWidth(0.1)} align="right">
                Send Bandwidth
              </TableCell>
              <TableCell sx={headerStyleWithWidth(0.1)} align="right">
                Recv Bandwidth
              </TableCell>
            </TableRow>
            {statEntries.sort(statSortFn).map((entry) => {
              const key =
                typeof entry.kind === "object" && "DnsDstDomain" in entry.kind
                  ? entry.kind["DnsDstDomain"]
                  : null;
              return (
                <TableRow key={key}>
                  <TableCell>{key}</TableCell>
                  <TableCell align="right">
                    {prettyPrintSiUnits(entry.summary.tx?.bytes, "B")}
                  </TableCell>
                  <TableCell align="right">
                    {prettyPrintSiUnits(entry.summary.rx?.bytes, "B")}
                  </TableCell>
                  <TableCell align="right">
                    {prettyPrintSiUnits(
                      entry.summary.tx?.last_min_byte_rate,
                      "Bytes/s",
                    )}
                  </TableCell>
                  <TableCell align="right">
                    {prettyPrintSiUnits(
                      entry.summary.rx?.last_min_byte_rate,
                      "Bytes/s",
                    )}
                  </TableCell>
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
