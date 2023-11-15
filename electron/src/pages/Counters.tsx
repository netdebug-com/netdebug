import React, { useState } from "react";
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
  reshapeCounter,
} from "../utils";
import { SwitchHelper } from "../SwitchHelper";
import { useWebSocketGuiToServer } from "../useWebSocketGuiToServer";

const Counters: React.FC = () => {
  const [counters, setCounters] = useState(new Map<string, number>());
  const [thousandsSep, setThousandsSep] = useState(true);

  const setCountersWrapper = (counters: object) => {
    setCounters(new Map(Object.entries(counters)));
  };

  useWebSocketGuiToServer({
    autoRefresh: true,
    reqMsgType: { DumpStatCounters: [] },
    respMsgType: "DumpStatCountersReply",
    min_time_between_requests_ms: 1000,
    max_time_between_requests_ms: 2000,
    responseCb: setCountersWrapper,
  });

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
