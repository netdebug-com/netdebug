import { useEffect, useState } from "react";
import { useInterval } from "react-use";
import { loadData } from "../common/data_loading";
import {
  DataLoadingState,
  renderDataLoadingState,
  renderIpStringData,
} from "../common/data_loading";
import { desktop_api_url, normalTableHeaderStyle } from "../common/utils";
import TableContainer from "@mui/material/TableContainer";
import Table from "@mui/material/Table";
import {
  Paper,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
} from "@mui/material";

export const AboutDevice = () => {
  // myIp state
  const [myIp, setMyIp] = useState(new DataLoadingState<string>());
  useEffect(() => {
    loadData(desktop_api_url("get_my_ip"), setMyIp);
  }, []);
  useInterval(() => {
    loadData(desktop_api_url("get_my_ip"), setMyIp);
  }, 5000);
  // device_uuid
  const [deviceUuid, setDeviceUuid] = useState(new DataLoadingState<string>());
  useEffect(() => {
    loadData(desktop_api_url("get_device_uuid"), setDeviceUuid);
  }, []);
  useInterval(() => {
    loadData(desktop_api_url("get_device_uuid"), setDeviceUuid);
  }, 5000);

  return (
    <TableContainer sx={{ width: "60%", margin: "5px" }} component={Paper}>
      <Table size="small" aria-label="simple table">
        <TableHead sx={{ ...normalTableHeaderStyle }}>
          <TableRow sx={{ fontWeight: "bold" }}>
            <TableCell colSpan={2}>Device Details</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          <TableRow>
            <TableCell>My External IP</TableCell>
            <TableCell>{renderIpStringData(myIp)}</TableCell>
          </TableRow>
          <TableRow>
            <TableCell>Device UUID</TableCell>
            <TableCell>
              {renderDataLoadingState(deviceUuid, (s: string) => (
                <em>{s}</em>
              ))}
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>
    </TableContainer>
  );
};
