import React, { useState } from "react";
import {
  DataGrid,
  GridColDef,
  GridToolbar,
  GridValueFormatterParams,
} from "@mui/x-data-grid";
import { formatValue, dataGridDefaultSxProp, reshapeCounter } from "../utils";
import { SwitchHelper } from "../components/SwitchHelper";
import { useWebSocketGuiToServer } from "../useWebSocketGuiToServer";
import { Box } from "@mui/material";

const Counters: React.FC = () => {
  const [counters, setCounters] = useState(new Map<string, number>());
  const [thousandsSep, setThousandsSep] = useState(true);

  const setCountersWrapper = (counters: object) => {
    setCounters(new Map(Object.entries(counters)));
  };

  const defaultGridColDef: {
    valueFormatter: GridColDef["valueFormatter"];
    align: GridColDef["align"];
    headerAlign: GridColDef["align"];
  } = {
    valueFormatter: (params: GridValueFormatterParams<number>) =>
      formatValue(params.value, thousandsSep),
    align: "right",
    headerAlign: "right",
  };
  const columns: GridColDef[] = [
    {
      field: "id",
      hideable: false,
      headerName: "Name",
      flex: 40,
    },
    {
      field: "t60",
      headerName: "60 sec",
      flex: 15,
      ...defaultGridColDef,
    },
    {
      field: "t600",
      headerName: "600 sec",
      type: "number",
      flex: 15,
      ...defaultGridColDef,
    },
    {
      field: "t3600",
      headerName: "3600 sec",
      flex: 15,
      ...defaultGridColDef,
    },
    {
      field: "all",
      headerName: "all",
      flex: 15,
      ...defaultGridColDef,
    },
  ];

  useWebSocketGuiToServer({
    autoRefresh: false,
    reqMsgType: { tag: "DumpStatCounters" },
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
      <Box width="100%">
        <DataGrid
          aria-label="Table of Stat Counter entries"
          density="compact"
          sx={{
            width: "100%",
            maxWidth: 1200,
            ...dataGridDefaultSxProp,
          }}
          rows={reshapeCounter(counters)}
          columns={columns}
          initialState={{
            sorting: {
              sortModel: [{ field: "id", sort: "asc" }],
            },
          }}
          slots={{
            toolbar: GridToolbar,
          }}
          slotProps={{
            toolbar: { printOptions: { disableToolbarButton: true } },
          }}
        />
      </Box>
    </>
  );
};

export default Counters;
