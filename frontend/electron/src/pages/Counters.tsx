import React, { useState } from "react";
import { DataGrid, GridColDef, GridToolbar } from "@mui/x-data-grid";
import {
  formatValue,
  dataGridDefaultSxProp,
  reshapeCounter,
  desktop_api_url,
} from "@netdebug/common";
import { SwitchHelper } from "../components/SwitchHelper";
import { Box } from "@mui/material";
import { useLoaderData, useRevalidator } from "react-router";
import { usePeriodicRefresh } from "../usePeriodicRefresh";
import { fetchAndCheckResult } from "../common/data_loading";

export const countersLoader = async () => {
  const res = await fetchAndCheckResult(desktop_api_url("get_counters"));
  return res
    .json()
    .then((counters: object) => new Map(Object.entries(counters)));
};

const RELOAD_INTERVAL_MS = 1000;
const MAX_RELOAD_TIME = 2000;

const Counters: React.FC = () => {
  const counters = useLoaderData() as Map<string, number>;
  const [thousandsSep, setThousandsSep] = useState(true);

  // lets us re-fetch the data.
  const revalidator = useRevalidator();
  usePeriodicRefresh(
    true /* autoRefresh */,
    revalidator,
    RELOAD_INTERVAL_MS,
    "Counters",
    MAX_RELOAD_TIME,
  );

  const defaultGridColDef: {
    valueFormatter: GridColDef["valueFormatter"];
    align: GridColDef["align"];
    headerAlign: GridColDef["align"];
  } = {
    valueFormatter: (params) => formatValue(params.value, thousandsSep),
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
