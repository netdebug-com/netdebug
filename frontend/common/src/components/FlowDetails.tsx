import { Button, Stack } from "@mui/material";
import { ConnectionKey, ConnectionMeasurements } from "../netdebug_types";
import { usePeriodicRefresh } from "../hooks/usePeriodicRefresh";
import { SwitchHelper } from "./SwitchHelper";
import { connIdString, desktop_api_url } from "../utils";
import { FlowSummaryProps } from "./FlowSummary";
import { useLoaderData, useNavigate, useRevalidator } from "react-router-dom";
import { useState } from "react";

function request_probe_flow(connId: ConnectionKey) {
  const url = desktop_api_url("probe_flow") + "/" + connIdString(connId);
  fetch(url)
    .then((res) => {
      if (!res.ok) {
        res.text().then((textMsg) => {
          console.error(
            "Failed to request probe_flow:",
            res.status,
            res.statusText,
            ":",
            textMsg,
          );
        });
      }
    })
    .catch((err) => {
      console.error(err.message);
    });
}

// Re-usable components to show the detailed information in a flow
// Assumes we already have the corresponding connection measurement
// The 'FlowSummary' is a one-line description of the flow - suitable for a list, but it's clickable
// so that it can popover a more detailed analysys of that flow
const RELOAD_INTERVAL_MS = 1000;
const MAX_RELOAD_TIME = 2000;

export const FlowDetails: React.FC<FlowSummaryProps> = (props) => {
  const navigate = useNavigate();
  const [autoRefresh, setAutoRefresh] = useState(true);
  const revalidator = useRevalidator();
  usePeriodicRefresh(
    autoRefresh,
    revalidator,
    RELOAD_INTERVAL_MS,
    "Flow Details",
    MAX_RELOAD_TIME,
  );
  return (
    <div style={{ padding: 20 }}>
      <Stack spacing={2} direction="row">
        <SwitchHelper
          text={"Auto Refresh"}
          state={autoRefresh}
          updateFn={setAutoRefresh}
        />
        <Button
          variant="outlined"
          onClick={() => request_probe_flow(props.flow.key)}
        >
          Probe Flow
        </Button>
        <Button variant="outlined" onClick={() => navigate(-1)}>
          Back
        </Button>
      </Stack>
      {props.flow ? (
        <div>
          Hack! Just JSON pretty print the whole thing for now
          <pre>{JSON.stringify(props.flow, undefined, 2)}</pre>
        </div>
      ) : (
        <div> Flow not found: Probably expired from the local cache </div>
      )}
    </div>
  );
};

// wrapper around FlowDetails when called by the loader
export const FlowDetailsByParam: React.FC = () => {
  const flow = useLoaderData() as ConnectionMeasurements;
  return <FlowDetails flow={flow} />;
};
