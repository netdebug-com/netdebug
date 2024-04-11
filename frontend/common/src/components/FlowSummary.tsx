import { Button, Stack } from "@mui/material";
import MuiLink from "@mui/material/Link";
import Popover from "@mui/material/Popover";
import { useState } from "react";
import {
  LoaderFunctionArgs,
  useLoaderData,
  useNavigate,
  useRevalidator,
} from "react-router";
import { Link } from "react-router-dom";
import { fetchAndCheckResult } from "../data_loading";
import { ConnectionKey, ConnectionMeasurements } from "../netdebug_types";
import { connIdString, desktop_api_url, getConnKeyForDisplay } from "../utils";
import { usePeriodicRefresh } from "../hooks/usePeriodicRefresh";
import { SwitchHelper } from "./SwitchHelper";

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
      <div>
        Hack! Just JSON pretty print the whole thing for now
        <pre>{JSON.stringify(props.flow, undefined, 2)}</pre>
      </div>
    </div>
  );
};

// wrapper around FlowDetails when called by the loader
export const FlowDetailsByParam: React.FC = () => {
  const flow = useLoaderData() as ConnectionMeasurements;
  return <FlowDetails flow={flow} />;
};

export interface FlowSummaryProps {
  flow: ConnectionMeasurements;
}

export interface FlowIdProps {
  conn_id: string;
}

export const flowByIdLoader = async ({
  params,
}: LoaderFunctionArgs<string>) => {
  const res = await fetchAndCheckResult(
    desktop_api_url("get_one_flow/" + params.conn_id),
  );
  return res.json();
};

export const FlowSummaryLink: React.FC<FlowSummaryProps> = (props) => {
  const flow_closed = props.flow.close_has_started;
  const flow_url = "/flows/one_flow/" + connIdString(props.flow.key);
  return (
    <div>
      {/* Link to the more detailed flow information by the connId of this flow */}
      <Link to={flow_url}>
        {
          // if a flow is closed, render it with strikethrough
          flow_closed ? (
            <s>{getConnKeyForDisplay(props.flow)}</s>
          ) : (
            getConnKeyForDisplay(props.flow)
          )
        }
      </Link>
    </div>
  );
};

export const FlowSummaryPopUp: React.FC<FlowSummaryProps> = (props) => {
  // copied from example at : https://mui.com/material-ui/react-popover/
  const [anchorEl, setAnchorEl] = useState<HTMLButtonElement | null>(null);

  const handleClick = (event: React.MouseEvent<HTMLButtonElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const open = Boolean(anchorEl);
  const id = open ? "simple-popover" : undefined;
  const flow_closed = props.flow.close_has_started;
  return (
    <div>
      <MuiLink
        component="button"
        underline="hover"
        aria-describedby={id}
        onClick={handleClick}
      >
        {
          // if a flow is closed, render it with strikethrough
          flow_closed ? (
            <s>{getConnKeyForDisplay(props.flow)}</s>
          ) : (
            getConnKeyForDisplay(props.flow)
          )
        }
      </MuiLink>
      <Popover
        id={id}
        open={open}
        anchorEl={anchorEl}
        onClose={handleClose}
        anchorOrigin={{
          vertical: "bottom",
          horizontal: "left",
        }}
      >
        <FlowDetails flow={props.flow} />
      </Popover>
    </div>
  );
};

/**
 * TODO : create a wraper DynamicFlowDetails that takes a key and a websocket and
 * dynamically pulls the key from the server and renders it...
 */
