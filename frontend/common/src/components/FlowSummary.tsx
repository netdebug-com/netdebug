import { connIdString, desktop_api_url, getConnKeyForDisplay } from "../utils";
import { ConnectionKey, ConnectionMeasurements } from "../netdebug_types";
import { useState } from "react";
import Popover from "@mui/material/Popover";
import MuiLink from "@mui/material/Link";
import { Button, Stack } from "@mui/material";

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
export const FlowDetails: React.FC<FlowSummaryProps> = (props) => {
  return (
    <div style={{ padding: 20 }}>
      <Stack spacing={2} direction="row">
        <Button
          variant="outlined"
          onClick={() => request_probe_flow(props.flow.key)}
        >
          Probe Flow
        </Button>
      </Stack>
      {props.flow ? (
        <div>
          Hack! Just JSON pretty print the whole thing for now
          <pre>{JSON.stringify(props.flow, undefined, 2)}</pre>
        </div>
      ) : (
        <div>
          {" "}
          Flow Not Found: May have been expired from the local flow cache
        </div>
      )}
    </div>
  );
};

export interface FlowSummaryProps {
  flow: ConnectionMeasurements;
}

export const FlowSummary: React.FC<FlowSummaryProps> = (props) => {
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
