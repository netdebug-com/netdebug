import { getConnKeyForDisplay } from "../utils";
import { ConnectionMeasurements } from "../netdebug_types";
import { useState } from "react";
import Popover from "@mui/material/Popover";
import Button from "@mui/material/Button";

// Re-usable components to show the detailed information in a flow
// Assumes we already have the corresponding connection measurement
// The 'FlowSummary' is a one-line description of the flow - suitable for a list, but it's clickable
// so that it can popover a more detailed analysys of that flow

export const FlowDetails: React.FC<FlowSummaryProps> = (props) => {
  return (
    <div>
      Hack! Just JSON pretty print the whole thing for now
      <pre>{JSON.stringify(props.flow, undefined, 2)}</pre>
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
  return (
    <div>
      <Button aria-describedby={id} onClick={handleClick}>
        {getConnKeyForDisplay(props.flow)}
      </Button>
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
