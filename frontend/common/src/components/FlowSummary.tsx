import MuiLink from "@mui/material/Link";
import Popover from "@mui/material/Popover";
import { useState } from "react";
import { LoaderFunctionArgs } from "react-router";
import { Link } from "react-router-dom";
import { fetchAndCheckResult } from "../data_loading";
import { ConnectionMeasurements } from "../netdebug_types";
import { connIdString, desktop_api_url, getConnKeyForDisplay } from "../utils";
import { FlowDetails } from "./FlowDetails";
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
