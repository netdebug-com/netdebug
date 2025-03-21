import { ToggleButton, ToggleButtonGroup } from "@mui/material";
import React from "react";
import { Link, Outlet } from "react-router-dom";
import { NavInfo, useMatchNavInfo } from "../common/hooks/useMatchRouteInfo";

const FLOW_ROUTE_INFOS: NavInfo[] = [
  { label: "By DNS Domain", to: "", exactMatch: true },
  { label: "By App", to: "by_app" },
  { label: "By Host / Latency", to: "by_host_latency" },
  { label: "By Flows", to: "by_flow", exactMatch: true },
];

const FlowsNav: React.FC = () => {
  let curSelected = useMatchNavInfo(FLOW_ROUTE_INFOS);
  if (!curSelected) {
    curSelected = "";
  }
  return (
    <div>
      <nav>
        <ToggleButtonGroup
          color="primary"
          value={curSelected}
          exclusive
          aria-label="Flow Groupings"
        >
          {FLOW_ROUTE_INFOS.map(({ label, to }) => {
            return (
              <ToggleButton component={Link} to={to} key={to} value={to}>
                {label}
              </ToggleButton>
            );
          })}
        </ToggleButtonGroup>
      </nav>
      <Outlet />
    </div>
  );
};
export default FlowsNav;
