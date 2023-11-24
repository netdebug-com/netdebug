import { ToggleButton, ToggleButtonGroup } from "@mui/material";
import React from "react";
import { Routes, Route, Link } from "react-router-dom";
import { NavInfo, useMatchNavInfo } from "./router_utils";
import Flows from "./pages/Flows";

const FLOW_ROUTE_INFOS: NavInfo[] = [
  { label: "By Flows", to: "", exactMatch: true },
  { label: "By DNS Domain", to: "by_dest_domain" },
  { label: "By App", to: "by_app" },
];

const FlowsNav: React.FC = () => {
  let curSelectedRoute = useMatchNavInfo(FLOW_ROUTE_INFOS);
  if (!curSelectedRoute) {
    curSelectedRoute = "";
  }
  return (
    <div>
      <div>
        <ToggleButtonGroup
          color="primary"
          value={curSelectedRoute}
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
      </div>
      <Routes>
        <Route index element={<Flows />} />
        <Route path="by_dest_domain" element={<h1>By Dest Domain</h1>} />
        <Route path="by_app" element={<h1>By App</h1>} />
      </Routes>
    </div>
  );
};
export default FlowsNav;
