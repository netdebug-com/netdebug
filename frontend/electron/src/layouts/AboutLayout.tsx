import { ToggleButton, ToggleButtonGroup } from "@mui/material";
import {
  NavInfo,
  useMatchNavInfo,
} from "../../../common/src/hooks/useMatchRouteInfo";
import React from "react";
import { Link, Outlet } from "react-router-dom";

const ABOUT_INFOS: NavInfo[] = [
  { label: "Release Notes", to: "", exactMatch: true },
  { label: "Internal Counters", to: "counters" },
  { label: "Device", to: "about_device" },
];

const AboutNav: React.FC = () => {
  let curSelected = useMatchNavInfo(ABOUT_INFOS);
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
          {ABOUT_INFOS.map(({ label, to }) => {
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
export default AboutNav;
