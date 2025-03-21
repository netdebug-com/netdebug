import Tabs from "@mui/material/Tabs";
import Tab from "@mui/material/Tab";
import { Link } from "react-router-dom";
import { useMatchNavInfo } from "../../../common/src/hooks/useMatchRouteInfo";

const TAB_NAV_INFO = [
  { label: "Home", to: "/", exactMatch: true },
  { label: "Local", to: "/local_network" },
  { label: "Bandwidth", to: "/bandwidth" },
  { label: "DNS", to: "/dns" },
  { label: "Devices", to: "/devices" },
  { label: "Flows", to: "/flows" },
  { label: "Webtest", to: "/webtest" },
  { label: "Router Delays", to: "/router_delays" },
  { label: "About", to: "/about" },
];

export default function Navbar() {
  const currentTab = useMatchNavInfo(TAB_NAV_INFO);
  return (
    <Tabs sx={{ marginBottom: 1 }} value={currentTab}>
      {TAB_NAV_INFO.map(({ label, to }) => {
        return (
          <Tab label={label} key={to} value={to} to={to} component={Link} />
        );
      })}
    </Tabs>
  );
}
