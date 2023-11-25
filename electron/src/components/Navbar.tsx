import Tabs from "@mui/material/Tabs";
import Tab from "@mui/material/Tab";
import { Link } from "react-router-dom";
import { useMatchNavInfo } from "../router_utils";

const TAB_NAV_INFO = [
  { label: "Home", to: "/", exactMatch: true },
  { label: "Bandwidth", to: "/bandwidth" },
  { label: "DNS", to: "/dns" },
  { label: "Flows", to: "/flows" },
  { label: "Counters", to: "/counters" },
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
