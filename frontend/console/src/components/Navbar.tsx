import Tabs from "@mui/material/Tabs";
import Tab from "@mui/material/Tab";
import { Link } from "react-router-dom";
import { useMatchNavInfo } from "../common/hooks/useMatchRouteInfo";
import { UserButton } from "@clerk/clerk-react";
import Box from "@mui/material/Box";

const TAB_NAV_INFO = [
  { label: "Home", to: "/", exactMatch: true },
  { label: "Test", to: "/test" },
  { label: "About", to: "/about" },
];

export default function Navbar() {
  const currentTab = useMatchNavInfo(TAB_NAV_INFO);
  return (
    <div>
      <Box sx={{ borderBottom: 1, borderColor: "divider" }}>
        <Tabs sx={{ marginBottom: 1 }} value={currentTab}>
          {TAB_NAV_INFO.map(({ label, to }) => {
            return (
              <Tab label={label} key={to} value={to} to={to} component={Link} />
            );
          })}
          {/* TODO: style this so it appears on all of the way on the right - how!? */}
          <UserButton />
        </Tabs>
      </Box>
    </div>
  );
}
