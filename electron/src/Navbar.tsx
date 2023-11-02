import Tabs from "@mui/material/Tabs";
import Tab from "@mui/material/Tab";
import { Link, matchPath, useLocation } from "react-router-dom";

const TabData = [
  ["Home", "/"],
  ["Bandwidth", "/bandwidth"],
  ["DNS", "/dns"],
  ["Flows", "/flows"],
  ["(Counters)", "/counters"],
];

function useRouteMatch(patterns: readonly string[]) {
  const { pathname } = useLocation();

  for (let i = 0; i < patterns.length; i += 1) {
    const pattern = patterns[i];
    const possibleMatch = matchPath(pattern, pathname);
    if (possibleMatch !== null) {
      return possibleMatch;
    }
  }

  return null;
}

export default function MyTabs() {
  const paths = TabData.map((tab) => tab[1]);
  const routeMatch = useRouteMatch(paths);
  const currentTab = routeMatch?.pattern?.path;
  return (
    <Tabs value={currentTab}>
      {TabData.map(([label, dst]) => {
        return (
          <Tab label={label} key={dst} value={dst} to={dst} component={Link} />
        );
      })}
    </Tabs>
  );
}
