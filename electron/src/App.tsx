import {
  Route,
  RouterProvider,
  createHashRouter,
  createRoutesFromElements,
} from "react-router-dom";

// import sub-pages
import Home, { myIpLoader } from "./pages/Home";
import Bandwidth, { bandwidthLoader } from "./pages/Bandwidth";
import Dns, { dnsCacheLoader } from "./pages/Dns";
import Counters, { countersLoader } from "./pages/Counters";
import Flows, { flowsLoader } from "./pages/Flows";
import FlowsByDnsDomain, {
  flowsByDnsDomainLoader,
} from "./pages/FlowsByDnsDomain";

// layouts
import RootLayout from "./layouts/RootLayout";
import FlowsLayout from "./layouts/FlowsLayout";
import RouterDelays, { routerDelayLoader } from "./pages/RouteDelays";

const router = createHashRouter(
  createRoutesFromElements(
    <Route path="/" element={<RootLayout />}>
      <Route index element={<Home />} loader={myIpLoader} />,
      <Route
        path="bandwidth"
        element={<Bandwidth />}
        loader={bandwidthLoader}
      />
      <Route path="flows" element={<FlowsLayout />}>
        <Route index element={<Flows />} loader={flowsLoader} />
        <Route
          path="by_dest_domain"
          element={<FlowsByDnsDomain />}
          loader={flowsByDnsDomainLoader}
        />
        <Route path="by_app" element={<h1>By App</h1>} />
      </Route>
      <Route path="dns" element={<Dns />} loader={dnsCacheLoader} />
      <Route
        path="router_delays"
        element={<RouterDelays />}
        loader={routerDelayLoader}
      />
      <Route path="counters" element={<Counters />} loader={countersLoader} />
    </Route>,
  ),
);

function App() {
  return <RouterProvider router={router} />;
}

export default App;
