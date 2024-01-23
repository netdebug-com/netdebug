import {
  Route,
  RouterProvider,
  createHashRouter,
  createRoutesFromElements,
} from "react-router-dom";

// import sub-pages
import Home from "./pages/Home";
import Bandwidth, { bandwidthLoader } from "./pages/Bandwidth";
import Dns, { dnsCacheLoader } from "./pages/Dns";
import Devices, { devicesLoader } from "./pages/Devices";
import Counters, { countersLoader } from "./pages/Counters";
import Flows, { flowsLoader } from "./pages/Flows";
import FlowsByApplication, {
  flowsByApplicationLoader,
} from "./pages/FlowsByApplication";
import FlowsByDnsDomain, {
  flowsByDnsDomainLoader,
} from "./pages/FlowsByDnsDomain";

// layouts
import RootLayout from "./layouts/RootLayout";
import FlowsLayout from "./layouts/FlowsLayout";
import RouterDelays, { routerDelayLoader } from "./pages/RouteDelays";
import { DefaultErrorElement } from "./components/DefaultErrorElement";
import RttLatency, { rttLatencyLoader } from "./pages/RttLatency";
import Webtest from "./pages/Webtest";

const router = createHashRouter(
  createRoutesFromElements(
    <Route path="/" element={<RootLayout />}>
      <Route index element={<Home />} />,
      <Route
        path="bandwidth"
        element={<Bandwidth />}
        loader={bandwidthLoader}
        errorElement={<DefaultErrorElement />}
      />
      <Route path="flows" element={<FlowsLayout />}>
        <Route
          index
          element={<Flows />}
          loader={flowsLoader}
          errorElement={<DefaultErrorElement />}
        />
        <Route
          path="by_dest_domain"
          element={<FlowsByDnsDomain />}
          loader={flowsByDnsDomainLoader}
          errorElement={<DefaultErrorElement />}
        />
        <Route
          path="by_app"
          element={<FlowsByApplication />}
          loader={flowsByApplicationLoader}
          errorElement={<DefaultErrorElement />}
        />
      </Route>
      <Route
        path="rtt_latency"
        element={<RttLatency />}
        loader={rttLatencyLoader}
        errorElement={<DefaultErrorElement />}
      />
      <Route
        path="webtest"
        element={<Webtest />}
        errorElement={<DefaultErrorElement />}
      />
      <Route
        path="dns"
        element={<Dns />}
        loader={dnsCacheLoader}
        errorElement={<DefaultErrorElement />}
      />
      <Route
        path="devices"
        element={<Devices />}
        loader={devicesLoader}
        errorElement={<DefaultErrorElement />}
      />
      <Route
        path="router_delays"
        element={<RouterDelays />}
        loader={routerDelayLoader}
        errorElement={<DefaultErrorElement />}
      />
      <Route
        path="counters"
        element={<Counters />}
        loader={countersLoader}
        errorElement={<DefaultErrorElement />}
      />
    </Route>,
  ),
);

function App() {
  return <RouterProvider router={router} />;
}

export default App;
