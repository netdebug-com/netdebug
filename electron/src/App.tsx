import {
  Route,
  RouterProvider,
  createHashRouter,
  createRoutesFromElements,
} from "react-router-dom";

// import sub-pages
import Home from "./pages/Home";
import Bandwidth from "./pages/Bandwidth";
import Dns from "./pages/Dns";
import Counters from "./pages/Counters";

// layouts
import RootLayout from "./layouts/RootLayout";
import FlowsLayout from "./layouts/FlowsLayout";
import Flows from "./pages/Flows";

const WS_URL = "ws://localhost:33434/ws";

const router = createHashRouter(
  createRoutesFromElements(
    <Route path="/" element={<RootLayout />}>
      <Route index element={<Home />} />,
      <Route path="bandwidth" element={<Bandwidth />} />
      <Route path="flows" element={<FlowsLayout />}>
        <Route index element={<Flows />} />
        <Route path="by_dest_domain" element={<h1>By Dest Domain</h1>} />
        <Route path="by_app" element={<h1>By App</h1>} />
      </Route>
      <Route path="dns" element={<Dns />} />
      <Route path="counters" element={<Counters />} />
    </Route>,
  ),
);

function App() {
  return <RouterProvider router={router} />;
}

export { WS_URL };
export default App;
