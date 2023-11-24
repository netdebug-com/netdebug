import { HashRouter, Route, Routes } from "react-router-dom";
import Navbar from "./Navbar";

import useWebSocket from "react-use-websocket";

// import sub-pages
import Home from "./pages/Home";
import Bandwidth from "./pages/Bandwidth";
import Dns from "./pages/Dns";
import Counters from "./pages/Counters";
import FlowsNav from "./FlowsNav";

const WS_URL = "ws://localhost:33434/ws";

function App() {
  return (
    <HashRouter>
      <div>
        <Navbar />
        <Routes>
          <Route index element={<Home />} />
          <Route path="/bandwidth" element={<Bandwidth />} />
          <Route path="/flows/*" element={<FlowsNav />} />
          <Route path="/dns" element={<Dns />} />
          <Route path="/counters" element={<Counters />} />
        </Routes>
      </div>
    </HashRouter>
  );
}

export { WS_URL };
export default App;
