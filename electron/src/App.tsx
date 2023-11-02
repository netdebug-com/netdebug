import { HashRouter, Route, Routes } from "react-router-dom";
import Navbar from "./Navbar";

import useWebSocket from "react-use-websocket";

// import sub-pages
import Home from "./pages/Home";
import Flows from "./pages/Flows";
import Bandwidth from "./pages/Bandwidth";
import Dns from "./pages/Dns";

const WS_URL = "ws://localhost:33434/ws";

function App() {
  useWebSocket(WS_URL, {
    onOpen: () => {
      console.log("WebSocket connection established.");
    },

    onMessage: (msg) => {
      console.log("Got message from websocket: ", msg.data);
    },
    onClose: () => {
      console.log("Closing websocket");
    },
  });
  return (
    <HashRouter>
      <div>
        <Navbar />
        <Routes>
          <Route path="" element={<Home />} />
          <Route path="/bandwidth" element={<Bandwidth />} />
          <Route path="/flows" element={<Flows />} />
          <Route path="/dns" element={<Dns />} />
          <Route path="/counters" element={<h1> TODO COUNTERS </h1>} />
        </Routes>
      </div>
    </HashRouter>
  );
}

export { WS_URL };
export default App;
