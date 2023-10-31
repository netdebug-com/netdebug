import { LinkContainer } from "react-router-bootstrap";
import { HashRouter, Route, Routes } from "react-router-dom";
import Container from "react-bootstrap/Container";
import Nav from "react-bootstrap/Nav";
import Navbar from "react-bootstrap/Navbar";
// import NavDropdown from "react-bootstrap/NavDropdown";
import Button from "react-bootstrap/Button";

import useWebSocket from "react-use-websocket";

// import CSS
import "bootstrap/dist/css/bootstrap.min.css";

// import sub-pages
import Home from "./pages/Home";
import Flows from "./pages/Flows";
import Bandwidth from "./pages/Bandwidth";
import Dns from "./pages/Dns";

// https://codesandbox.io/s/github/react-bootstrap/code-sandbox-examples/tree/master/basic-react-router-v5?file=/src/App.js:143-188
function NetDebugNavbar() {
  return (
    <Navbar className="nav-tabs">
      <Container>
        <LinkContainer to="">
          <Nav.Link href="">NetDebug</Nav.Link>
        </LinkContainer>
        <LinkContainer to="/bandwidth">
          <Nav.Link href="/bandwidth">Bandwidth</Nav.Link>
        </LinkContainer>
        <LinkContainer to="/flows">
          <Nav.Link href="/flows">Flows</Nav.Link>
        </LinkContainer>
        <LinkContainer to="/dns">
          <Nav.Link href="/dns">DNS</Nav.Link>
        </LinkContainer>
      </Container>
    </Navbar>
  );
}

const WS_URL = "ws://localhost:33434/ws";

function App() {
  useWebSocket(WS_URL, {
    onOpen: () => {
      console.log("WebSocket connection established.");
    },

    onMessage: (msg) => {
      console.log("Got message from websocket: ", msg.data);
    },
    onClose: (msg) => {
      console.log("Closing websocket");
    },
  });
  return (
    <HashRouter>
      <div>
        <NetDebugNavbar />
        <Routes>
          <Route path="" element={<Home />} />
          <Route path="/bandwidth" element={<Bandwidth />} />
          <Route path="/flows" element={<Flows />} />
          <Route path="/dns" element={<Dns />} />
        </Routes>
      </div>
    </HashRouter>
  );
}

export { WS_URL };
export default App;
