import React from "react";
import { Link } from "react-router-dom";
import useWebSocket from "react-use-websocket";
import { WS_URL } from "../App";

const Home: React.FC = () => {
  useWebSocket(WS_URL, {
    onOpen: () => {
      console.log("WebSocket connection established.");
    },

    onMessage: (msg) => {
      console.log("Got message from websocket: ", msg.data);
    },

	onClose: (msg) => {
      console.log("Closing websocket");
	}
  });
  return (
    <div>
      <h1>Home Page</h1>
      <Link to="flows">Flows</Link>
    </div>
  );
};

export default Home;
