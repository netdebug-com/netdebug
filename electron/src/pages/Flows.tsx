import React from "react";
import useWebSocket from "react-use-websocket";
import { WS_URL } from "../App";

const Flows: React.FC = () => {
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
    <div>
      <h1>Flows Page</h1>
    </div>
  );
};

export default Flows;
