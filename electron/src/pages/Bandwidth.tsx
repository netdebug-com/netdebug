import React from "react";
import { useParams } from "react-router-dom";
import useWebSocket from "react-use-websocket";
import { WS_URL } from "../App";

const Bandwidth: React.FC = () => {
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
      <h1>Bandwidth Page</h1>
    </div>
  );
};

export default Bandwidth;
