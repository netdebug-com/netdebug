import React, { useEffect, useRef, useState } from "react";
import useWebSocket from "react-use-websocket";
import { WS_URL } from "../App";

const Home: React.FC = () => {
  const [myIp, setMyIp] = useState("Loading...");
  const last_send = useRef(null);
  useEffect(() => {
    sendRequest();
  }, []);

  const { sendMessage } = useWebSocket(WS_URL, {
    onOpen: () => {
      console.debug("WebSocket connection established.");
    },
    onMessage: (msg) => {
      const parsed = JSON.parse(msg.data);
      if (parsed.tag == "WhatsMyIpReply") {
        setMyIp(parsed.data.ip);
      }
    },
    onClose: () => {
      console.debug("Closing websocket");
    },
  });

  const sendRequest = () => {
    console.debug("Sending WhatsMyIp request");
    sendMessage(
      JSON.stringify({
        tag: "WhatsMyIp",
      }),
    );
    last_send.current = window.performance.now();
  };

  return (
    <div>
      <h1>Home Page</h1>
      My external IP Address is <em>{myIp}</em>.
    </div>
  );
};

export default Home;
