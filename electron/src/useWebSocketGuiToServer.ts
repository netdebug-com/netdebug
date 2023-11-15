import { useEffect, useRef } from "react";
import { GuiToServerMessages } from "./netdebug_types";
import useWebSocket from "react-use-websocket";
import { WS_URL } from "./App";
import { periodic_with_sla } from "./utils";

// The arguments passed to useWebSocketGuiToServer
export type WebSocketGuiToServerArgs<T> = {
  // Wether to automatically refresh/resend the request to the server.
  // Either a hard-coded boolean or a react state variable
  autoRefresh: boolean;
  // The type of the request message to send.
  reqMsgType: GuiToServerMessages;
  // The type of the response message. We currently just use string here
  // because we can't generate typescript types for the responses yet
  // (need to first remove some of the counter structs the old UI
  // is still using.
  respMsgType: string;
  // The callback we'll call with the parsed response.
  responseCb: (response: T) => void;
  // If auto-refresh is on: the time to wait between sending requests
  min_time_between_requests_ms: number;
  // if auto-refresh is on and it took longer than this time to refresh,
  // a warning is logged to the console
  max_time_between_requests_ms: number;
};

// React hook that wraps GuiToServer message handling. It can send a single
// type of (parameterless) request to the server/desktop and will parse and return
// the response.
// It also handles periodic refreshes
export function useWebSocketGuiToServer<T>(args: WebSocketGuiToServerArgs<T>) {
  const timeout_id = useRef(null);
  const last_send = useRef(null);

  const sendRequest = () => {
    console.debug(`Sending $reqMsgType request`);
    sendMessage(JSON.stringify(args.reqMsgType));
    last_send.current = window.performance.now();
  };

  const { sendMessage } = useWebSocket(WS_URL, {
    onOpen: () => {
      console.debug("WebSocket connection established.");
    },

    onMessage: (msg) => {
      const data = JSON.parse(msg.data);
      console.debug("Got message from websocket: ", Object.keys(data));
      if (args.respMsgType in data) {
        if (args.autoRefresh) {
          args.responseCb(data[args.respMsgType]);
          //setFlowEntries(data.DumpFlowsReply);
          periodic_with_sla(
            args.respMsgType,
            timeout_id,
            last_send,
            args.min_time_between_requests_ms,
            args.max_time_between_requests_ms,
            sendRequest,
          );
        }
      }
    },

    onError: () => {
      // If this happens, something is seriously wrong since the desktop
      // process must not be running
      alert("Error connecting to websocket");
    },

    onClose: () => {
      console.debug("Closing websocket");
    },
  });

  useEffect(() => {
    if (args.autoRefresh) {
      sendRequest();
    }
    return () => {
      // on unmount, clear the timeout, if it's set
      timeout_id && clearTimeout(timeout_id.current);
    };
  }, [args.autoRefresh]);
}
