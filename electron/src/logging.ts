import log from "electron-log/main";
import { WebSocket } from "@oznu/ws-connect";
import { LogMessage, Transport } from "electron-log";
import { DesktopLogLevel, DesktopToTopologyServer } from "./netdebug_types";
// whether we are in dev-mode or prod
import isDev from "electron-is-dev";

// Set to true to also remote log in dev mode.
// For debugging/testing the remote logging
const OVERRIDE_LOG_TO_REMOTE = false;

function setupRemoteLogging(url: string) {
  const ws = new WebSocket(url, {
    reconnectInterval: 1000, // in ms
    pingInterval: 2000, // in ms. Sends keepalive's
    options: {
      headers: { "User-Agent": "net-debug-electron" },
    },
  });
  ws.on("error", console.error);
  ws.on("websocket-status", (msg: string) =>
    process.stderr.write("Remote Logging: " + msg + "\n"),
  );
  ws.on("open", () => log.info("WS connection established"));

  const wsFormatter = makeLogFormatter(false);
  const wsTransport = (msg: LogMessage) => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const [dateStr, _level, scopeStr, ...remainder] = wsFormatter({
      message: msg,
    });

    let desktopLogLevel: DesktopLogLevel = "Info";
    switch (msg.level) {
      case "error":
        desktopLogLevel = "Error";
        break;
      case "warn":
        desktopLogLevel = "Warn";
        break;
      case "info":
        desktopLogLevel = "Info";
        break;
      default:
        desktopLogLevel = "Debug";
        break;
    }
    const wsMessage: DesktopToTopologyServer = {
      tag: "PushLog",
      data: {
        timestamp: dateStr,
        level: desktopLogLevel,
        scope: scopeStr,
        msg: remainder.join(" "),
        os: "",
        version: "",
        client_id: "",
      },
    };

    ws.send(JSON.stringify(wsMessage));
  };
  log.transports.remote_websocket = wsTransport as Transport;
}

// Function used to format log messages.
function makeLogFormatter(useColor: boolean) {
  const logFormatter = ({ message }: { message: LogMessage }) => {
    // if the log originally came from rust, we use the timestamp from
    // rust and we strip the timestamp (data[0]) and level (data[1]) from
    // the data to log (since we are going to use the electron-log level)
    const [dateStr, data, scopeStr] =
      message.scope === "rust"
        ? [message.data[0], message.data.slice(2), "[RS]"]
        : [message.date.toISOString(), message.data, "[JS]"];
    if (useColor) {
      let color = "unset"; // the default color
      switch (message.level) {
        case "info":
          color = "green";
          break;
        case "warn":
          color = "yellow";
          break;
        case "error":
          color = "red";
          break;
        default:
          color = "unset";
      }
      return [
        dateStr,
        `%c${message.level.toUpperCase()}`,
        `color: ${color}`,
        `%c${scopeStr}`,
        `color: ${color}`,
        ...data,
      ];
    } else {
      return [dateStr, message.level.toUpperCase(), scopeStr, ...data];
    }
  };
  return logFormatter;
}

export function setupNetdebugLogging(url: string) {
  // spyRendererConsole will also log any JS console messages from
  // the renderer to our logging backends
  log.initialize({ spyRendererConsole: true });

  // "Overwrite all "console.*" functions with the logger equivalent
  Object.assign(console, log.functions);

  // Default logfile locations:
  // on Linux: ~/.config/{app name}/logs/netdebug.log
  // on macOS: ~/Library/Logs/{app name}/netdebug.log
  // on Windows: %USERPROFILE%\AppData\Roaming\{app name}\logs\netdebug.log
  // Also, at least on MacOS the logs also show up in the system consiole. Likely the same is true
  // for Windows and possibly Linux (syslog)
  log.transports.file.fileName = "netdebug.log";
  // set a custom formatter
  log.transports.console.format = makeLogFormatter(true);
  log.transports.file.format = makeLogFormatter(false);
  if (!isDev || OVERRIDE_LOG_TO_REMOTE) {
    process.stderr.write("Setting up remote logging\n");
    setupRemoteLogging(url);
  } else {
    process.stderr.write("Dev Mode -- no remote logging\n");
  }

  log.info("NetDebug GUI starting up.");
}
