import WebSocket from "ws";
import log from "electron-log/main";
import { LogMessage, Transport } from "electron-log";
import { DesktopLogLevel, DesktopToTopologyServer } from "./netdebug_types";

export function setupNetdebugLogging(url: string) {
  const ws = new WebSocket(url, undefined, {
    headers: { "User-Agent": "net-debug-electron" },
  });
  ws.on("error", console.error);
  ws.on("open", () => log.info("WS connection established"));

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

  // spyRendererConsole will also log any JS console messages from
  // the renderer to our logging backends
  log.initialize({ spyRendererConsole: true });

  // "Overwrite all "console.*" functions with the logger equivalent
  Object.assign(console, log.functions);

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

    if (ws.readyState === ws.OPEN) {
      ws.send(JSON.stringify(wsMessage));
    } else if (ws.readyState !== ws.CONNECTING) {
      // don't use console, otherwise we get the messag right back in an infinte loop :-/
      process.stderr.write("WARNING: Can't write to logging websocket\n");
    }
  };

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
  log.transports.foo = wsTransport as Transport;
  log.info("NetDebug GUI starting up.");
}
