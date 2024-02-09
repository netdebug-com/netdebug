import { app, BrowserWindow, dialog } from "electron";
import { ChildProcess, spawn, SpawnOptions } from "child_process";
import log from "electron-log/main";
import path from "node:path";
// This allows TypeScript to pick up the magic constants that's auto-generated by Forge's Webpack
// plugin that tells the Electron app where to look for the Webpack-bundled app code (depending on
// whether you're running in development or production).
declare const MAIN_WINDOW_WEBPACK_ENTRY: string;
declare const MAIN_WINDOW_PRELOAD_WEBPACK_ENTRY: string;

// Handle creating/removing shortcuts on Windows when installing/uninstalling.
if (require("electron-squirrel-startup")) {
  app.quit();
}

// whether we are in dev-mode or prod
import isDev from "electron-is-dev";

const MAX_RESTARTS = 5;
let desktopProcess: ChildProcess = undefined;
let numRestarts = 0;

// setup config for autoUpdate, following https://github.com/electron/update-electron-app
import { updateElectronApp, UpdateSourceType } from "update-electron-app";
import { setupNetdebugLogging } from "./logging";

/*** 
 * A set of things I tried (unsuccessfully!) to get local-testing of upgrades with
 * self-signed certificates to work. 
 * Leaving it here to try again/more/harder in the future.
 * 
 * What a PITA
// DO NOT SET TO 'true' for production; super insecure
const debug_upgrade = true;
//(in theory) allow a the self signed certificate if debugging upgrade
// in practice and many hours later, non of this works... leaving it here
// in case someone else can
if (debug_upgrade) {
  // lots of work arounds at: https://stackoverflow.com/questions/38986692/how-do-i-trust-a-self-signed-certificate-from-an-electron-app
  // NOTE: when debugging upgrade issues, Electron creates a txt *file* in the
  // same directory as the binary, e.g., on windows it's:
  // $USER/AppData/Local/net_debug/Squirrel-CheckForUpdate
  app.commandLine.appendSwitch("ignore-certificate-errors");

  // /* This does nothing; apparently outdated stack-overflow wisdom
  app.on(
    "certificate-error",
    (event, webContents, url, error, certificate, callback) => {
      console.log("Checking certificate... YAY?");
      // On certificate error we disable default behaviour (stop loading the page)
      // and we then say "it is all fine - true" to the callback
      event.preventDefault();
      callback(true);
    },
  );
  //
}
*/

setupNetdebugLogging("wss://topology.netdebug.com:443/desktop");
// for local debug:
// setupNetdebugLogging("ws://localhost:3030/desktop");

updateElectronApp({
  updateSource: {
    type: UpdateSourceType.StaticStorage,
    // url must be 'https' or will assert()
    // NOTE: on my machine at least, we have to hardcode '127.0.0.1' because the PITA
    // python webserver won't bind a v4+v6 addr easily
    baseUrl:
      // NOTE: must use backticks and not quotes for variables to expand!
      `https://topology.netdebug.com:443/static/updater_235235/${process.platform}/${process.arch}`,
    // This triggers a GET of
    // "/static/updater_235235/win32/x64/RELEASES?id=net_debug&localVersion=0.0.1&arch=amd64 HTTP/1.1"
  },
  // defaults to checking every 10m; seems fine for now
  notifyUser: true, // this is the default, but be explicit
});

// Create the browser window.
const createWindow = (): void => {
  const mainWindow = new BrowserWindow({
    height: 800,
    width: 1200,
    autoHideMenuBar: true,
    webPreferences: {
      preload: MAIN_WINDOW_PRELOAD_WEBPACK_ENTRY,
    },
  });

  // and load the index.html of the app.
  mainWindow.loadURL(MAIN_WINDOW_WEBPACK_ENTRY);

  // Open the DevTools.
  if (isDev) {
    mainWindow.webContents.openDevTools();
  }
};

let panicMsg = "";
let isInPanicMsg = false;

function spawn_desktop_binary(command: string) {
  const args: string[] = [
    // default to connecting to a local webserver/topology server on ws://localhost:3030/desktop
  ];
  const options: SpawnOptions = { stdio: "pipe", windowsHide: true };
  desktopProcess = spawn(command, args, options);
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  desktopProcess.on("exit", (code, signal) => {
    numRestarts += 1;
    if (numRestarts > MAX_RESTARTS) {
      // TODO: looks like this exception triggers a dialog for an uncaught exception but doesn't
      // terminate the app. Fine for now but eventually we want to this more nicely: display
      // error and when user clicks "Ok", close the app.
      dialog.showErrorBox(
        "Background Process Failed",
        "Desktop background process failed too many times. Giving up: " +
          panicMsg,
      );
      app.quit();
    } else {
      console.error(
        "Desktop binary exited (crashed?) with: " + code + ". Restarting",
      );
      isInPanicMsg = false;
      panicMsg = "";
      spawn_desktop_binary(command);
    }
  });
  desktopProcess.on("error", (err) => {
    console.error("Failed to spawn background process:", err);
  });
  desktopProcess.on("spawn", () => {
    console.log("Successfully spawned background process");
  });
  // TODO: should we do anything with stdout??
  desktopProcess.stderr.setEncoding("utf-8");
  desktopProcess.stderr.on("data", (chunk: string) => {
    const logscope = log.scope("rust");
    chunk
      .replace(/\r?\n$/, "") // remove final newline
      .split(/\r?\n/)
      .forEach((line) => {
        // Hacky trick to extract the panic messages from everything going on
        // on stderr
        if (line === "##PANIC-MSG-END##") {
          isInPanicMsg = false;
        }
        if (isInPanicMsg) {
          panicMsg += line + "\n";
        }
        if (line === "##PANIC-MSG-START##") {
          isInPanicMsg = true;
        }
        const parts = line.split(" ");
        switch (parts[1]) {
          case "WARN":
            logscope.warn(...parts);
            break;
          case "ERROR":
            logscope.error(...parts);
            break;
          case "DEBUG":
            logscope.debug(...parts);
            break;
          default:
            logscope.log(...parts);
        }
      });
  });
}

// This method will be called when Electron has finished
// initialization and is ready to create browser windows.
// Some APIs can only be used after this event occurs.
app.on("ready", () => {
  // In a production build `process.resourcePath` will point to the resource directory
  // (see `extraResource` in `forge.config.ts`. However, in prod it points to a useless
  // place. Instead we start from __dirname (which points to `.webpack/main/` and go
  // to extra-resources.
  let resourcePath = process.resourcesPath;
  if (isDev) {
    resourcePath = path.join(__dirname, "..", "..");
  }
  const desktop_binary = path.join(resourcePath, "extra-resources", "desktop");
  console.log("Using desktop rust binary", desktop_binary);
  spawn_desktop_binary(desktop_binary);

  createWindow();
});

// Quit when all windows are closed, except on macOS. There, it's common
// for applications and their menu bar to stay active until the user quits
// explicitly with Cmd + Q.
// TODO: should change this
app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});

// We're about to shutdown. Kill the desktop process and remove its exit
// handler so we don't resapwn it.
app.on("will-quit", () => {
  console.log("About to quit");
  if (desktopProcess !== undefined) {
    desktopProcess.removeAllListeners("exit");
    desktopProcess.kill();
  }
});

app.on("activate", () => {
  // On OS X it's common to re-create a window in the app when the
  // dock icon is clicked and there are no other windows open.
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});
