import { app, BrowserWindow } from "electron";
import { ChildProcess, spawn, SpawnOptions } from "child_process";
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

function spawn_desktop_binary(command: string) {
  const args: string[] = [
    // default to connecting to a local webserver/topology server on ws://localhost:3030/desktop
  ];
  const options: SpawnOptions = { stdio: "inherit", windowsHide: true };
  desktopProcess = spawn(command, args, options);
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  desktopProcess.on("exit", (code, signal) => {
    numRestarts += 1;
    if (numRestarts > MAX_RESTARTS) {
      // TODO: looks like this exception triggers a dialog for an uncaught exception but doesn't
      // terminate the app. Fine for now but eventually we want to this more nicely: display
      // error and when user clicks "Ok", close the app.
      throw new Error(
        "Desktop background process failed to many times. Giving up",
      );
    } else {
      console.warn(
        "Desktop binary exited (crashed?) with: " + code + ". Restarting",
      );
      spawn_desktop_binary(command);
    }
  });
  desktopProcess.on("error", (err) => {
    console.error("Failed to spawn background process:", err);
  });
  desktopProcess.on("spawn", () => {
    console.log("Successfully spawned background process");
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
