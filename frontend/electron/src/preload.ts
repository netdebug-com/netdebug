import { contextBridge, ipcRenderer } from "electron";

// see https://www.electronjs.org/docs/latest/tutorial/ipc

export type NetDebugApi = {
  eulaAccepted: () => void;
};

const netdebugApi: NetDebugApi = {
  eulaAccepted: () => ipcRenderer.send("eula-accepted"),
};

contextBridge.exposeInMainWorld("netdebugApi", netdebugApi);
