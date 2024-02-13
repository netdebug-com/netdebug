import type { NetDebugApi } from "./preload";

declare global {
  interface Window {
    netdebugApi: NetDebugApi;
  }
}
