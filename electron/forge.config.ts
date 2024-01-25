import type { ForgeConfig } from "@electron-forge/shared-types";
import { MakerSquirrel } from "@electron-forge/maker-squirrel";
import { MakerZIP } from "@electron-forge/maker-zip";
//import { MakerDeb } from "@electron-forge/maker-deb";
//import { MakerRpm } from "@electron-forge/maker-rpm";
import { AutoUnpackNativesPlugin } from "@electron-forge/plugin-auto-unpack-natives";
import { WebpackPlugin } from "@electron-forge/plugin-webpack";

import { mainConfig } from "./webpack.main.config";
import { rendererConfig } from "./webpack.renderer.config";

const config: ForgeConfig = {
  packagerConfig: {
    asar: true,
    extraResource: "extra-resources",
    // see https://www.electronforge.io/guides/create-and-add-icons
    // extensions is automatically added based on target platform:
    // .icns for Mac; .ico for Windows. joy
    icon: "src/images/icon",
  },
  rebuildConfig: {},
  makers: [
    new MakerSquirrel({}),
    new MakerZIP({}, ["darwin"]),
    // disable linux for now
    // new MakerRpm({}),
    // new MakerDeb({}),
  ],
  plugins: [
    new AutoUnpackNativesPlugin({}),
    new WebpackPlugin({
      mainConfig,
      // deault-src: Need this otherwise I can't connect to websocket in dev mode?!?!
      // see https://stackoverflow.com/questions/70132291/electron-content-security-policy-error-when-connecting-to-my-api
      // #black-magic
      // frame-src: see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-src
      //            specify which domains can be opened in iframes
      devContentSecurityPolicy:
        "default-src 'self' 'unsafe-eval' 'unsafe-inline' http://localhost:* ws://localhost:*;" +
        "frame-src 'self' *.topology.netdebug.com topology.netdebug.com",
      renderer: {
        config: rendererConfig,
        entryPoints: [
          {
            html: "./src/index.html",
            js: "./src/renderer.tsx",
            name: "main_window",
            preload: {
              js: "./src/preload.ts",
            },
          },
        ],
      },
    }),
  ],
};

export default config;
