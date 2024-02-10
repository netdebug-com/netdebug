import type { ForgeConfig } from "@electron-forge/shared-types";
import { MakerSquirrel } from "@electron-forge/maker-squirrel";
import { MakerZIP } from "@electron-forge/maker-zip";
import { MakerDMG } from "@electron-forge/maker-dmg";
//import { MakerDeb } from "@electron-forge/maker-deb";
//import { MakerRpm } from "@electron-forge/maker-rpm";
import { AutoUnpackNativesPlugin } from "@electron-forge/plugin-auto-unpack-natives";
import { WebpackPlugin } from "@electron-forge/plugin-webpack";
import path from "path/posix";

import { mainConfig } from "./webpack.main.config";
import { rendererConfig } from "./webpack.renderer.config";

const config: ForgeConfig = {
  packagerConfig: {
    osxSign: {}, // object needs to exist even if empty
    osxNotarize: {
      tool: "notarytool",
      // TODO: Use Gregor's personal appleId & developer account for now until
      // we can figure out the corp one.
      // I've store my credentials in my keychain with:
      // xcrun notarytool store-credentials "notarytool-credential-personal"
      //    --apple-id "<AppleID>"
      //    --team-id <DeveloperTeamID>
      //    --password <secret_password>
      // see https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution/customizing_the_
      keychainProfile: "notarytool-credential-personal",
    },
    osxUniversal: {
      // config options for `@electron/universal`
      // Needed, otherwise I get:
      // Error: Detected file "Contents/Resources/extra-resources/desktop" that's the same in both
      //        x64 and arm64 builds and not covered by the x64ArchFiles rule: "undefined"
      x64ArchFiles: "*",
    },
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
    new MakerZIP(
      {
        macUpdateManifestBaseUrl:
          "https://topology.netdebug.com/static/updater_235235/darwin/universal",
      },
      ["darwin"],
    ),
    new MakerDMG({
      icon: "src/images/icon.icns",
      iconSize: 100,
      // should be 658 × 498
      background: "assets/background.png",
      debug: true,
      contents: (opts) => {
        // TS things opts does not contain `appPath`. But it does. I guess
        // the type in the lib is busted. Force it as any to make TS
        // happy.
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const appPath = (opts as any).appPath;
        // I couldn't find an way to find the path the to source directory other
        // than this hack of using the path to the background image and just getting
        // the basename of it :-(
        const assetsPath = path.dirname(opts.background || "");
        return [
          { x: 162, y: 115, type: "file", path: appPath },
          { x: 478, y: 115, type: "link", path: "/Applications" },
          {
            x: 162,
            y: 300,
            type: "file",
            path: assetsPath + "/ReadMeFirst.html",
          },
          {
            x: 329,
            y: 300,
            type: "file",
            path: assetsPath + "/Install ChmodBPF.pkg",
          },
          {
            x: 478,
            y: 300,
            type: "file",
            path: assetsPath + "/Uninstall ChmodBPF.pkg",
          },
          // usually these two are hidden, unless ShowAllFiles is enabled
          // in Finder (like Gregor does), so in this case: move them outside
          // window
          { x: 172, y: 600, type: "position", path: ".background" },
          { x: 468, y: 600, type: "position", path: ".VolumeIcon.icns" },
        ];
      },
    }),
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
