# Desktop GUI and electron stuff 

This directory has the desktop GUI (react) typescript files, and all the plumbing (webpack, etc.) to build it into an electron app. 


> ⚠️ **NOTE:** currently this directory contains none of the desktop GUI. But it does use react. 


## Dev environment setup. 

Visual Studio Code is the best IDE/editor to use. 

Building / running the GUI requires node and npm. I found it easiest to use a version manager for npm/node so that it's easy to select
which node/npm version to use and to switch between them. Might not be necessary. 

I'm using [nvm - Node Version Manager](https://github.com/nvm-sh/nvm). It integrates with your shell (it sources it's configuration in `.bashrc` or similar and then modifies your PATH to point to the version of node you want to use). After installing nvm, run 
`nvm install --lts --default`. This should install the node LTS and make it the default. To verify open a shell (in VsCode) and run `nvm version` and/or `node --version`

(As of Oct 2023, Node 20.* is the current LTS version. Electron's stable release currently uses node 18 but the next electron release should be coming in a couple of weeks). In any case. Either 18 or 20 should work just fine for local development. 

Then run 
`cd electron; npm install` 
which should download all the node packages that react/webpack/electron need. 

## Directory and Files 
* `package.json`: the npm package config
* `webpack.*.config.ts`: webpack configs for the main and render processes. Probably no need to touch. 
* `forge.config.ts`: electron-forge (scripts/framework to package electron into App bundles / exe. etc). Mostly relevant to add extra resources (like the desktop deamon binary) I think
* `src/`: all the GUI source code lives here. Most relevant are: 
  * `main.ts`: the entry point for the main electron process. Here's where we would muck around with spawning the rust desktop binary, creating the app window, etc. 
  * `renderer.tsx`: the entry point for the UI. Right now it basically just loads the `<App />` react component from `App.tsx`
* `node_modules`: where npm downloads and complies stuff. Excluded from version control
* `out`: packages output for distribution.

## Run and build

* `npm start`: start electron with a development webserver that supports hot-reload
* `npm run make`: create a distribution bundle for the OS you're running on 