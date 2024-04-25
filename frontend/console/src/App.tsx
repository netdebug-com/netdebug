import "./App.css";
import { SignIn, SignedIn, SignedOut } from "@clerk/clerk-react";

import { ClerkProvider } from "@clerk/clerk-react";

// non-secret key from Clerk
const CLERK_PUBLISHABLE_KEY =
  import.meta.env.MODE == "development"
    ? import.meta.env.VITE_CLERK_PUBLISHABLE_DEV_KEY
    : import.meta.env.VITE_CLERK_PUBLISHABLE_PROD_KEY;

if (!CLERK_PUBLISHABLE_KEY) {
  throw new Error("Missing Publishable Key");
}

if (import.meta.env.MODE == "development") {
  console.log("Running in development mode");
}
import Home, { worstDevicesPacketLossLoader } from "./pages/Home";
import About from "./pages/About";
import Devices, { devicesLoader } from "./pages/Devices";
import { RouterProvider } from "react-router-dom";

// Import the layouts
import RootLayout from "./layouts/RootLayout";
import {
  Route,
  createBrowserRouter,
  createRoutesFromElements,
} from "react-router-dom";
import { DefaultErrorElement } from "./common";
import Device, { deviceLoader } from "./pages/Device";
import { DeviceFlows, deviceFlowsLoader } from "./pages/DeviceFlows";

// TODO: change to createBrowserRouter()
const router = createBrowserRouter(
  createRoutesFromElements(
    <Route
      path="/"
      element={<RootLayout />}
      errorElement={<DefaultErrorElement />}
    >
      <Route
        index
        element={<Home />}
        loader={worstDevicesPacketLossLoader}
        errorElement={<DefaultErrorElement />}
      />
      ,
      <Route
        path="devices/device/:uuid"
        loader={deviceLoader}
        element={<Device />}
        errorElement={<DefaultErrorElement />}
      />
      <Route
        path="devices"
        loader={devicesLoader}
        element={<Devices />}
        errorElement={<DefaultErrorElement />}
      />
      ,
      <Route
        path="devices/flows/:uuid"
        loader={deviceFlowsLoader}
        element={<DeviceFlows />}
        errorElement={<DefaultErrorElement />}
      />
      ,
      <Route
        path="about"
        element={<About />}
        errorElement={<DefaultErrorElement />}
      />
      ,
    </Route>,
  ),
);

export function App() {
  return (
    <ClerkProvider publishableKey={CLERK_PUBLISHABLE_KEY}>
      <SignedIn>
        {/* If user is signed in, show the full console router */}
        <RouterProvider router={router} />
      </SignedIn>
      <SignedOut>
        {/* If user is not logged in, only show the signin prompt */}
        <SignIn afterSignInUrl={window.location.href} />
      </SignedOut>
    </ClerkProvider>
  );
}
