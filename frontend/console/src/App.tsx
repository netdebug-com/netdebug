import "./App.css";
import {
  SignOutButton,
  SignIn,
  SignedIn,
  SignedOut,
  UserButton,
} from "@clerk/clerk-react";

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
import { useEffect, useState } from "react";
import Home from "./pages/Home";
import About from "./pages/About";
import { RouterProvider } from "react-router-dom";

// Import the layouts
import RootLayout from "./layouts/RootLayout";
import {
  Route,
  createHashRouter,
  createRoutesFromElements,
} from "react-router-dom";
import { loadDataWithAuth } from "./console_utlils";
import { DataLoadingState, PublicOrganizationInfo } from "./common";

const router = createHashRouter(
  createRoutesFromElements(
    <Route path="/" element={<RootLayout />}>
      <Route index element={<Home />} />,
      <Route path="test" element={<TestApp />} />,
      <Route path="about" element={<About />} />,
    </Route>,
  ),
);

export function App() {
  return (
    <ClerkProvider publishableKey={CLERK_PUBLISHABLE_KEY}>
      <SignedIn>
        {/* If user is signed in, show the full console router */}
        <RouterProvider router={router} />;
      </SignedIn>
      <SignedOut>
        {/* If user is not logged in, only show the signin prompt */}
        <SignIn />
      </SignedOut>
    </ClerkProvider>
  );
}

export function TestApp() {
  // and (for this code at least) every time we get a REST API token, test it
  const [organization, setOrganization] = useState<string | null>(null);
  useEffect(() => {
    loadDataWithAuth(
      "api/organization_info",
      (resp: DataLoadingState<PublicOrganizationInfo>) => {
        if (resp.isPending) {
          setOrganization("Pending...");
        } else if (resp.error) {
          setOrganization("Error: " + resp.error);
        } else {
          setOrganization(resp.data.name);
        }
      },
    );
  }, []);

  return (
    <div>
      <SignedOut>
        <SignIn />
      </SignedOut>
      <SignedIn>
        {/*<SignOutButton signOutCallback={() => redirect('/')}> /*/}
        <SignOutButton />
        <div>
          This content is private. Only signed in users can see the
          SignOutButton above this text.
          <UserButton />
          <ul>
            <li> yay organization: {organization && organization}</li>
          </ul>
        </div>
      </SignedIn>
    </div>
  );
}
