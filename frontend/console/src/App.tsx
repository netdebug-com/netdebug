import "./App.css";
import {
  SignOutButton,
  SignIn,
  useAuth,
  SignedIn,
  SignedOut,
  UserButton,
  // useUser,
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
  // Get the auth information from Clerk.com
  // in theory, auth will get reloaded when the Clerk session expires.  Not sure how
  // often this is.
  const auth = useAuth();

  // each clerk.com auth includes a jwt that validates the signature
  const [jwt, setJwt] = useState<string | null>(null);
  useEffect(() => {
    auth.getToken().then((token) => setJwt(token));
  }, [auth]);

  // with each new JWT, we get a NetDebug session token for REST API access
  const [login, setLogin] = useState<Response | null>(null);
  useEffect(() => {
    if (jwt === null) {
      setLogin(null);
    } else {
      fetch(get_rest_url("api/login?clerk_jwt=" + jwt)).then((resp) =>
        setLogin(resp),
      );
    }
  }, [jwt]);

  // and (for this code at least) every time we get a REST API token, test it
  const [test, setTest] = useState<string | null>(null);
  useEffect(() => {
    if (login === null) {
      setTest(null);
    } else {
      fetch(get_rest_url("api/test_auth"))
        .then((resp) => resp.text())
        .then((t) => setTest(t));
    }
  }, [login]);

  // and (for this code at least) every time we get a REST API token, test it
  const [organization, setOrganization] = useState<string | null>(null);
  useEffect(() => {
    if (login === null) {
      setOrganization(null);
    } else {
      fetch(get_rest_url("api/organization_info"))
        .then((resp) => resp.json())
        .then((org) => setOrganization(JSON.stringify(org, undefined, 2)));
    }
  }, [login]);

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
            <li> isLoaded={auth.isLoaded}</li>
            <li> isSignedin={auth.isSignedIn}</li>
            <li>SessionId={auth.sessionId}</li>
            <li> jWt={jwt && jwt} </li>
            <li> login={login && login.headers && login.status} </li>
            <li> Test: {test && test} </li>
            <li>
              organization:
              {organization && organization}{" "}
            </li>
          </ul>
        </div>
      </SignedIn>
    </div>
  );
}

function get_rest_url(path: string): string {
  // e.g., "https://hostname:port"
  return window.location.origin + "/" + path;
}

export default App;
