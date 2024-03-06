import "./App.css";
import {
  SignOutButton,
  SignIn,
  SignedIn,
  SignedOut,
  useAuth,
  UserButton,
  // useUser,
} from "@clerk/clerk-react";
import { useEffect, useState } from "react";

function App() {
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
    if (auth === null) {
      setTest(null);
    } else {
      fetch(get_rest_url("api/test_auth"))
        .then((resp) => resp.text())
        .then((t) => setTest(t));
    }
  }, [auth]);

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
            <li> TestStatus={test && test}</li>
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
