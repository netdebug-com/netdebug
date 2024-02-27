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
  const auth = useAuth();
  // const user = getUser();
  const [jwt, setJwt] = useState<string | null>(null);
  useEffect(() => {
    auth.getToken().then((token) => setJwt(token));
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
          </ul>
        </div>
      </SignedIn>
    </div>
  );
}

export default App;
