import { Outlet } from "react-router-dom";
import Navbar from "../components/Navbar";

// The example on Clerk.com says to put the ClerkProvider HERE but that's
// only if you want a mix of pages that are available for people logged in and not logged in
export default function RootLayout() {
  return (
    <div>
      <header>
        <nav>
          <Navbar />
        </nav>
      </header>
      <main>
        <Outlet />
      </main>
    </div>
  );
}
