import { useLocation, useResolvedPath } from "react-router-dom";

// TODO: This whole logic feel fragile and convoluted. But I haven't found a better
// way of tackling things. So before I waste more time, let's call it good enough
// and move on.

// Helper type to match routes to Nav elements like ToggleButtonGroup or
// Navbar.
export type NavInfo = {
  // The label to display
  label: string;
  // the "to" field of the link / nav element
  to: string;
  // if it's an exact match. Generally, needed for the route
  exactMatch?: boolean;
};

// this feels hacky. Given a list of NavInfos, we try to return the
// `to` field of the NavInfo that matches the current route. This
// surprisingly convoluted. It is based on the current position in the
// route hierarchy.
export function useMatchNavInfo(routeInfos: readonly NavInfo[]) {
  const locationPathname = useLocation().pathname;
  let firstMatch: string = null;
  for (let i = 0; i < routeInfos.length; i += 1) {
    const { to, exactMatch } = routeInfos[i];

    // This code is borrowed from react-router's `<NavLink>` component which
    // uses it to figure out if a link is "active" (i.e., it's part of the
    // current route.

    // useResolvedPath takes a `to` like we'd specify on a <Link> and generates
    // the absolute pathname (based on current location etc.) for it.
    // eslint-disable-next-line react-hooks/rules-of-hooks
    const toPathname = useResolvedPath(to).pathname;

    // If the `to` has a trailing slash, look at that exact spot.  Otherwise,
    // we're looking for a slash _after_ what's in `to`.  For example:
    // <NavLink to="/users"> and <NavLink to="/users/">
    // both want to look for a / at index 6 to match URL `/users/matt`
    const endSlashPosition =
      toPathname !== "/" && toPathname.endsWith("/")
        ? toPathname.length - 1
        : toPathname.length;
    if (
      locationPathname === toPathname ||
      (!exactMatch &&
        locationPathname.startsWith(toPathname) &&
        locationPathname.charAt(endSlashPosition) === "/")
    ) {
      // we can't early return here. React gets very unhappy if a hooks isn't called
      // the same number of times on each render of a component and we need to
      // use `useResolvePath` in a loop.  We hack around it by making sure we
      // don't return early
      firstMatch = firstMatch ? firstMatch : to;
    }
  }

  return firstMatch;
}
