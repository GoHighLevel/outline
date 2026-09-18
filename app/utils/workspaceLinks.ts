import isCloudHosted from "./isCloudHosted";

/**
 * Builds a link that selects the workspace before opening a private document.
 *
 * @param teamId the workspace that owns the document.
 * @param path the document path including optional query and heading.
 * @param origin the application origin.
 * @returns the shareable link; access still requires document permissions.
 */
export function workspaceDocumentUrl(
  teamId: string,
  path: string,
  origin = window.location.origin
) {
  if (isCloudHosted) {
    return `${origin}${path}`;
  }
  const url = new URL("/", origin);
  url.searchParams.set("workspace", teamId);
  url.searchParams.set("document", path);
  return url.toString();
}

/**
 * Allows only local document destinations from workspace links.
 *
 * @param path the untrusted document query parameter.
 * @returns a document path, or undefined for an invalid destination.
 */
export function getWorkspaceDocumentPath(
  path: string | null
): string | undefined {
  if (!path?.startsWith("/doc/") || path.includes("\\")) {
    return;
  }
  const url = new URL(path, "https://outline.invalid");
  if (
    url.origin !== "https://outline.invalid" ||
    !url.pathname.startsWith("/doc/")
  ) {
    return;
  }
  return `${url.pathname}${url.search}${url.hash}`;
}
