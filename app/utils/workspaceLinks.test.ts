import {
  getWorkspaceDocumentPath,
  workspaceDocumentUrl,
} from "./workspaceLinks";

describe("workspace document links", () => {
  it("preserves the destination workspace and document without granting access", () => {
    const url = new URL(
      workspaceDocumentUrl(
        "team-id",
        "/doc/example-AbCdEf1234#heading",
        "https://docs.example.com"
      )
    );
    expect(url.origin).toBe("https://docs.example.com");
    expect(url.pathname).toBe("/");
    expect(url.searchParams.get("workspace")).toBe("team-id");
    expect(url.searchParams.get("document")).toBe(
      "/doc/example-AbCdEf1234#heading"
    );
  });

  it.each([
    "https://evil.example/doc/example",
    "//evil.example/doc/example",
    "/auth/google",
    "/doc/\\evil.example",
    null,
  ])("rejects an unsafe document destination: %s", (path) => {
    expect(getWorkspaceDocumentPath(path)).toBeUndefined();
  });

  it("accepts a private document path including its query and heading", () => {
    expect(
      getWorkspaceDocumentPath("/doc/example-AbCdEf1234?revisionId=123#heading")
    ).toBe("/doc/example-AbCdEf1234?revisionId=123#heading");
  });
});
