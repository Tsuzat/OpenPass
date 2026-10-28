import { describe, expect, test } from "bun:test";
import { registrableDomain, uriMatches } from "./match";

describe("registrableDomain", () => {
  test("basic + subdomain + multi-label suffix", () => {
    expect(registrableDomain("github.com")).toBe("github.com");
    expect(registrableDomain("api.github.com")).toBe("github.com");
    expect(registrableDomain("login.example.co.uk")).toBe("example.co.uk");
  });
});

describe("uriMatches", () => {
  test("domain matches subdomains but not lookalikes", () => {
    expect(uriMatches("https://github.com/login", "domain", "gist.github.com")).toBe(true);
    expect(uriMatches("https://github.com", "domain", "evilgithub.com")).toBe(false);
    expect(uriMatches("https://github.com", "domain", "github.com.evil.com")).toBe(false);
  });
  test("host is exact only", () => {
    expect(uriMatches("https://accounts.google.com", "host", "accounts.google.com")).toBe(true);
    expect(uriMatches("https://accounts.google.com", "host", "mail.google.com")).toBe(false);
  });
  test("never never fills", () => {
    expect(uriMatches("https://github.com", "never", "github.com")).toBe(false);
  });
});
