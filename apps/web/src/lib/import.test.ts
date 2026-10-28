import { describe, expect, test } from "bun:test";
import { normalizeTotp, parseBitwardenJson, parseGenericCsv } from "./import";

describe("normalizeTotp", () => {
  test("raw secret and otpauth URI", () => {
    expect(normalizeTotp("jbsw y3dp ehpk 3pxp")?.secretBase32).toBe("JBSWY3DPEHPK3PXP");
    const parsed = normalizeTotp("otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub");
    expect(parsed).toEqual({ secretBase32: "JBSWY3DPEHPK3PXP", issuer: "GitHub", account: "octocat" });
    expect(normalizeTotp("not a secret!!")).toBeNull();
  });
});

describe("parseBitwardenJson", () => {
  test("login + embedded TOTP becomes two items; card maps", () => {
    const items = parseBitwardenJson(JSON.stringify({
      items: [
        { name: "GitHub", type: 1, login: { username: "octo", password: "pw", totp: "JBSWY3DPEHPK3PXP", uris: [{ uri: "https://github.com" }] } },
        { name: "Visa", type: 3, card: { cardholderName: "A B", number: "4111111111111111", expMonth: "01", expYear: "2030", code: "123" } },
      ],
    }));
    expect(items).toHaveLength(3);
    expect(items[0].type).toBe("login");
    expect(items[1].type).toBe("totp");
    expect(items[2]).toMatchObject({ type: "card", number: "4111111111111111", cvv: "123" });
  });
});

describe("parseGenericCsv", () => {
  test("chrome-style csv with quoted commas", () => {
    const items = parseGenericCsv('name,url,username,password,note\n"Git, Hub",https://github.com,octo,"p,w",hello');
    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({ name: "Git, Hub", username: "octo", password: "p,w" });
  });
});
