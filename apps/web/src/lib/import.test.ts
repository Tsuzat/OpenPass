import { describe, expect, test } from "bun:test";
import { zipSync, strToU8 } from "fflate";
import { dedupeKey, normalizeTotp, parse1Password1pux, parseBitwardenJson, parseGenericCsv, parseProtonJson, parseZohoCsv, partitionDuplicates } from "./import";

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

describe("parse1Password1pux", () => {
  test("unzips export.data and maps login + card, splits TOTP", async () => {
    const data = {
      accounts: [{ vaults: [{ attrs: { name: "Personal" }, items: [
        {
          categoryUuid: "001", overview: { title: "GitHub", urls: [{ url: "https://github.com" }], tags: ["dev"] },
          details: {
            loginFields: [
              { designation: "username", value: "octo" },
              { designation: "password", value: "pw" },
            ],
            sections: [{ fields: [{ title: "one-time password", value: { totp: "otpauth://totp/GitHub:octo?secret=JBSWY3DPEHPK3PXP&issuer=GitHub" } }] }],
          },
        },
        {
          categoryUuid: "002", overview: { title: "Visa" },
          details: { sections: [{ fields: [
            { title: "card number", value: { creditCardNumber: "4111111111111111" } },
            { title: "expiry date", value: { string: "012030" } },
            { title: "cvv", value: { string: "123" } },
          ] }] },
        },
      ] }] }],
    };
    const zip = zipSync({ "export.data": strToU8(JSON.stringify(data)) });
    const items = await parse1Password1pux(zip);
    expect(items.map((i) => i.type)).toEqual(["login", "totp", "card"]);
    expect(items[0]).toMatchObject({ username: "octo", tags: ["dev", "Personal"] });
    expect(items[2]).toMatchObject({ number: "4111111111111111", expMonth: "01", expYear: "2030" });
  });
});

describe("parseZohoCsv", () => {
  test("web secret + card via secret type/chamber tags", () => {
    const csv = [
      "Password Name,Description,User Name,Password,URL,Notes,Secret Type,Chamber Name",
      "GitHub,work,octo,pw,https://github.com,,Web Account,Work",
      "Visa,,,4111111111111111,,card note,Credit Card,Finance",
    ].join("\n");
    const items = parseZohoCsv(csv);
    // card number arrives in Password column and also detected by type
    expect(items[0]).toMatchObject({ type: "login", username: "octo", tags: ["Work"] });
    expect(items[1].type).toBe("card");
  });
});

describe("parseProtonJson + KeePass CSV", () => {
  test("proton login", () => {
    const items = parseProtonJson(JSON.stringify({ items: [{ data: { type: "login", metadata: { name: "GH" }, content: { username: "o", password: "p", urls: ["https://github.com"] } } }] }));
    expect(items[0]).toMatchObject({ type: "login", name: "GH" });
  });
  test("keepass csv with TOTP seed and group tag", () => {
    const items = parseGenericCsv('Group,Title,Username,Password,URL,Notes,TOTP Seed\n Banking,Visa,me,pw,https://bank.example,,JBSWY3DPEHPK3PXP');
    expect(items).toHaveLength(2);
    expect(items[0]).toMatchObject({ type: "login", name: "Visa", tags: ["Banking"] });
    expect(items[1].type).toBe("totp");
  });
});

describe("dedupe", () => {
  test("partition skips existing and intra-file duplicates", () => {
    const existing = new Set([dedupeKey({ type: "login", name: "GitHub", username: "octo", uris: [{ uri: "https://github.com/login" }] })]);
    const incoming = [
      { type: "login", name: "github", username: "Octo", uris: [{ uri: "github.com" }] },
      { type: "login", name: "New", username: "x", uris: [] },
      { type: "login", name: "New", username: "x", uris: [] },
    ];
    const { fresh, duplicates } = partitionDuplicates(incoming, existing);
    expect(fresh).toHaveLength(1);
    expect(duplicates).toHaveLength(2);
  });
});

describe("parseGenericCsv", () => {
  test("chrome-style csv with quoted commas", () => {
    const items = parseGenericCsv('name,url,username,password,note\n"Git, Hub",https://github.com,octo,"p,w",hello');
    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({ name: "Git, Hub", username: "octo", password: "p,w" });
  });
});
