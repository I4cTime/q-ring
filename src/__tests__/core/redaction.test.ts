import { describe, it, expect, vi } from "vitest";
import {
  RedactionSet,
  RedactionStream,
  SLICE_WINDOW,
  DERIVE_MAX_LENGTH,
  SLICE_MAX_LENGTH,
  sliceRegions,
  resetRedactionNotes,
  type RedactionEntry,
} from "../../core/redaction.js";

/** Deterministic high-entropy text (fake secrets). */
function fakeSecret(length: number, seed: number): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let x = seed >>> 0;
  let out = "";
  for (let i = 0; i < length; i++) {
    x = (Math.imul(x, 1103515245) + 12345) >>> 0;
    out += chars[(x >>> 16) % chars.length];
  }
  return out;
}

function fakePem(bodyLines: number, seed: number): string {
  const lines = Array.from({ length: bodyLines }, (_, i) => fakeSecret(64, seed + i));
  return `-----BEGIN PRIVATE KEY-----\n${lines.join("\n")}\n-----END PRIVATE KEY-----`;
}

const b64url = (s: string) => Buffer.from(s).toString("base64url");
const tok = (name: string) => `[QRING:REDACTED:${name}]`;

/** Feed `chunks` through a stream, returning the output and the largest hold-back seen. */
function stream(
  set: RedactionSet,
  chunks: string[],
): { out: string; maxHeld: number; early: number } {
  const s = new RedactionStream(set);
  let out = "";
  let maxHeld = 0;
  for (const c of chunks) {
    out += s.write(c);
    maxHeld = Math.max(maxHeld, s.held);
  }
  const early = out.length;
  out += s.end();
  return { out, maxHeld, early };
}

/** Stderr spy that swallows output; restore with .mockRestore(). */
const muteStderr = () => vi.spyOn(process.stderr, "write").mockImplementation(() => true);

describe("bounded hold-back on repeating values (review #1)", () => {
  it("streams an endless run of a repeating PIN in bounded memory", () => {
    const set = new RedactionSet([{ name: "PIN", value: "000000" }]);
    const chunk = "0".repeat(1024);
    const chunks = Array.from({ length: 2000 }, () => chunk);
    const t0 = performance.now();
    const { out, maxHeld, early } = stream(set, chunks);
    const ms = performance.now() - t0;
    expect(maxHeld).toBeLessThanOrEqual(set.holdMax);
    expect(early).toBeGreaterThan(0); // emitted before end, not all at EOF
    expect(out).toMatch(/^(\[QRING:REDACTED:PIN\])+0{0,5}$/);
    expect(ms).toBeLessThan(5000);
  });

  it("streams a periodic encoded form (hex) without growing the hold-back", () => {
    const set = new RedactionSet([{ name: "PIN", value: "000000" }]);
    const chunks = Array.from({ length: 500 }, () => "30".repeat(512));
    const { out, maxHeld } = stream(set, chunks);
    expect(maxHeld).toBeLessThanOrEqual(set.holdMax);
    expect(out).toMatch(/^(\[QRING:REDACTED:PIN\])+(30){0,5}3?$/);
  });

  it("caps a chain of overlapping hits at holdMax and keeps redacting it", () => {
    const set = new RedactionSet([
      { name: "A", value: "abcabcabc" },
      { name: "B", value: "cabcabcab" },
    ]);
    const chunks = Array.from({ length: 300 }, () => "abc".repeat(100));
    const { out, maxHeld, early } = stream(set, chunks);
    expect(maxHeld).toBeLessThanOrEqual(set.holdMax);
    expect(early).toBeGreaterThan(0);
    expect(out).toMatch(/^(\[QRING:REDACTED:[AB]\])+[abc]{0,8}$/);
  });
});

describe("encoded forms and minimal hold-back (review #2)", () => {
  it(`derives encoded forms only for values up to ${DERIVE_MAX_LENGTH} chars`, () => {
    const atLimit = fakeSecret(DERIVE_MAX_LENGTH, 1);
    const over = fakeSecret(DERIVE_MAX_LENGTH + 1, 2);
    const set = new RedactionSet([
      { name: "AT", value: atLimit },
      { name: "OVER", value: over },
    ]);
    const hex = (s: string) => Buffer.from(s).toString("hex");
    expect(set.redact(`h=${hex(atLimit)}`)).toBe(`h=${tok("AT")}`);
    expect(set.redact(`v=${over}`)).toBe(`v=${tok("OVER")}`);
    // Over the limit: verbatim and slices only, the hex form passes.
    expect(set.redact(`h=${hex(over)}`)).toBe(`h=${hex(over)}`);
  });

  it("flushes ordinary output immediately even with a long PEM in the set", () => {
    const muted = muteStderr();
    try {
      const set = new RedactionSet([
        { name: "TLS_KEY", value: fakePem(34, 7) },
        ...Array.from({ length: 30 }, (_, i) => ({
          name: `T${i}`,
          value: fakeSecret(40, 100 + i),
        })),
      ]);
      expect(set.holdMax).toBeGreaterThan(2000);
      const s = new RedactionStream(set);
      expect(s.write("2026-11-04T10:00:00Z INFO server listening on :8080\n")).toBe(
        "2026-11-04T10:00:00Z INFO server listening on :8080\n",
      );
      expect(s.held).toBe(0);
      // A suffix that could still become the PEM is held, nothing more.
      expect(s.write("dumping -----BEGIN")).toBe("dumping ");
      expect(s.held).toBe("-----BEGIN".length);
    } finally {
      muted.mockRestore();
    }
  });

  it("holds only the live suffix of a partially written secret", () => {
    const S = fakeSecret(40, 3);
    const set = new RedactionSet([{ name: "K", value: S }]);
    const s = new RedactionStream(set);
    expect(s.write(`token: ${S.slice(0, 10)}`)).toBe("token: ");
    expect(s.write(`${S.slice(10)} ok\n`)).toBe(`${tok("K")} ok\n`);
  });
});

describe("slice regions of structured secrets (review #3)", () => {
  it("URL with userinfo: the userinfo only", () => {
    expect(
      sliceRegions("postgresql://postgres:hunter2pass@localhost:5432/app?sslmode=require"),
    ).toEqual(["postgres:hunter2pass"]);
  });

  it("URL without userinfo: path and query, scheme and host stripped", () => {
    expect(sliceRegions("https://example.com/hooks/T0/B0/abcdef?x=1")).toEqual([
      "/hooks/T0/B0/abcdef?x=1",
    ]);
    // Nothing credential-shaped left: never an empty list, the whole value.
    expect(sliceRegions("https://api.example.com")).toEqual(["https://api.example.com"]);
  });

  it("JWT: the signature segment only", () => {
    const jwt = `${b64url('{"alg":"HS256","typ":"JWT"}')}.${b64url('{"role":"x"}')}.SIGNATUREsegment_-123`;
    expect(sliceRegions(jwt)).toEqual(["SIGNATUREsegment_-123"]);
  });

  it("PEM: body lines without armor or headers", () => {
    const body = [fakeSecret(64, 11), fakeSecret(20, 12)];
    const pem = `-----BEGIN EC PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n${body.join("\n")}\n-----END EC PRIVATE KEY-----\n`;
    expect(sliceRegions(pem)).toEqual(body);
  });

  it("JSON object: string values under credential-named keys, recursively", () => {
    const json = JSON.stringify({
      type: "service_account_type",
      client_email: "someone@example-project.iam.gserviceaccount.com",
      nested: {
        secret: "s3cr3t-value-0123456789",
        credentials: ["https://u:passw0rd-long-enough@h/x"],
        notes: "a long public description string",
      },
      token_uri: "https://oauth2.googleapis.com/token/exchange-endpoint",
    });
    expect(sliceRegions(json)).toEqual(["s3cr3t-value-0123456789", "u:passw0rd-long-enough"]);
  });

  it("anything else: the whole value", () => {
    expect(sliceRegions("sk-plain-api-key-0123456789")).toEqual(["sk-plain-api-key-0123456789"]);
  });

  it("ignores low-entropy windows", () => {
    const value = `${"x".repeat(24)}${fakeSecret(24, 5)}`;
    const set = new RedactionSet([{ name: "K", value }]);
    expect(set.redact(`pad ${"x".repeat(30)} pad`)).toBe(`pad ${"x".repeat(30)} pad`);
    expect(set.redact(`pad ${"0".repeat(30)} pad`)).toBe(`pad ${"0".repeat(30)} pad`);
    // The high-entropy part still slices (and extends through the x run).
    expect(set.redact(`pad ${value.slice(20, 44)} pad`)).toBe(`pad ${tok("K")} pad`);
  });

  it("repro: a different connection string to the same kind of database passes untouched", () => {
    const set = new RedactionSet([
      {
        name: "DATABASE_URL",
        value: "postgresql://postgres:hunter2pass@localhost:5432/app?sslmode=require",
      },
    ]);
    const line =
      "Connecting to postgresql://postgres:otherpw@db.example.com:5432/other?sslmode=require";
    expect(set.redact(line)).toBe(line);
    // The real credential is still caught, verbatim and as a slice.
    expect(set.redact("auth failed for postgres:hunter2pass@localhost")).toBe(
      `auth failed for ${tok("DATABASE_URL")}@localhost`,
    );
  });

  it("repro: Slack webhook docs text passes untouched", () => {
    // Assembled at runtime so no webhook-shaped literal sits in the source
    // (GitHub push protection flags even Slack's documented placeholder).
    const hooks = ["https:/", "hooks.slack.com", "services"].join("/");
    const set = new RedactionSet([
      {
        name: "SLACK_WEBHOOK",
        value: [hooks, "T0ABCDEF1", "B0GHIJKL2", fakeSecret(24, 9)].join("/"),
      },
    ]);
    const docs = `POST your message to ${hooks}/ with a JSON body`;
    expect(set.redact(docs)).toBe(docs);
    const example = `It looks like ${[hooks, "T00000000", "B00000000", "X".repeat(24)].join("/")}`;
    expect(set.redact(example)).toBe(example);
  });

  it("repro: a Supabase anon key is not redacted as the service-role key", () => {
    const header = b64url('{"alg":"HS256","typ":"JWT"}');
    const claims = (role: string) =>
      b64url(
        `{"iss":"supabase","ref":"abcdefghijklmnopqrst","role":"${role}","iat":1700000000,"exp":2000000000}`,
      );
    const service = `${header}.${claims("service_role")}.${fakeSecret(43, 21)}`;
    const anon = `${header}.${claims("anon")}.${fakeSecret(43, 22)}`;
    const set = new RedactionSet([{ name: "SUPABASE_SERVICE_ROLE_KEY", value: service }]);
    expect(set.redact(`NEXT_PUBLIC_SUPABASE_ANON_KEY=${anon}`)).toBe(
      `NEXT_PUBLIC_SUPABASE_ANON_KEY=${anon}`,
    );
    expect(set.redact(`key=${service}`)).toBe(`key=${tok("SUPABASE_SERVICE_ROLE_KEY")}`);
    const sig = service.split(".")[2];
    expect(set.redact(`sig ${sig.slice(5, 30)} end`)).toBe(
      `sig ${tok("SUPABASE_SERVICE_ROLE_KEY")} end`,
    );
  });
});

describe("nested secrets (review #4)", () => {
  it("a short value inside a longer one does not shadow the longer one's slice", () => {
    const set = new RedactionSet([
      { name: "DB_USER", value: "appuser" },
      { name: "DATABASE_URL", value: "postgres://appuser:S3cr3tPassw0rd!@db.internal:5432/app" },
    ]);
    expect(set.redact("login appuser:S3cr3tPassw0rd failed")).toBe(
      `login ${tok("DATABASE_URL")} failed`,
    );
    // On its own the short value keeps its own name.
    expect(set.redact("user appuser logged in")).toBe(`user ${tok("DB_USER")} logged in`);
  });
});

describe("per-part slice limit", () => {
  it(`slices parts up to ${SLICE_MAX_LENGTH} chars, matches longer opaque values verbatim only`, () => {
    resetRedactionNotes();
    const write = muteStderr();
    try {
      const atLimit = fakeSecret(SLICE_MAX_LENGTH, 31);
      const over = fakeSecret(SLICE_MAX_LENGTH + 1, 32);
      const set = new RedactionSet([
        { name: "AT", value: atLimit },
        { name: "OVER", value: over },
      ]);
      expect(set.redact(`a=${atLimit}`)).toBe(`a=${tok("AT")}`);
      expect(set.redact(`o=${over}`)).toBe(`o=${tok("OVER")}`);
      expect(set.redact(`s ${atLimit.slice(500, 520)} e`)).toBe(`s ${tok("AT")} e`);
      expect(set.redact(`s ${over.slice(500, 520)} e`)).toBe(`s ${over.slice(500, 520)} e`);

      // Counts only, once per process.
      new RedactionSet([{ name: "OVER", value: over }]);
      expect(write).toHaveBeenCalledTimes(1);
      const msg = String(write.mock.calls[0][0]);
      expect(msg).toContain("1 credential part(s)");
      expect(msg).not.toContain("OVER");
      expect(msg).not.toContain(over.slice(0, 16));
    } finally {
      write.mockRestore();
      resetRedactionNotes();
    }
  });

  it("a 1500-char opaque token is matched verbatim but not sliced", () => {
    const write = muteStderr();
    try {
      const blob = fakeSecret(1500, 61);
      const set = new RedactionSet([{ name: "BLOB", value: blob }]);
      expect(set.slicing).toBe(false);
      expect(set.redact(`b=${blob};`)).toBe(`b=${tok("BLOB")};`);
      expect(set.redact(`s ${blob.slice(700, 740)} e`)).toBe(`s ${blob.slice(700, 740)} e`);
    } finally {
      write.mockRestore();
    }
  });

  it("a realistic 2.3 KB service-account JSON slices its key body and token fields", () => {
    // Fake key material, assembled at runtime so secret scanning has nothing to flag.
    const body = Array.from({ length: 25 }, (_, i) => fakeSecret(64, 700 + i));
    const pem = ["-----BEGIN PRIVATE KEY-----", ...body, "-----END PRIVATE KEY-----", ""].join(
      "\n",
    );
    const account = {
      type: "service_account",
      project_id: "demo-project-123456",
      private_key_id: fakeSecret(40, 760).toLowerCase(),
      private_key: pem,
      client_email: "deployer@demo-project-123456.iam.gserviceaccount.com",
      client_id: "104857364829105738291",
      auth_uri: "https://accounts.google.com/o/oauth2/auth",
      token_uri: "https://oauth2.googleapis.com/token",
      auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
      client_x509_cert_url:
        "https://www.googleapis.com/robot/v1/metadata/x509/deployer%40demo-project-123456.iam.gserviceaccount.com",
      universe_domain: "googleapis.com",
      refresh_token: fakeSecret(48, 761),
    };
    const value = JSON.stringify(account, null, 2);
    expect(value.length).toBeGreaterThan(2200);
    expect(value.length).toBeLessThan(2600);

    const set = new RedactionSet([{ name: "GCP_SA_JSON", value }]);
    expect(set.redact(`key: ${body[12].slice(20, 55)}...`)).toBe(`key: ${tok("GCP_SA_JSON")}...`);
    expect(set.redact(`token=${account.refresh_token.slice(4, 28)}&`)).toBe(
      `token=${tok("GCP_SA_JSON")}&`,
    );
    expect(set.redact(`whole: ${value}`)).toBe(`whole: ${tok("GCP_SA_JSON")}`);
    // Public structure stays: the token URI and the client email domain.
    expect(set.redact("POST https://oauth2.googleapis.com/token")).toBe(
      "POST https://oauth2.googleapis.com/token",
    );
  });

  it("a long PEM in the set never turns off slicing for a short API key", () => {
    const write = muteStderr();
    try {
      const key = fakeSecret(40, 41);
      const set = new RedactionSet([
        { name: "TLS_KEY", value: fakePem(80, 42) },
        { name: "API_KEY", value: key },
      ]);
      expect(set.redact(`first 20: ${key.slice(0, 20)}...`)).toBe(`first 20: ${tok("API_KEY")}...`);
    } finally {
      write.mockRestore();
    }
  });
});

describe("lone UTF-16 surrogates (review #6)", () => {
  it("a malformed value never fails the set; good values stay fully redacted", () => {
    const bad = `pw\ud83d${fakeSecret(24, 51)}`;
    const good = fakeSecret(40, 52);
    expect(() => encodeURIComponent(bad)).toThrow(URIError);
    const set = new RedactionSet([
      { name: "BAD", value: bad },
      { name: "GOOD", value: good },
    ]);
    expect(set.redact(`g=${good}`)).toBe(`g=${tok("GOOD")}`);
    expect(set.redact(`h=${Buffer.from(good).toString("hex")}`)).toBe(`h=${tok("GOOD")}`);
    expect(set.redact(`s=${encodeURIComponent(good.slice(0, 20))}`)).toBe(`s=${tok("GOOD")}`);
    expect(set.redact(`b=${bad}`)).toBe(`b=${tok("BAD")}`);
    expect(set.redact(`bs=${bad.slice(6, 26)}`)).toBe(`bs=${tok("BAD")}`);
  });
});

describe("streaming equals one-shot redaction", () => {
  it("over 100 random chunkings (fixed seed)", () => {
    let seed = 42;
    const rnd = (n: number) => {
      seed = (Math.imul(seed, 1103515245) + 12345) >>> 0;
      return (seed >>> 8) % n;
    };
    const S1 = fakeSecret(40, 61);
    const S2 = "postgres://admin:hunter2-very-long@db.internal:5432/app";
    const entries: RedactionEntry[] = [
      { name: "A", value: S1 },
      { name: "B", value: S2 },
      { name: "PIN", value: "424242" },
    ];
    const set = new RedactionSet(entries);
    const pieces = [
      S1,
      S2,
      S1.slice(3, 25),
      S2.slice(10, 40),
      Buffer.from(S1).toString("base64"),
      Buffer.from(`x:${S2}`).toString("base64url"),
      Buffer.from(S1).toString("hex"),
      encodeURIComponent(S2),
      JSON.stringify(S2),
      "424242",
      " ",
      "\n",
      "hello world ",
      "abc",
    ];
    for (let trial = 0; trial < 100; trial++) {
      let text = "";
      const n = 1 + rnd(12);
      for (let k = 0; k < n; k++) text += pieces[rnd(pieces.length)];
      const expected = set.redact(text);
      const chunks: string[] = [];
      for (let p = 0; p < text.length;) {
        const len = 1 + rnd(30);
        chunks.push(text.slice(p, p + len));
        p += len;
      }
      const { out } = stream(set, chunks);
      expect(out, JSON.stringify(chunks)).toBe(expected);
      expect(out).not.toContain(S1.slice(0, 16));
      expect(out).not.toContain("hunter2-very-long");
    }
  });
});

/** Deterministic lowercase hex (fake). */
function fakeHex(length: number, seed: number): string {
  let x = seed >>> 0;
  let out = "";
  for (let i = 0; i < length; i++) {
    x = (Math.imul(x, 1103515245) + 12345) >>> 0;
    out += ((x >>> 16) & 15).toString(16);
  }
  return out;
}

describe("JSON credentials holding a PEM (review 4 #1)", () => {
  const pemBody = Array.from({ length: 4 }, (_, i) => fakeSecret(64, 300 + i));
  const pem = `-----BEGIN PRIVATE KEY-----\n${pemBody.join("\n")}\n-----END PRIVATE KEY-----\n`;
  const account = {
    type: "service_account",
    project_id: "demo-project",
    private_key_id: fakeHex(40, 310),
    private_key: pem,
    client_email: "svc@demo-project.iam.gserviceaccount.com",
    refresh_token: fakeSecret(40, 311),
  };

  for (const [shape, value] of [
    ["compact", JSON.stringify(account)],
    ["pretty-printed", JSON.stringify(account, null, 2)],
  ] as const) {
    it(`slices the key body and the token fields of ${shape} JSON`, () => {
      expect(value.length).toBeLessThanOrEqual(SLICE_MAX_LENGTH);
      expect(value.length).toBeGreaterThan(DERIVE_MAX_LENGTH); // no encoded forms to fall back on
      const regions = sliceRegions(value);
      expect(regions).toEqual(
        expect.arrayContaining([...pemBody, account.private_key_id, account.refresh_token]),
      );
      expect(regions.some((r) => r.includes("{") || r.includes("BEGIN"))).toBe(false);

      const set = new RedactionSet([{ name: "GCP_SA", value }]);
      const body = pemBody[1].slice(10, 45); // 35 chars of the key body
      expect(set.redact(`key: ${body}...`)).toBe(`key: ${tok("GCP_SA")}...`);
      expect(set.redact(`tok=${account.refresh_token.slice(0, 20)}`)).toBe(`tok=${tok("GCP_SA")}`);
      expect(set.redact(`kid ${account.private_key_id.slice(5, 30)} x`)).toBe(
        `kid ${tok("GCP_SA")} x`,
      );
    });
  }

  it("a PEM pasted into .env with literal \\n separators yields its body lines", () => {
    const escaped = pem.replace(/\n/g, "\\n");
    expect(sliceRegions(escaped)).toEqual(pemBody);
  });

  it("outside JSON, never returns an empty region list", () => {
    expect(sliceRegions("-----BEGIN X-----\n-----END X-----")).toEqual([
      "-----BEGIN X-----\n-----END X-----",
    ]);
  });

  it("a JSON value with no credential string yields no regions (still matched verbatim)", () => {
    const value = '{"username":"admin","password":"Xk9#qL2!"}';
    expect(sliceRegions(value)).toEqual([]);
    expect(sliceRegions('{"a":1,"b":true}')).toEqual([]);
    const set = new RedactionSet([{ name: "DB_LOGIN", value }]);
    expect(set.slicing).toBe(false);
    const unrelated = '{"username":"admin","role":"owner"}';
    expect(set.redact(unrelated)).toBe(unrelated);
    expect(set.redact(`cfg=${value}`)).toBe(`cfg=${tok("DB_LOGIN")}`);
  });
});

describe("slice variety rule (review 4 #3)", () => {
  it("slices a 20-digit account number at 17 and 18 chars", () => {
    const acct = "73019582640157396284";
    const set = new RedactionSet([{ name: "ACCOUNT_NO", value: acct }]);
    expect(set.slicing).toBe(true);
    expect(set.redact(`ref ${acct.slice(0, 17)} ok`)).toBe(`ref ${tok("ACCOUNT_NO")} ok`);
    expect(set.redact(`ref ${acct.slice(2, 20)} ok`)).toBe(`ref ${tok("ACCOUNT_NO")} ok`);
  });

  it("slices a 32-char hex token", () => {
    const hex = fakeHex(32, 320);
    const set = new RedactionSet([{ name: "HEX_TOKEN", value: hex }]);
    expect(set.redact(`t=${hex.slice(6, 26)};`)).toBe(`t=${tok("HEX_TOKEN")};`);
  });

  it("never indexes repeated-character runs", () => {
    for (const run of ["0".repeat(24), "x".repeat(24), "ab".repeat(12)]) {
      const set = new RedactionSet([{ name: "RUN", value: run }]);
      expect(set.slicing, run).toBe(false);
      expect(set.redact(`pad ${run.slice(0, 20)} pad`)).toBe(`pad ${run.slice(0, 20)} pad`);
    }
  });
});

describe("table size (review 4 #4)", () => {
  // Measured building 200 sliceable 1000-char secrets (Node 26, x86-64, cold,
  // retained after GC): before, Set/Map tables, about 104 MB of heap and
  // 295 ms; now, sorted typed arrays behind a bit filter, about 14 MB and
  // 85 ms. The bound here is loose so a regression shows without flaking.
  it("builds 200 x 1000-char secrets in well under a second", () => {
    const entries = Array.from({ length: 200 }, (_, i) => ({
      name: `TOKEN_${i}`,
      value: fakeSecret(1000, 1000 + i),
    }));
    const t0 = performance.now();
    const set = new RedactionSet(entries);
    const ms = performance.now() - t0;
    expect(set.slicing).toBe(true);
    expect(ms).toBeLessThan(1000);
    const v = entries[123].value;
    expect(set.redact(`x ${v.slice(400, 430)} y`)).toBe(`x ${tok("TOKEN_123")} y`);
    // An ordinary line still flushes whole.
    const s = new RedactionStream(set);
    expect(s.write("INFO all good\n")).toBe("INFO all good\n");
  });
});

describe("public strings inside a JSON credential (review 5 #2)", () => {
  // Fake key material, assembled at runtime so secret scanning has nothing to flag.
  const body = Array.from({ length: 25 }, (_, i) => fakeSecret(64, 800 + i));
  const pem = ["-----BEGIN PRIVATE KEY-----", ...body, "-----END PRIVATE KEY-----", ""].join("\n");
  const account = {
    type: "service_account",
    project_id: "demo-project-123456",
    private_key_id: fakeHex(40, 860),
    private_key: pem,
    client_email: "deployer@demo-project-123456.iam.gserviceaccount.com",
    client_id: "104857364829105738291",
    auth_uri: "https://accounts.google.com/o/oauth2/auth",
    token_uri: "https://oauth2.googleapis.com/token",
    auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
    client_x509_cert_url:
      "https://www.googleapis.com/robot/v1/metadata/x509/deployer%40demo-project-123456.iam.gserviceaccount.com",
    universe_domain: "googleapis.com",
    refresh_token: fakeSecret(48, 861),
  };
  const set = new RedactionSet([{ name: "GCP_SA_JSON", value: JSON.stringify(account, null, 2) }]);

  it("leaves gcloud output and Google's public cert URL untouched", () => {
    const gcloud =
      "DISPLAY NAME  EMAIL                                                 DISABLED\n" +
      "deployer      deployer@demo-project-123456.iam.gserviceaccount.com  False";
    expect(set.redact(gcloud)).toBe(gcloud);
    const certs =
      "fetching https://www.googleapis.com/oauth2/v1/certs and " +
      "https://www.googleapis.com/robot/v1/metadata/x509/deployer%40demo-project-123456.iam.gserviceaccount.com";
    expect(set.redact(certs)).toBe(certs);
  });

  it("still slices the private key body, private_key_id and refresh_token", () => {
    expect(set.redact(`k ${body[3].slice(10, 45)} k`)).toBe(`k ${tok("GCP_SA_JSON")} k`);
    expect(set.redact(`id ${account.private_key_id.slice(2, 30)} id`)).toBe(
      `id ${tok("GCP_SA_JSON")} id`,
    );
    expect(set.redact(`rt ${account.refresh_token.slice(10, 40)} rt`)).toBe(
      `rt ${tok("GCP_SA_JSON")} rt`,
    );
  });

  it("a PEM is sliced whatever key it sits under", () => {
    expect(sliceRegions(JSON.stringify({ blob: pem }))).toEqual(body);
  });
});

describe("slices: false (review 5 #1)", () => {
  it("builds no slice tables: whole values and encoded forms only", () => {
    const S = fakeSecret(40, 900);
    const set = new RedactionSet([{ name: "K", value: S }], { slices: false });
    expect(set.slicing).toBe(false);
    expect(set.redact(`v=${S}`)).toBe(`v=${tok("K")}`);
    expect(set.redact(`b=${Buffer.from(S).toString("base64")}`)).toMatch(/^b=\[QRING:REDACTED:K\]/);
    expect(set.redact(`s=${S.slice(0, 30)}`)).toBe(`s=${S.slice(0, 30)}`);
  });
});

describe("overlapping slices of different secrets (review 5 #4)", () => {
  it("finds a run of another secret that starts inside a hit", () => {
    const k0 = fakeSecret(40, 910);
    // k2's 20th char is k0's first, so a k2 run can end where a k0 run begins.
    const k2 = `${fakeSecret(19, 911)}${k0[0]}${fakeSecret(20, 912)}`;
    const set = new RedactionSet([
      { name: "K0", value: k0 },
      { name: "K2", value: k2 },
    ]);
    const text = `x ${k2.slice(0, 20)}${k0.slice(1, 16)} y`;
    const out = set.redact(text);
    expect(out).toBe(`x ${tok("K2")} y`);
    expect(out).not.toContain(k0.slice(1, 16));
    const streamed = stream(set, [text.slice(0, 13), text.slice(13)]).out;
    expect(streamed).toBe(out);
  });

  it("seeded multi-secret fuzz: no raw 16-char run survives, streaming equals one-shot", () => {
    let seed = 7;
    const rnd = (n: number) => {
      seed = (Math.imul(seed, 1103515245) + 12345) >>> 0;
      return (seed >>> 8) % n;
    };
    const k0 = fakeSecret(40, 920);
    const k1 = `${k0.slice(28)}${fakeSecret(28, 921)}`; // shares 12 chars with k0's tail
    const k2 = `${fakeSecret(30, 922)}${k1.slice(0, 10)}`; // ends with k1's head
    const secrets = [k0, k1, k2];
    const set = new RedactionSet(secrets.map((value, i) => ({ name: `K${i}`, value })));
    for (let trial = 0; trial < 200; trial++) {
      let text = "";
      const n = 1 + rnd(6);
      for (let k = 0; k < n; k++) {
        const s = secrets[rnd(3)];
        const len = SLICE_WINDOW + rnd(s.length - SLICE_WINDOW + 1);
        const from = rnd(s.length - len + 1);
        text += s.slice(from, from + len) + (rnd(3) === 0 ? " " : "");
      }
      const once = set.redact(text);
      for (const s of secrets) {
        for (let o = 0; o + SLICE_WINDOW <= s.length; o++) {
          expect(once.includes(s.slice(o, o + SLICE_WINDOW)), `trial ${trial}: ${text}`).toBe(
            false,
          );
        }
      }
      const chunks: string[] = [];
      for (let p = 0; p < text.length;) {
        const len = 1 + rnd(25);
        chunks.push(text.slice(p, p + len));
        p += len;
      }
      expect(stream(set, chunks).out, `trial ${trial}: ${JSON.stringify(chunks)}`).toBe(once);
    }
  });
});
