import { describe, it, expect, vi, beforeEach } from "vitest";

const httpRequestMock = vi.hoisted(() => vi.fn());
vi.mock("../../utils/http-request.js", () => ({ httpRequest: httpRequestMock }));

import { registry, validateSecret } from "../../core/validate.js";

beforeEach(() => {
  httpRequestMock.mockReset();
  httpRequestMock.mockResolvedValue({ statusCode: 200, body: "{}" });
});

describe("provider detection", () => {
  it("sk-ant- detects anthropic, not openai", () => {
    expect(registry.detectProvider("sk-ant-api03-xxxx")?.name).toBe("anthropic");
  });

  it("sk-or- detects openrouter, not openai", () => {
    expect(registry.detectProvider("sk-or-v1-xxxx")?.name).toBe("openrouter");
  });

  it("plain sk- still detects openai", () => {
    expect(registry.detectProvider("sk-proj-xxxx")?.name).toBe("openai");
  });

  it("detects the rest of the AI stack by prefix", () => {
    expect(registry.detectProvider("AIzaSyXXXX")?.name).toBe("google-ai");
    expect(registry.detectProvider("gsk_xxxx")?.name).toBe("groq");
    expect(registry.detectProvider("hf_xxxx")?.name).toBe("huggingface");
  });

  it("stripe prefixes are not shadowed", () => {
    expect(registry.detectProvider("sk_live_xxxx")?.name).toBe("stripe");
  });

  it("elevenlabs and vercel are explicit-only", () => {
    expect(registry.get("elevenlabs")).toBeDefined();
    expect(registry.get("vercel")).toBeDefined();
    expect(registry.get("elevenlabs")?.prefixes).toBeUndefined();
    expect(registry.get("vercel")?.prefixes).toBeUndefined();
  });
});

describe("AI-stack liveness checks", () => {
  it("anthropic sends the key as x-api-key with a version header, never in the URL", async () => {
    const result = await validateSecret("sk-ant-api03-abc");
    expect(result.provider).toBe("anthropic");
    expect(result.valid).toBe(true);

    const req = httpRequestMock.mock.calls[0][0];
    expect(req.url).toBe("https://api.anthropic.com/v1/models?limit=1");
    expect(req.url).not.toContain("sk-ant");
    expect(req.headers["x-api-key"]).toBe("sk-ant-api03-abc");
    expect(req.headers["anthropic-version"]).toBeDefined();
  });

  it("google-ai sends the key as x-goog-api-key, not a query param", async () => {
    await validateSecret("AIzaSyTest");
    const req = httpRequestMock.mock.calls[0][0];
    expect(req.url).not.toContain("AIza");
    expect(req.headers["x-goog-api-key"]).toBe("AIzaSyTest");
  });

  it("elevenlabs validates via xi-api-key when explicitly selected", async () => {
    const result = await validateSecret("sk_whatever", { provider: "elevenlabs" });
    expect(result.provider).toBe("elevenlabs");
    const req = httpRequestMock.mock.calls[0][0];
    expect(req.headers["xi-api-key"]).toBe("sk_whatever");
  });

  it("maps 401 to invalid and 429 to may-be-valid", async () => {
    httpRequestMock.mockResolvedValueOnce({ statusCode: 401, body: "" });
    const invalid = await validateSecret("gsk_bad");
    expect(invalid.status).toBe("invalid");
    expect(invalid.valid).toBe(false);

    httpRequestMock.mockResolvedValueOnce({ statusCode: 429, body: "" });
    const limited = await validateSecret("gsk_limited");
    expect(limited.valid).toBe(true);
    expect(limited.status).toBe("error");
  });

  it("network failure maps to error, not invalid", async () => {
    httpRequestMock.mockRejectedValueOnce(new Error("ECONNREFUSED"));
    const result = await validateSecret("hf_token");
    expect(result.status).toBe("error");
    expect(result.message).toContain("ECONNREFUSED");
  });
});
