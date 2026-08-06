/**
 * Secret Liveness Validation: test if a secret is actually valid
 * with its target service using a pluggable provider system.
 */

import { httpRequest } from "../utils/http-request.js";
import { generateSecret, type NoiseFormat } from "./noise.js";
import { checkSSRF } from "./ssrf.js";

export interface ValidationResult {
  valid: boolean;
  status: "valid" | "invalid" | "error" | "unknown";
  message: string;
  latencyMs: number;
  provider: string;
}

export interface Provider {
  name: string;
  description: string;
  /** Prefixes that auto-detect to this provider */
  prefixes?: string[];
  validate(value: string): Promise<ValidationResult>;
}

function makeRequest(
  url: string,
  headers: Record<string, string>,
  timeoutMs = 10000,
): Promise<{ statusCode: number; body: string }> {
  return httpRequest({ url, method: "GET", headers, timeoutMs });
}

export class ProviderRegistry {
  private providers = new Map<string, Provider>();

  register(provider: Provider): void {
    this.providers.set(provider.name, provider);
  }

  get(name: string): Provider | undefined {
    return this.providers.get(name);
  }

  detectProvider(
    value: string,
    hints?: { provider?: string; prefix?: string },
  ): Provider | undefined {
    if (hints?.provider) {
      return this.providers.get(hints.provider);
    }

    for (const provider of this.providers.values()) {
      if (provider.prefixes) {
        for (const pfx of provider.prefixes) {
          if (value.startsWith(pfx)) return provider;
        }
      }
    }

    return undefined;
  }

  listProviders(): Provider[] {
    return [...this.providers.values()];
  }
}

// ─── Built-in Providers ───

/**
 * Factory for the common liveness shape: one authenticated GET against a
 * cheap endpoint, with the standard 200/401/403/429 interpretation.
 */
function livenessProvider(cfg: {
  name: string;
  description: string;
  prefixes?: string[];
  url: string;
  headers: (value: string) => Record<string, string>;
}): Provider {
  return {
    name: cfg.name,
    description: cfg.description,
    prefixes: cfg.prefixes,
    async validate(value: string): Promise<ValidationResult> {
      const start = Date.now();
      try {
        const { statusCode } = await makeRequest(cfg.url, {
          "User-Agent": "q-ring-validator/1.0",
          ...cfg.headers(value),
        });
        const latencyMs = Date.now() - start;

        if (statusCode === 200)
          return { valid: true, status: "valid", message: "API key is valid", latencyMs, provider: cfg.name };
        if (statusCode === 401 || statusCode === 403)
          return { valid: false, status: "invalid", message: `Invalid or revoked API key (${statusCode})`, latencyMs, provider: cfg.name };
        if (statusCode === 429)
          return { valid: true, status: "error", message: "Rate limited — key may be valid", latencyMs, provider: cfg.name };
        return { valid: false, status: "error", message: `Unexpected status ${statusCode}`, latencyMs, provider: cfg.name };
      } catch (err) {
        return { valid: false, status: "error", message: `${err instanceof Error ? err.message : "Network error"}`, latencyMs: Date.now() - start, provider: cfg.name };
      }
    },
  };
}

// AI-stack providers. Keys are only ever sent in headers (never the URL —
// URLs land in server logs), against the cheapest read-only endpoint each
// platform has.

const anthropicProvider = livenessProvider({
  name: "anthropic",
  description: "Anthropic API key validation",
  prefixes: ["sk-ant-"],
  url: "https://api.anthropic.com/v1/models?limit=1",
  headers: (value) => ({ "x-api-key": value, "anthropic-version": "2023-06-01" }),
});

const openrouterProvider = livenessProvider({
  name: "openrouter",
  description: "OpenRouter API key validation",
  prefixes: ["sk-or-"],
  url: "https://openrouter.ai/api/v1/key",
  headers: (value) => ({ Authorization: `Bearer ${value}` }),
});

const googleAiProvider = livenessProvider({
  name: "google-ai",
  description: "Google AI (Gemini) API key validation",
  prefixes: ["AIza"],
  url: "https://generativelanguage.googleapis.com/v1beta/models?pageSize=1",
  headers: (value) => ({ "x-goog-api-key": value }),
});

const groqProvider = livenessProvider({
  name: "groq",
  description: "Groq API key validation",
  prefixes: ["gsk_"],
  url: "https://api.groq.com/openai/v1/models",
  headers: (value) => ({ Authorization: `Bearer ${value}` }),
});

const huggingfaceProvider = livenessProvider({
  name: "huggingface",
  description: "Hugging Face token validation",
  prefixes: ["hf_"],
  url: "https://huggingface.co/api/whoami-v2",
  headers: (value) => ({ Authorization: `Bearer ${value}` }),
});

// No prefix: ElevenLabs "sk_..." would shadow Stripe's sk_live_/sk_test_,
// so it is explicit-only (set `provider: "elevenlabs"` on the secret/manifest).
const elevenlabsProvider = livenessProvider({
  name: "elevenlabs",
  description: "ElevenLabs API key validation (explicit-only — set provider on the secret)",
  url: "https://api.elevenlabs.io/v1/user",
  headers: (value) => ({ "xi-api-key": value }),
});

// No prefix: Vercel tokens have no stable public prefix — explicit-only.
const vercelProvider = livenessProvider({
  name: "vercel",
  description: "Vercel token validation (explicit-only — set provider on the secret)",
  url: "https://api.vercel.com/v2/user",
  headers: (value) => ({ Authorization: `Bearer ${value}` }),
});

const openaiProvider: Provider = {
  name: "openai",
  description: "OpenAI API key validation",
  prefixes: ["sk-"],
  async validate(value: string): Promise<ValidationResult> {
    const start = Date.now();
    try {
      const { statusCode } = await makeRequest(
        "https://api.openai.com/v1/models?limit=1",
        {
          Authorization: `Bearer ${value}`,
          "User-Agent": "q-ring-validator/1.0",
        },
      );
      const latencyMs = Date.now() - start;

      if (statusCode === 200)
        return { valid: true, status: "valid", message: "API key is valid", latencyMs, provider: "openai" };
      if (statusCode === 401)
        return { valid: false, status: "invalid", message: "Invalid or revoked API key", latencyMs, provider: "openai" };
      if (statusCode === 429)
        return { valid: true, status: "error", message: "Rate limited — key may be valid", latencyMs, provider: "openai" };
      return { valid: false, status: "error", message: `Unexpected status ${statusCode}`, latencyMs, provider: "openai" };
    } catch (err) {
      return { valid: false, status: "error", message: `${err instanceof Error ? err.message : "Network error"}`, latencyMs: Date.now() - start, provider: "openai" };
    }
  },
};

const stripeProvider: Provider = {
  name: "stripe",
  description: "Stripe API key validation",
  prefixes: ["sk_live_", "sk_test_", "rk_live_", "rk_test_", "pk_live_", "pk_test_"],
  async validate(value: string): Promise<ValidationResult> {
    const start = Date.now();
    try {
      const { statusCode } = await makeRequest(
        "https://api.stripe.com/v1/balance",
        {
          Authorization: `Bearer ${value}`,
          "User-Agent": "q-ring-validator/1.0",
        },
      );
      const latencyMs = Date.now() - start;

      if (statusCode === 200)
        return { valid: true, status: "valid", message: "API key is valid", latencyMs, provider: "stripe" };
      if (statusCode === 401)
        return { valid: false, status: "invalid", message: "Invalid or revoked API key", latencyMs, provider: "stripe" };
      if (statusCode === 429)
        return { valid: true, status: "error", message: "Rate limited — key may be valid", latencyMs, provider: "stripe" };
      return { valid: false, status: "error", message: `Unexpected status ${statusCode}`, latencyMs, provider: "stripe" };
    } catch (err) {
      return { valid: false, status: "error", message: `${err instanceof Error ? err.message : "Network error"}`, latencyMs: Date.now() - start, provider: "stripe" };
    }
  },
};

const githubProvider: Provider = {
  name: "github",
  description: "GitHub token validation",
  prefixes: ["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"],
  async validate(value: string): Promise<ValidationResult> {
    const start = Date.now();
    try {
      const { statusCode } = await makeRequest(
        "https://api.github.com/user",
        {
          Authorization: `token ${value}`,
          "User-Agent": "q-ring-validator/1.0",
          Accept: "application/vnd.github+json",
        },
      );
      const latencyMs = Date.now() - start;

      if (statusCode === 200)
        return { valid: true, status: "valid", message: "Token is valid", latencyMs, provider: "github" };
      if (statusCode === 401)
        return { valid: false, status: "invalid", message: "Invalid or expired token", latencyMs, provider: "github" };
      if (statusCode === 403)
        return { valid: false, status: "invalid", message: "Token lacks required permissions", latencyMs, provider: "github" };
      if (statusCode === 429)
        return { valid: true, status: "error", message: "Rate limited — token may be valid", latencyMs, provider: "github" };
      return { valid: false, status: "error", message: `Unexpected status ${statusCode}`, latencyMs, provider: "github" };
    } catch (err) {
      return { valid: false, status: "error", message: `${err instanceof Error ? err.message : "Network error"}`, latencyMs: Date.now() - start, provider: "github" };
    }
  },
};

const awsProvider: Provider = {
  name: "aws",
  description: "AWS access key validation (checks key format only — full STS validation requires secret key + region)",
  prefixes: ["AKIA", "ASIA"],
  async validate(value: string): Promise<ValidationResult> {
    const start = Date.now();
    const latencyMs = Date.now() - start;

    if (/^(AKIA|ASIA)[A-Z0-9]{16}$/.test(value)) {
      return { valid: true, status: "unknown", message: "Valid AWS access key format (STS validation requires secret key)", latencyMs, provider: "aws" };
    }
    return { valid: false, status: "invalid", message: "Invalid AWS access key format", latencyMs, provider: "aws" };
  },
};

const httpProvider: Provider = {
  name: "http",
  description: "Generic HTTP endpoint validation",
  async validate(value: string, url?: string): Promise<ValidationResult> {
    const start = Date.now();

    if (!url) {
      return { valid: false, status: "unknown", message: "No validation URL configured", latencyMs: 0, provider: "http" };
    }

    const ssrfBlock = await checkSSRF(url);
    if (ssrfBlock) {
      return { valid: false, status: "error", message: `SSRF blocked: ${ssrfBlock}`, latencyMs: Date.now() - start, provider: "http" };
    }

    try {
      const { statusCode } = await makeRequest(url, {
        Authorization: `Bearer ${value}`,
        "User-Agent": "q-ring-validator/1.0",
      });
      const latencyMs = Date.now() - start;

      if (statusCode >= 200 && statusCode < 300)
        return { valid: true, status: "valid", message: `Endpoint returned ${statusCode}`, latencyMs, provider: "http" };
      if (statusCode === 401 || statusCode === 403)
        return { valid: false, status: "invalid", message: `Authentication failed (${statusCode})`, latencyMs, provider: "http" };
      return { valid: false, status: "error", message: `Unexpected status ${statusCode}`, latencyMs, provider: "http" };
    } catch (err) {
      return { valid: false, status: "error", message: `${err instanceof Error ? err.message : "Network error"}`, latencyMs: Date.now() - start, provider: "http" };
    }
  },
};

export const registry = new ProviderRegistry();
// Prefix detection iterates in registration order: anthropic (sk-ant-) and
// openrouter (sk-or-) MUST come before openai, whose bare "sk-" would
// otherwise shadow them.
registry.register(anthropicProvider);
registry.register(openrouterProvider);
registry.register(openaiProvider);
registry.register(googleAiProvider);
registry.register(groqProvider);
registry.register(huggingfaceProvider);
registry.register(elevenlabsProvider);
registry.register(vercelProvider);
registry.register(stripeProvider);
registry.register(githubProvider);
registry.register(awsProvider);
registry.register(httpProvider);

/**
 * Validate a secret value against its detected or specified provider.
 */
export async function validateSecret(
  value: string,
  opts?: { provider?: string; validationUrl?: string },
): Promise<ValidationResult> {
  const provider = opts?.provider
    ? registry.get(opts.provider)
    : registry.detectProvider(value);

  if (!provider) {
    return {
      valid: false,
      status: "unknown",
      message: "No provider detected — set a provider in the manifest or secret metadata",
      latencyMs: 0,
      provider: "none",
    };
  }

  if (provider.name === "http" && opts?.validationUrl) {
    return (provider as any).validate(value, opts.validationUrl);
  }

  return provider.validate(value);
}

// ─── Rotation Support ───

export interface RotationResult {
  rotated: boolean;
  provider: string;
  message: string;
  newValue?: string;
}

export interface RotatableProvider extends Provider {
  rotate?(currentValue: string): Promise<RotationResult>;
  supportsRotation: boolean;
}

/**
 * Attempt provider-native rotation of a secret.
 * Falls back to local generation if the provider does not support native rotation.
 */
export async function rotateWithProvider(
  value: string,
  providerName?: string,
): Promise<RotationResult> {
  const provider = providerName
    ? registry.get(providerName)
    : registry.detectProvider(value);

  if (!provider) {
    return { rotated: false, provider: "none", message: "No provider detected for rotation" };
  }

  const rotatable = provider as RotatableProvider;
  if (rotatable.supportsRotation && rotatable.rotate) {
    return rotatable.rotate(value);
  }

  // Fall back to local generation
  const format: NoiseFormat = "api-key";
  const newValue = generateSecret({ format, length: 48 });
  return {
    rotated: true,
    provider: provider.name,
    message: `Provider "${provider.name}" does not support native rotation — generated new value locally`,
    newValue,
  };
}

// ─── CI Scan ───

export interface CiScanResult {
  key: string;
  validation: ValidationResult;
  requiresRotation: boolean;
}

/**
 * CI-oriented batch validation: validates all secrets and returns
 * a structured report suitable for CI pipeline gating.
 */
export async function ciValidateBatch(
  secrets: { key: string; value: string; provider?: string; validationUrl?: string }[],
): Promise<{ results: CiScanResult[]; allValid: boolean; failCount: number }> {
  const results: CiScanResult[] = [];

  for (const s of secrets) {
    const validation = await validateSecret(s.value, {
      provider: s.provider,
      validationUrl: s.validationUrl,
    });

    results.push({
      key: s.key,
      validation,
      requiresRotation: validation.status === "invalid",
    });
  }

  const failCount = results.filter((r) => !r.validation.valid).length;

  return { results, allValid: failCount === 0, failCount };
}
