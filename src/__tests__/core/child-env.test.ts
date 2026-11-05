import { describe, it, expect } from "vitest";
import { withoutQringCredentials, QRING_CREDENTIAL_ENV_VARS } from "../../core/child-env.js";

describe("withoutQringCredentials", () => {
  it("drops q-ring's master-key variables and undefined values, keeps the rest", () => {
    const out = withoutQringCredentials({
      PATH: "/usr/bin",
      HOME: "/home/u",
      QRING_FILE_PASSPHRASE: "file-master",
      QRING_MEMORY_PASSPHRASE: "memory-master",
      QRING_BACKEND: "file",
      EMPTY: undefined,
    });
    expect(out).toEqual({ PATH: "/usr/bin", HOME: "/home/u", QRING_BACKEND: "file" });
  });

  it("covers both master keys", () => {
    expect(QRING_CREDENTIAL_ENV_VARS).toEqual(["QRING_FILE_PASSPHRASE", "QRING_MEMORY_PASSPHRASE"]);
  });

  it("strips them whatever the case (Windows env names are case-insensitive)", () => {
    const out = withoutQringCredentials({
      Qring_File_Passphrase: "file-master",
      qring_memory_passphrase: "memory-master",
      Path: "C:\\Windows",
    });
    expect(out).toEqual({ Path: "C:\\Windows" });
  });
});
