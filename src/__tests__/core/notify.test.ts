import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const spawnMock = vi.hoisted(() => vi.fn());
vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return { ...actual, spawn: spawnMock };
});

import {
  notifyUser,
  notifyApprovalRequested,
  notificationsEnabled,
  resetNotifyThrottle,
} from "../../core/notify.js";

function fakeChild() {
  return { on: vi.fn(), unref: vi.fn() };
}

// notifyUser branches on process.platform (and no-ops on win32) — pin it to
// linux so these tests behave identically on every CI runner.
const realPlatform = Object.getOwnPropertyDescriptor(process, "platform")!;

beforeEach(() => {
  Object.defineProperty(process, "platform", { value: "linux" });
  resetNotifyThrottle();
  spawnMock.mockReset();
  spawnMock.mockReturnValue(fakeChild());
  vi.useFakeTimers();
});

afterEach(() => {
  Object.defineProperty(process, "platform", realPlatform);
  delete process.env.QRING_NOTIFY;
  vi.useRealTimers();
});

describe("notifyUser", () => {
  it("uses notify-send on linux, detached, without a shell", () => {
    const launched = notifyUser("title", "body");
    expect(launched).toBe(true);
    const [cmd, args, opts] = spawnMock.mock.calls[0];
    expect(cmd).toBe("notify-send");
    expect(args).toContain("title");
    expect(opts.detached).toBe(true);
    expect(opts.shell).toBeUndefined();
  });

  it("never throws when spawn fails", () => {
    spawnMock.mockImplementation(() => {
      throw new Error("ENOENT");
    });
    expect(notifyUser("t", "b")).toBe(false);
  });
});

describe("notifyApprovalRequested", () => {
  it("notifies with the key and the approve command", () => {
    notifyApprovalRequested("PROD_DB_PASSWORD", "mcp");
    const [, args] = spawnMock.mock.calls[0];
    const payload = args.join(" ");
    expect(payload).toContain("PROD_DB_PASSWORD");
    expect(payload).toContain("qring approve PROD_DB_PASSWORD");
  });

  it("throttles repeats per key within 5 minutes", () => {
    notifyApprovalRequested("KEY_A", "mcp");
    notifyApprovalRequested("KEY_A", "mcp");
    notifyApprovalRequested("KEY_B", "mcp");
    expect(spawnMock).toHaveBeenCalledTimes(2);

    vi.advanceTimersByTime(5 * 60 * 1000 + 1);
    notifyApprovalRequested("KEY_A", "mcp");
    expect(spawnMock).toHaveBeenCalledTimes(3);
  });

  it("QRING_NOTIFY=off disables notifications", () => {
    process.env.QRING_NOTIFY = "off";
    expect(notificationsEnabled()).toBe(false);
    notifyApprovalRequested("KEY", "mcp");
    expect(spawnMock).not.toHaveBeenCalled();
  });
});
