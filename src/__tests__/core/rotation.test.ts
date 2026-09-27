import { describe, it, expect } from "vitest";
import {
  rotationStatus,
  describeRotation,
  compareRotationUrgency,
  dueSoonWindowDays,
} from "../../core/rotation.js";

const DAY = 86_400_000;
const NOW = Date.parse("2026-09-26T12:00:00.000Z");
const daysAgo = (n: number) => new Date(NOW - n * DAY).toISOString();

describe("rotationStatus — anchor selection", () => {
  it("measures age from rotatedAt when present", () => {
    const r = rotationStatus(
      { createdAt: daysAgo(100), updatedAt: daysAgo(50), rotatedAt: daysAgo(10) },
      NOW,
    );
    expect(r.lastRotatedAt).toBe(daysAgo(10));
    expect(r.ageDays).toBe(10);
  });

  it("falls back to updatedAt, then createdAt, for pre-0.18 envelopes", () => {
    const viaUpdated = rotationStatus({ createdAt: daysAgo(100), updatedAt: daysAgo(30) }, NOW);
    expect(viaUpdated.lastRotatedAt).toBe(daysAgo(30));
    expect(viaUpdated.ageDays).toBe(30);

    const viaCreated = rotationStatus(
      { createdAt: daysAgo(100), updatedAt: undefined as unknown as string },
      NOW,
    );
    expect(viaCreated.lastRotatedAt).toBe(daysAgo(100));
    expect(viaCreated.ageDays).toBe(100);
  });

  it("floors partial days and never reports a negative age", () => {
    expect(rotationStatus({ createdAt: daysAgo(2.9), updatedAt: daysAgo(2.9) }, NOW).ageDays).toBe(2);
    expect(rotationStatus({ createdAt: daysAgo(-3), updatedAt: daysAgo(-3) }, NOW).ageDays).toBe(0);
  });

  it("treats an unparseable anchor as just now instead of throwing", () => {
    const r = rotationStatus({ createdAt: "garbage", updatedAt: "garbage", rotateEveryDays: 30 }, NOW);
    expect(r.ageDays).toBe(0);
    expect(r.state).toBe("ok");
    expect(r.daysUntilDue).toBe(30);
  });

  it("accepts a Date for now", () => {
    const r = rotationStatus({ createdAt: daysAgo(5), updatedAt: daysAgo(5) }, new Date(NOW));
    expect(r.ageDays).toBe(5);
  });
});

describe("rotationStatus — unscheduled", () => {
  it("is unscheduled with null due fields when no interval is set", () => {
    const r = rotationStatus({ createdAt: daysAgo(400), updatedAt: daysAgo(400) }, NOW);
    expect(r).toEqual({
      lastRotatedAt: daysAgo(400),
      ageDays: 400,
      rotateEveryDays: null,
      dueAt: null,
      daysUntilDue: null,
      state: "unscheduled",
    });
  });

  it("treats a zero or negative interval as unscheduled", () => {
    expect(
      rotationStatus({ createdAt: daysAgo(1), updatedAt: daysAgo(1), rotateEveryDays: 0 }, NOW).state,
    ).toBe("unscheduled");
    expect(
      rotationStatus({ createdAt: daysAgo(1), updatedAt: daysAgo(1), rotateEveryDays: -5 }, NOW).state,
    ).toBe("unscheduled");
  });
});

describe("rotationStatus — scheduled states", () => {
  it("is ok well before the due date and reports dueAt/daysUntilDue", () => {
    const r = rotationStatus(
      { createdAt: daysAgo(10), updatedAt: daysAgo(10), rotatedAt: daysAgo(10), rotateEveryDays: 90 },
      NOW,
    );
    expect(r.state).toBe("ok");
    expect(r.rotateEveryDays).toBe(90);
    expect(r.dueAt).toBe(new Date(NOW + 80 * DAY).toISOString());
    expect(r.daysUntilDue).toBe(80);
  });

  it("due-soon window is min(20% of interval, 7 days)", () => {
    expect(dueSoonWindowDays(90)).toBe(7); // 18 > 7 → capped
    expect(dueSoonWindowDays(30)).toBe(6); // 20% of 30
    expect(dueSoonWindowDays(10)).toBe(2);
  });

  it("becomes due-soon inside the window (7-day cap for long intervals)", () => {
    const outside = rotationStatus(
      { createdAt: daysAgo(82), updatedAt: daysAgo(82), rotateEveryDays: 90 },
      NOW,
    );
    expect(outside.state).toBe("ok");
    expect(outside.daysUntilDue).toBe(8);

    const inside = rotationStatus(
      { createdAt: daysAgo(83), updatedAt: daysAgo(83), rotateEveryDays: 90 },
      NOW,
    );
    expect(inside.state).toBe("due-soon");
    expect(inside.daysUntilDue).toBe(7);
  });

  it("becomes due-soon at 20% for short intervals", () => {
    // 30-day interval → 6-day window
    expect(
      rotationStatus({ createdAt: daysAgo(23), updatedAt: daysAgo(23), rotateEveryDays: 30 }, NOW).state,
    ).toBe("ok");
    expect(
      rotationStatus({ createdAt: daysAgo(24), updatedAt: daysAgo(24), rotateEveryDays: 30 }, NOW).state,
    ).toBe("due-soon");
  });

  it("is overdue once dueAt has passed, with negative daysUntilDue", () => {
    const r = rotationStatus(
      { createdAt: daysAgo(102), updatedAt: daysAgo(102), rotateEveryDays: 90 },
      NOW,
    );
    expect(r.state).toBe("overdue");
    expect(r.daysUntilDue).toBe(-12);
    expect(describeRotation(r)).toBe("overdue 12d");
  });

  it("is overdue at exactly dueAt", () => {
    const r = rotationStatus(
      { createdAt: daysAgo(30), updatedAt: daysAgo(30), rotateEveryDays: 30 },
      NOW,
    );
    expect(r.state).toBe("overdue");
    expect(r.daysUntilDue).toBe(0);
    expect(describeRotation(r)).toBe("due now");
  });

  it("rounds a partial remaining day up so 'due in 1d' never shows 0", () => {
    const r = rotationStatus(
      { createdAt: daysAgo(29.5), updatedAt: daysAgo(29.5), rotateEveryDays: 30 },
      NOW,
    );
    expect(r.state).toBe("due-soon");
    expect(r.daysUntilDue).toBe(1);
    expect(describeRotation(r)).toBe("due in 1d");
  });

  it("is a pure function of (meta, now)", () => {
    const meta = { createdAt: daysAgo(10), updatedAt: daysAgo(10), rotateEveryDays: 30 };
    expect(rotationStatus(meta, NOW)).toEqual(rotationStatus(meta, NOW));
    // due at NOW+20d; the 6-day window opens at NOW+14d
    expect(rotationStatus(meta, NOW + 13 * DAY).state).toBe("ok");
    expect(rotationStatus(meta, NOW + 15 * DAY).state).toBe("due-soon");
    expect(rotationStatus(meta, NOW + 20 * DAY).state).toBe("overdue");
  });
});

describe("describeRotation / compareRotationUrgency", () => {
  it("labels unscheduled", () => {
    expect(
      describeRotation(rotationStatus({ createdAt: daysAgo(1), updatedAt: daysAgo(1) }, NOW)),
    ).toBe("unscheduled");
  });

  it("sorts most-overdue first, then soonest due, unscheduled last", () => {
    const mk = (age: number, every?: number) =>
      rotationStatus(
        { createdAt: daysAgo(age), updatedAt: daysAgo(age), rotateEveryDays: every },
        NOW,
      );
    const list = [mk(5, 90), mk(1), mk(40, 30), mk(28, 30), mk(100, 30)];
    const sorted = [...list].sort(compareRotationUrgency);
    expect(sorted.map((r) => r.daysUntilDue)).toEqual([-70, -10, 2, 85, null]);
  });
});
