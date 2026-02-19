import { expect } from "chai";
import {
  retry,
  retryable,
  retryAll,
  retryWithFallback,
  CircuitBreaker,
} from "../src/utils/retry";

// ============================================================
// Helpers
// ============================================================

/** Create a function that fails N times then succeeds */
function failNTimes(n: number, result: string = "ok") {
  let calls = 0;
  return async () => {
    calls++;
    if (calls <= n) throw new Error(`fail #${calls}`);
    return result;
  };
}

/** Create a function that always fails */
function alwaysFail(msg: string = "always fails") {
  return async () => {
    throw new Error(msg);
  };
}

// ============================================================
// Tests
// ============================================================

describe("Retry Utilities", () => {
  describe("retry", () => {
    it("should succeed on first try", async () => {
      const result = await retry(async () => "success", {
        maxAttempts: 3,
        initialDelayMs: 1,
      });
      expect(result).to.equal("success");
    });

    it("should retry and succeed after transient failure", async () => {
      const fn = failNTimes(2);
      const result = await retry(fn, {
        maxAttempts: 3,
        initialDelayMs: 1,
        jitter: false,
        shouldRetry: () => true,
      });
      expect(result).to.equal("ok");
    });

    it("should throw after exhausting maxAttempts", async () => {
      try {
        await retry(alwaysFail(), {
          maxAttempts: 2,
          initialDelayMs: 1,
          jitter: false,
          shouldRetry: () => true,
        });
        expect.fail("should have thrown");
      } catch (e: any) {
        expect(e.message).to.equal("always fails");
      }
    });

    it("should call onRetry callback on each retry", async () => {
      const retries: number[] = [];
      const fn = failNTimes(2);
      await retry(fn, {
        maxAttempts: 3,
        initialDelayMs: 1,
        jitter: false,
        shouldRetry: () => true,
        onRetry: (_err, attempt) => retries.push(attempt),
      });
      expect(retries).to.deep.equal([1, 2]);
    });

    it("should respect shouldRetry predicate", async () => {
      let attempts = 0;
      try {
        await retry(
          async () => {
            attempts++;
            throw new Error("non-retryable");
          },
          {
            maxAttempts: 5,
            initialDelayMs: 1,
            shouldRetry: () => false, // never retry
          },
        );
      } catch {
        // expected
      }
      expect(attempts).to.equal(1);
    });

    it("should handle maxAttempts = 1 (no retry)", async () => {
      try {
        await retry(alwaysFail(), { maxAttempts: 1, initialDelayMs: 1 });
        expect.fail("should have thrown");
      } catch (e: any) {
        expect(e.message).to.equal("always fails");
      }
    });
  });

  describe("retryable", () => {
    it("should wrap a function with retry logic", async () => {
      const fn = failNTimes(1, "wrapped");
      const wrapped = retryable(fn, {
        maxAttempts: 3,
        initialDelayMs: 1,
        jitter: false,
        shouldRetry: () => true,
      });
      const result = await wrapped();
      expect(result).to.equal("wrapped");
    });
  });

  describe("retryAll", () => {
    it("should retry all operations and return all results", async () => {
      const ops = [async () => "a", async () => "b", async () => "c"];
      const results = await retryAll(ops, {
        maxAttempts: 1,
        initialDelayMs: 1,
      });
      expect(results).to.deep.equal(["a", "b", "c"]);
    });

    it("should fail if any operation exhausts retries", async () => {
      const ops = [async () => "ok", alwaysFail()];
      try {
        await retryAll(ops, {
          maxAttempts: 2,
          initialDelayMs: 1,
          jitter: false,
          shouldRetry: () => true,
        });
        expect.fail("should have thrown");
      } catch (e: any) {
        expect(e.message).to.include("always fails");
      }
    });
  });

  describe("retryWithFallback", () => {
    it("should return primary result on success", async () => {
      const result = await retryWithFallback(
        async () => "primary",
        async () => "fallback",
        { maxAttempts: 1, initialDelayMs: 1 },
      );
      expect(result).to.equal("primary");
    });

    it("should fall back when primary exhausts retries", async () => {
      const result = await retryWithFallback(
        alwaysFail(),
        async () => "fallback",
        { maxAttempts: 2, initialDelayMs: 1, jitter: false, shouldRetry: () => true },
      );
      expect(result).to.equal("fallback");
    });

    it("should throw if both primary and fallback fail", async () => {
      try {
        await retryWithFallback(
          alwaysFail("primary fails"),
          alwaysFail("fallback fails"),
          { maxAttempts: 1, initialDelayMs: 1, jitter: false, shouldRetry: () => true },
        );
        expect.fail("should have thrown");
      } catch (e: any) {
        expect(e.message).to.include("fallback fails");
      }
    });
  });

  describe("CircuitBreaker", () => {
    it("should start in closed state", () => {
      const cb = new CircuitBreaker(async () => "ok", {
        maxAttempts: 1,
        initialDelayMs: 1,
        failureThreshold: 3,
        resetTimeoutMs: 100,
      });
      expect(cb.getState()).to.equal("closed");
    });

    it("should succeed when closed", async () => {
      const cb = new CircuitBreaker(async () => "ok", {
        maxAttempts: 1,
        initialDelayMs: 1,
        failureThreshold: 3,
        resetTimeoutMs: 100,
      });
      const result = await cb.call();
      expect(result).to.equal("ok");
    });

    it("should open after failureThreshold failures", async () => {
      let callCount = 0;
      const cb = new CircuitBreaker(
        async () => {
          callCount++;
          throw new Error("fail");
        },
        {
          maxAttempts: 1,
          initialDelayMs: 1,
          failureThreshold: 2,
          resetTimeoutMs: 5000,
        },
      );

      // Fail twice to trip the breaker
      for (let i = 0; i < 2; i++) {
        try {
          await cb.call();
        } catch {
          /* expected */
        }
      }

      expect(cb.getState()).to.equal("open");

      // Next call should fail immediately (circuit open)
      try {
        await cb.call();
        expect.fail("should have thrown");
      } catch (e: any) {
        expect(e.message.toLowerCase()).to.include("circuit");
      }
    });

    it("reset should return to closed state", async () => {
      const cb = new CircuitBreaker(alwaysFail(), {
        maxAttempts: 1,
        initialDelayMs: 1,
        failureThreshold: 1,
        resetTimeoutMs: 5000,
      });

      try {
        await cb.call();
      } catch {
        /* trip breaker */
      }
      expect(cb.getState()).to.equal("open");

      cb.reset();
      expect(cb.getState()).to.equal("closed");
    });
  });
});
