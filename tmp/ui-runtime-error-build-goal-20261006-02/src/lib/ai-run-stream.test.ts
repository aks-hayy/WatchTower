import assert from "node:assert/strict";
import test from "node:test";

test("keeps EventSource reconnect enabled and clears polling when it reopens", async () => {
  const streamModule = await import("./ai-run-stream").catch(() => null);
  assert.ok(streamModule, "AI run stream lifecycle helper is implemented");

  const listeners = new Map<string, (event: Event) => void>();
  const source = {
    closeCount: 0,
    onopen: null as ((event: Event) => void) | null,
    onerror: null as ((event: Event) => void) | null,
    addEventListener(name: string, listener: (event: Event) => void) {
      listeners.set(name, listener);
    },
    close() {
      this.closeCount += 1;
    },
  };
  let timerCallback: (() => void) | undefined;
  const clearedTimers: number[] = [];
  const timerHost = {
    setInterval(callback: () => void, delay: number) {
      assert.equal(delay, 1500);
      timerCallback = callback;
      return 7;
    },
    clearInterval(id: number) {
      clearedTimers.push(id);
    },
  };
  let syncCalls = 0;

  const cleanup = streamModule.attachAIRunStream(
    source as unknown as EventSource,
    () => {
      syncCalls += 1;
    },
    timerHost,
  );

  source.onerror?.(new Event("error"));
  assert.equal(source.closeCount, 0);
  assert.ok(timerCallback);
  timerCallback();
  assert.equal(syncCalls, 1);

  source.onopen?.(new Event("open"));
  assert.deepEqual(clearedTimers, [7]);
  listeners.get("tool_complete")?.(new Event("message"));
  assert.equal(syncCalls, 2);

  cleanup();
  assert.equal(source.closeCount, 1);
});

test("treats interrupted runs as terminal and delivers the recovery event", async () => {
  const streamModule = await import("./ai-run-stream").catch(() => null);
  assert.ok(streamModule, "AI run stream lifecycle helper is implemented");
  assert.equal(streamModule.isTerminalAIRunStatus("INTERRUPTED"), true);
  assert.equal(streamModule.isTerminalAIRunStatus("RUNNING"), false);

  const listeners = new Map<string, (event: Event) => void>();
  const source = {
    onopen: null,
    onerror: null,
    addEventListener(name: string, listener: (event: Event) => void) {
      listeners.set(name, listener);
    },
    close() {},
  };
  let syncCalls = 0;
  const cleanup = streamModule.attachAIRunStream(
    source as unknown as EventSource,
    () => {
      syncCalls += 1;
    },
    { setInterval: () => 1, clearInterval: () => undefined },
  );

  assert.ok(listeners.has("interrupted"));
  listeners.get("interrupted")?.(new Event("message"));
  assert.equal(syncCalls, 1);
  cleanup();
});
