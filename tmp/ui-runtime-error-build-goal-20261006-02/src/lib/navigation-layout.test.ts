import assert from "node:assert/strict";
import test from "node:test";

type NavigationDestination = { title: string; url: string };

const destinations: NavigationDestination[] = [
  { title: "Overview", url: "/" },
  { title: "Capture", url: "/capture" },
  { title: "Connections", url: "/flows" },
  { title: "Devices", url: "/entities" },
  { title: "Network map", url: "/topology" },
  { title: "Sensors", url: "/fleet" },
  { title: "Alerts", url: "/alerts" },
  { title: "Detection rules", url: "/sigma" },
  { title: "Cases", url: "/forensics" },
  { title: "Search", url: "/lookup" },
  { title: "Hunts", url: "/hunt" },
  { title: "Evidence", url: "/evidence" },
  { title: "System settings", url: "/settings" },
  { title: "Extensions", url: "/plugins" },
  { title: "Analyst", url: "/ai" },
];

test("Simple navigation shows essentials while keeping every other route under More tools", async () => {
  const navigation = await requireNavigationLayout();
  const { primary, moreTools } = navigation.partitionSimpleNavigation(destinations);

  assert.deepEqual(
    primary.map(({ url }) => url),
    ["/", "/capture", "/flows", "/entities", "/alerts", "/forensics"],
  );
  assert.deepEqual(
    moreTools.map(({ url }) => url),
    [
      "/topology",
      "/fleet",
      "/sigma",
      "/lookup",
      "/hunt",
      "/evidence",
      "/settings",
      "/plugins",
      "/ai",
    ],
  );
  assert.equal(new Set([...primary, ...moreTools].map(({ url }) => url)).size, destinations.length);
});

test("More tools opens automatically for an advanced deep link and nested route", async () => {
  const navigation = await requireNavigationLayout();
  const { moreTools } = navigation.partitionSimpleNavigation(destinations);

  assert.equal(navigation.shouldExpandMoreTools("/", false, moreTools), false);
  assert.equal(navigation.shouldExpandMoreTools("/lookup", false, moreTools), true);
  assert.equal(navigation.shouldExpandMoreTools("/lookup/host/192.0.2.8", false, moreTools), true);
  assert.equal(navigation.shouldExpandMoreTools("/", true, moreTools), true);
});

async function requireNavigationLayout() {
  const navigation = import("./navigation-layout").catch(() => null);
  const module = await navigation;
  assert.ok(module, "Simple navigation layout policy is implemented");
  return module;
}
