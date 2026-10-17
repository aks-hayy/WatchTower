export type NavigationDestination = {
  title: string;
  url: string;
};

const SIMPLE_PRIMARY_URLS = new Set([
  "/",
  "/capture",
  "/flows",
  "/entities",
  "/alerts",
  "/forensics",
]);

export function partitionSimpleNavigation<T extends NavigationDestination>(
  destinations: readonly T[],
): { primary: T[]; moreTools: T[] } {
  return {
    primary: destinations.filter(({ url }) => SIMPLE_PRIMARY_URLS.has(url)),
    moreTools: destinations.filter(({ url }) => !SIMPLE_PRIMARY_URLS.has(url)),
  };
}

export function shouldExpandMoreTools<T extends NavigationDestination>(
  currentPath: string,
  manuallyExpanded: boolean,
  moreTools: readonly T[],
): boolean {
  return (
    manuallyExpanded ||
    moreTools.some(({ url }) =>
      url === "/" ? currentPath === "/" : currentPath === url || currentPath.startsWith(`${url}/`),
    )
  );
}
