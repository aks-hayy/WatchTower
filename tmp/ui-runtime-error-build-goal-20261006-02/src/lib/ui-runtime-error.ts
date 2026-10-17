export type UiRuntimeErrorKind = "request_error" | "stale_ui_bundle";

export type UiRuntimeErrorPresentation = {
  kind: UiRuntimeErrorKind;
  title: string;
  message: string;
  actionLabel: string;
  showTechnicalDetails: boolean;
};

const STALE_UI_BUNDLE_ERROR =
  /failed to fetch dynamically imported module|importing a module script failed|error loading dynamically imported module|chunkloaderror|loading chunk \d+ failed/i;

export function describeUiRuntimeError(error: unknown): UiRuntimeErrorPresentation {
  const detail = error instanceof Error ? error.message : typeof error === "string" ? error : "";
  if (STALE_UI_BUNDLE_ERROR.test(detail)) {
    return {
      kind: "stale_ui_bundle",
      title: "Restart WatchTower UI",
      message:
        "This page's UI files changed while WatchTower was running. Restart the WatchTower UI, then reload this page. Your capture and saved data are not changed by this error.",
      actionLabel: "Reload after restart",
      showTechnicalDetails: false,
    };
  }

  return {
    kind: "request_error",
    title: "Something went wrong",
    message: "The request could not be completed. Retry after checking pipeline health.",
    actionLabel: "Try again",
    showTechnicalDetails: true,
  };
}
