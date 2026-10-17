export function captureControlDisabled(input: {
  busy: boolean;
  capturing: boolean;
  interfaceUp: boolean;
  backendAvailable: boolean;
}): boolean {
  if (input.busy) return true;
  if (input.capturing) return false;
  return !input.interfaceUp || !input.backendAvailable;
}
