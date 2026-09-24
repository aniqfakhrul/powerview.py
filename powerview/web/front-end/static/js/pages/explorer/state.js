export function createRequestLane() {
  let controller;
  return {
    next() { controller?.abort(); controller = new AbortController(); return controller.signal; },
    cancel() { controller?.abort(); },
  };
}
