export function createMutationGuard({ onBlocked, onChange } = {}) {
  let busy = false;
  return {
    busy: () => busy,
    begin() {
      if (busy) { onBlocked?.(); return false; }
      busy = true;
      onChange?.(true);
      return true;
    },
    end() {
      busy = false;
      onChange?.(false);
    },
  };
}
