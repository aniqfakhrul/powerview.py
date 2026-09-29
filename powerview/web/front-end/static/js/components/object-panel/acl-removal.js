export function removalParameters(ace) {
  const identity = ace.RemovalIdentity;
  if (!identity || !Number.isSafeInteger(identity.index) || identity.index < 0) return null;
  if (![identity.ace, identity.dacl].every((value) => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value))) return null;
  return { ace: { index: identity.index, ace: identity.ace, dacl: identity.dacl } };
}
