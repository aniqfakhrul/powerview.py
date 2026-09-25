import { confirmAction } from '../confirm.js';
import { notify } from '../notify.js';

export function createMembershipEditor({ tab, record, directory, guard, canLeave, onChanged }) {
  const ownsMembers = tab === 'members';
  const pair = (other) => (ownsMembers ? [record.dn, other] : [other, record.dn]);

  async function change(action, other, success) {
    if (!canLeave() || !guard.begin()) return false;
    try {
      await directory.groupMember(action, ...pair(other));
    } finally {
      guard.end();
    }
    notify.success(success);
    try { await onChanged(); } catch (failure) { notify.warn(`${success}, but refreshing failed: ${failure.message}`); }
    return true;
  }

  return {
    groupsOnly: !ownsMembers,
    addLabel: ownsMembers ? 'Add member' : 'Add to group',
    removeLabel: ownsMembers ? 'Remove' : 'Leave',
    async add(target, fail) {
      try {
        return await change('add', target.dn, ownsMembers ? `Added ${target.label}` : `Added to ${target.label}`);
      } catch (failure) {
        fail(failure.message);
        return false;
      }
    },
    async remove(item) {
      if (!canLeave()) return;
      const confirmed = await confirmAction({
        title: ownsMembers ? `Remove ${item.label}?` : `Remove from ${item.label}?`,
        context: item.dn,
        message: ownsMembers ? 'The object stays in the directory; only its membership in this group is removed.' : 'Only this group membership is removed.',
        confirmLabel: 'Remove',
        danger: true,
      });
      if (!confirmed) return;
      try {
        await change('remove', item.dn, ownsMembers ? `Removed ${item.label}` : `Removed from ${item.label}`);
      } catch (failure) {
        notify.error(failure.message);
      }
    },
  };
}
