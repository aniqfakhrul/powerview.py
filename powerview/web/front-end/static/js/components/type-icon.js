import { TYPE_ICONS } from '../core/directory.js';
import { icon } from '../core/dom.js';

export const typeIcon = (type) => icon(TYPE_ICONS[type], `type--${type}`);
