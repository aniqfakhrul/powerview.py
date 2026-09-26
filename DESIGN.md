---
name: "PowerView.py"
description: "A classic two-pane directory browser in neutral graphite and crisp light: tree, property grid, address bar, status bar."
colors:
  canvas: "#f7f7f8"
  surface: "#fff"
  sidebar: "#f7f7f8"
  raised: "#fff"
  hover: "#f0f0f2"
  active: "#e8e8eb"
  text: "#1a1a1d"
  muted: "#5c5c66"
  faint: "#6e6e78"
  border: "#e6e6e9"
  border-strong: "#d2d2d7"
  divider: "#f0f0f2"
  input-border: "#8c8c95"
  guide: "#e3e3e7"
  accent: "#2f6fed"
  selection: "#e3eafb"
  selection-focus: "#d4e0fa"
  selection-text: "#1a1a1d"
  primary: "#1a1a1d"
  primary-hover: "#333338"
  primary-text: "#fff"
  danger: "#c42b3b"
  danger-soft: "#fcebed"
  danger-text: "#fff"
  success: "#1d7a4b"
  pill-success-bg: "#d9f3e4"
  pill-success-fg: "#11643a"
  pill-neutral-bg: "#ececef"
  pill-neutral-fg: "#4f4f58"
  overlay: "rgb(10 10 12 / 28%)"
  type-domain: "#2f6fed"
  type-user: "#2f6fed"
  type-group: "#1f8a5b"
  type-computer: "#7c4ddb"
  type-ou: "#b7791f"
  type-container: "#6e6e78"
  type-other: "#b83280"
  dark-canvas: "#0a0a0b"
  dark-surface: "#101011"
  dark-sidebar: "#0c0c0d"
  dark-raised: "#18181a"
  dark-hover: "#1a1a1c"
  dark-active: "#232326"
  dark-text: "#ededef"
  dark-muted: "#a1a1aa"
  dark-faint: "#85858e"
  dark-border: "#222225"
  dark-border-strong: "#313135"
  dark-divider: "#1a1a1c"
  dark-input-border: "#66666e"
  dark-guide: "#28282c"
  dark-accent: "#7aa2ff"
  dark-selection: "#333339"
  dark-selection-focus: "#3a3a40"
  dark-selection-text: "#fff"
  dark-primary: "#ededef"
  dark-primary-hover: "#d4d4d8"
  dark-primary-text: "#0a0a0b"
  dark-danger: "#f47174"
  dark-danger-soft: "#2a1516"
  dark-danger-text: "#0a0a0b"
  dark-success: "#5fcf97"
  dark-pill-success-bg: "#133524"
  dark-pill-success-fg: "#8ce0b3"
  dark-pill-neutral-bg: "#27272b"
  dark-pill-neutral-fg: "#b4b4bc"
  dark-overlay: "rgb(0 0 0 / 55%)"
  dark-type-domain: "#7aa2ff"
  dark-type-user: "#7aa7ff"
  dark-type-group: "#5fcf97"
  dark-type-computer: "#b39dff"
  dark-type-ou: "#e7b25a"
  dark-type-container: "#8b8b94"
  dark-type-other: "#f28cc0"
typography:
  headline:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, \"Helvetica Neue\", sans-serif"
    fontSize: "14px"
    fontWeight: 600
    lineHeight: 1.45
  title:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, \"Helvetica Neue\", sans-serif"
    fontSize: "13px"
    fontWeight: 600
    lineHeight: 1.45
  body:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, \"Helvetica Neue\", sans-serif"
    fontSize: "13px"
    fontWeight: 400
    lineHeight: 1.45
  label:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, \"Helvetica Neue\", sans-serif"
    fontSize: "11px"
    fontWeight: 500
    lineHeight: 1.45
  mono:
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"
    fontSize: "12px"
    fontWeight: 400
    lineHeight: 1.45
rounded:
  sm: "4px"
  md: "6px"
  full: "999px"
spacing:
  space-1: "4px"
  space-2: "8px"
  space-3: "12px"
  space-4: "16px"
  space-5: "24px"
  space-6: "32px"
  row-height: "24px"
  control-height: "28px"
  bar-height: "40px"
  sidebar-width: "208px"
  tree-width: "360px"
components:
  button:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text}"
    typography: "{typography.body}"
    rounded: "{rounded.sm}"
    padding: "0 10px"
    height: "28px"
  button-hover:
    backgroundColor: "{colors.hover}"
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.primary-text}"
    rounded: "{rounded.sm}"
    padding: "0 10px"
    height: "28px"
  button-primary-hover:
    backgroundColor: "{colors.primary-hover}"
  button-danger:
    backgroundColor: "{colors.danger}"
    rounded: "{rounded.sm}"
    padding: "0 10px"
    height: "28px"
  button-toolbar:
    backgroundColor: "transparent"
    textColor: "{colors.muted}"
    rounded: "{rounded.sm}"
    padding: "0 10px"
    height: "28px"
  button-toolbar-hover:
    backgroundColor: "{colors.hover}"
    textColor: "{colors.text}"
  icon-button:
    backgroundColor: "transparent"
    textColor: "{colors.muted}"
    rounded: "{rounded.sm}"
    size: "28px"
  icon-button-hover:
    backgroundColor: "{colors.hover}"
    textColor: "{colors.text}"
  text-input:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text}"
    rounded: "{rounded.sm}"
    padding: "0 8px"
    height: "28px"
  search-field:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.faint}"
    rounded: "{rounded.sm}"
    padding: "0 8px"
    height: "28px"
  address-bar:
    backgroundColor: "{colors.canvas}"
    textColor: "{colors.text}"
    typography: "{typography.mono}"
    rounded: "{rounded.sm}"
    padding: "0 8px"
    height: "28px"
  toolbar:
    backgroundColor: "{colors.surface}"
    height: "{spacing.bar-height}"
    padding: "0 8px 0 12px"
  tree-row:
    backgroundColor: "transparent"
    textColor: "{colors.text}"
    typography: "{typography.body}"
    rounded: "{rounded.sm}"
    height: "{spacing.row-height}"
  tree-row-hover:
    backgroundColor: "{colors.hover}"
  tree-row-selected:
    backgroundColor: "{colors.selection}"
    textColor: "{colors.selection-text}"
  tree-row-selected-focus:
    backgroundColor: "{colors.selection-focus}"
  grid-row-selected:
    backgroundColor: "{colors.selection}"
    textColor: "{colors.selection-text}"
  grid-row-selected-focus:
    backgroundColor: "{colors.selection-focus}"
  state-tag:
    backgroundColor: "{colors.pill-success-bg}"
    textColor: "{colors.pill-success-fg}"
    rounded: "{rounded.full}"
    padding: "0 8px"
    height: "18px"
  state-tag-neutral:
    backgroundColor: "{colors.pill-neutral-bg}"
    textColor: "{colors.pill-neutral-fg}"
  state-tag-danger:
    backgroundColor: "{colors.danger-soft}"
    textColor: "{colors.danger}"
  property-grid-header:
    backgroundColor: "{colors.sidebar}"
    textColor: "{colors.faint}"
    typography: "{typography.label}"
    height: "26px"
    padding: "3px 12px"
  property-grid-name:
    textColor: "{colors.muted}"
    typography: "{typography.body}"
    padding: "3px 12px 3px 16px"
  property-grid-value:
    textColor: "{colors.text}"
    typography: "{typography.body}"
    padding: "3px 12px"
  property-grid-row-hover:
    backgroundColor: "{colors.hover}"
  property-grid-row-editing:
    backgroundColor: "{colors.canvas}"
  value-dn:
    textColor: "{colors.accent}"
    typography: "{typography.mono}"
  statusbar:
    backgroundColor: "{colors.sidebar}"
    textColor: "{colors.faint}"
    typography: "{typography.label}"
    height: "24px"
    padding: "0 12px"
  nav-link:
    backgroundColor: "transparent"
    textColor: "{colors.muted}"
    rounded: "{rounded.sm}"
    padding: "0 8px"
    height: "28px"
  nav-link-hover:
    backgroundColor: "{colors.hover}"
    textColor: "{colors.text}"
  nav-link-active:
    backgroundColor: "{colors.active}"
    textColor: "{colors.text}"
  dialog:
    backgroundColor: "{colors.raised}"
    textColor: "{colors.text}"
    rounded: "{rounded.md}"
    width: "420px"
---

# Design System: PowerView.py

## Overview

**Creative North Star: "The Directory Browser"**

PowerView.py looks like a classic desktop directory browser rebuilt with modern restraint: a slim navigation sidebar, a 40px toolbar holding a distinguished-name address bar and the object actions, a resizable tree with indent guides on the left, a property grid on the right, and a 24px status bar along the bottom, shared by every page, that carries live connection state. Every pane sits flush against its neighbour and is divided by a single hairline. Nothing floats at rest, nothing is wrapped in a card, and nothing announces itself with a hero heading.

The palette is neutral graphite in dark mode (near-black grounds from canvas to raised, with no blue cast) and crisp near-white in light mode, following the OS setting. The chrome carries no colour. Colour is reserved for information: object type icons, DN links, the focus ring, selection, and error or success status. Density is high but calm. Rows are 24px, text is 13px, and hierarchy comes from tone (text, muted, faint) rather than size.

The world rejects card layouts, hero headings and hint paragraphs. Pills appear only as state tags and count chips, which carry data and never decorate. It is an instrument for reading and editing live directory state, not a dashboard.

**Key Characteristics:**
- Two fixed heights: 40px bars and 24px rows, plus 28px controls inside the bars.
- Hairline 1px dividers and tonal steps for all structure; shadow only on layers that float.
- Tight corners: 4px on controls and rows, 6px on containers and dialogs, fully round only on state tags and count chips.
- Chrome without colour; colour only on type icons, DN links, focus, selection and status.
- Primary buttons invert: the text colour becomes the ground.
- System sans for everything, with mono reserved for distinguished names and machine identifiers.

## Colors

A neutral graphite and crisp light pair with one blue accent and a small, fixed set of object-type hues.

### Primary
- **Ink Inversion** (`primary`, dark: `dark-primary`): the fill of primary buttons (Save, dialog submit). It is the text colour itself, so a primary button reads as a solid block of ink in light mode and a near-white block in dark mode. `primary-text` is the page ground, which completes the inversion.
- **Directory Blue** (`accent`, dark: `dark-accent`): DN links, "Show more" and retry links, the 2px focus ring, text caret, and the pane resizer on hover or drag. It never fills a button or a surface.

### Tertiary
- **Type icon hues** (`type-domain`, `type-user`, `type-group`, `type-computer`, `type-ou`, `type-container`, `type-other` and their `dark-` pairs): stroke colour for the 15-16px object icons in the tree and the object header. Domains and users are blue, groups green, computers violet, OUs amber, containers neutral grey, anything else magenta. Only the icon takes the hue; the label beside it stays in text colour.
- **Status** (`danger`, `success`, `danger-soft`): danger colours destructive hover states, the Clear attribute link, form errors, tree load errors and error status messages. It also fills the destructive dialog submit. Success colours the status-bar confirmation message, the connection dot and success toasts.
- **State tag tones** (`pill-success-bg`, `pill-success-fg`, `pill-neutral-bg`, `pill-neutral-fg` and their `dark-` pairs): the fill and text of state tags. Success marks an active or positive state, neutral an inactive or categorical one. The danger tone reuses `danger-soft` and `danger`. Every pair keeps 4.5:1 text contrast.

### Neutral
- **Canvas** (`canvas`): the page ground, the address-bar field, and the row being edited.
- **Surface** (`surface`): the explorer body, the property grid, inputs and default buttons.
- **Sidebar** (`sidebar`): the navigation sidebar, the tree pane, the sticky grid header and the status bar. These are the recessed frames around the grid.
- **Raised** (`raised`): dialogs, the only elevated surface.
- **Hover / Active** (`hover`, `active`): row and control hover, and the current navigation item.
- **Text / Muted / Faint** (`text`, `muted`, `faint`): three tonal tiers. Values are in text, attribute names and toolbar labels are muted, and column headers, placeholders, twisties, the type label and the status bar are faint.
- **Border / Divider / Border Strong / Guide** (`border`, `divider`, `border-strong`, `guide`): hairlines between panes and bars, the lighter rule between property-grid rows, button strokes, and tree indent guides.
- **Input Border** (`input-border`): the resting stroke of text inputs, selects and search fields. It holds 3:1 against every ground a field sits on (surface, canvas and raised), so the edge of a field is always visible. Focus replaces it with the accent outline.
- **Selection** (`selection`, `selection-focus`): the selected tree row and grid row, one step stronger while the tree or grid holds focus, with `selection-text`. In light mode it is a pale blue tint. In dark mode it is a neutral graphite step, at least 1.5:1 against the surface so it reads without hue, with white text. Keyboard focus never borrows the selection tone.

### Named Rules
**The Graphite Rule.** Dark neutrals stay achromatic. Canvas through raised (`dark-canvas` to `dark-raised`) never lean more than a few units toward blue, and a new dark surface is picked from this ramp, not tinted.

**The Colour Carries Meaning Rule.** Chrome is neutral. A pixel is coloured only when it encodes an object type, a link to another object, focus, selection, or an outcome. If a colour decorates, remove it.

## Typography

**Body Font:** the system UI sans stack (`-apple-system`, Segoe UI, Roboto, Helvetica Neue)
**Label/Mono Font:** the system monospace stack (`ui-monospace`, SF Mono, Menlo, Consolas)

**Character:** the platform's own UI face at desktop-application sizes. Mono appears only where the content is machine syntax, so a DN reads as something you can paste and follow.

### Hierarchy
- **Headline** (600, 14px): dialog titles and the brand wordmark (650). There is no larger display tier inside the explorer.
- **Title** (600, 13px): the selected object's name in the object header. It sits at body size and is set apart by weight alone.
- **Body** (400, 13px, 1.45): tree labels, attribute names (in muted), values, buttons and inputs.
- **Label** (500 or 400, 11px): property-grid column headers, sidebar group labels, the status bar and the version in the brand row. Always sentence case, never tracked uppercase.
- **Mono** (400, 12px): the address bar, DN values in the grid, the attribute-name and DN inputs in editors, the dialog context line, the status-bar domain, and literal field names in the Fields menu.

### Named Rules
**The Mono Is for Machines Rule.** Monospace is used only for distinguished names and other literal directory identifiers. Labels, headings and ordinary values stay in sans.

**The Weight Not Size Rule.** Inside the explorer, hierarchy moves through weight (400 to 600) and tone (text, muted, faint) and stays between 11px and 14px. Do not add larger headings to the workspace.

## Layout

The workspace is a two-column grid: a 208px sidebar and a fluid body. On the Explorer page the body fills the viewport height and stacks a toolbar, a two-pane body and a status bar. The tree pane defaults to 360px, the user can resize it with a 1px separator that has an 8px invisible hit area, and it works from the keyboard. The object pane takes the rest of the width and holds a 40px object header above the scrolling property grid.

Spacing uses a 4px base (4, 8, 12, 16, 24, 32). Bars get 8-16px horizontal padding, grid cells 3px by 12px, and the attribute-name column 16px on its leading edge. The name column is fixed at 240px.

Responsive behaviour:
- **At 1100px and below:** the tree narrows to 300px, toolbar buttons collapse to 28px icon-only squares (their labels stay available to assistive tech), and the name column drops to 180px.
- **At 720px and below:** the sidebar becomes a horizontally scrolling nav strip with a fade mask, and the tree becomes a drawer over the grid, opened from a toolbar folder button. Tree rows grow to 40px touch targets, row edit buttons stay visible, and the status-bar domain is hidden.

### Named Rules
**The Two Heights Rule.** Horizontal chrome is 40px (sidebar brand, toolbar, object header). Rows and the status bar are 24px. Controls inside a bar are 28px. New chrome picks one of these heights.

## Elevation & Depth

The system is flat. Depth comes from tone (the sidebar-toned frames recede behind the surface-toned grid) and from 1px hairlines. The sticky grid header separates from the rows with an inset hairline rather than a shadow. Only layers that float over content get a shadow: the dialog and the mobile tree drawer. Both use a single pop shadow. In dark mode that shadow also adds a 1px strong-border ring so the edge still reads on near-black.

### Shadow Vocabulary
- **Pop** (light: `0 12px 40px rgb(10 10 12 / 16%), 0 2px 6px rgb(10 10 12 / 8%)`; dark: `0 16px 48px rgb(0 0 0 / 60%), 0 0 0 1px #313135`): dialogs and the mobile tree drawer only.

### Named Rules
**The Hairline Rule.** Resting surfaces are separated by one 1px border or one tonal step, never by a shadow. A shadow means the layer is floating above the page.

## Shapes

Corners are tight and functional. Buttons, inputs, search fields, tree rows, nav links and skeleton bars use 4px. Containers and dialogs use 6px. Panes, bars and the property grid are square and run edge to edge, divided by hairlines. Icons are 16px outline strokes (1.4-1.5px) from a single SVG sprite and drop to 14px inside search fields and toolbar buttons and 12px for tree twisties. State tags and count chips are the only fully rounded shapes.

## Components

### Buttons
Quiet, compact, desktop-native.
- **Shape:** 4px corners, 28px tall, 10px horizontal padding, 6px icon gap, weight 500.
- **Default:** surface fill with a strong-border stroke. Hover moves to the hover tone over a 120ms background transition.
- **Primary:** inverted, with an ink fill and ground-coloured text. Hover steps to `primary-hover`. Use it once per decision point (Save, dialog submit).
- **Danger:** a danger-red fill with `danger-text` (white in light, near-black in dark for 4.5:1+), used only for the destructive dialog submit.
- **Toolbar:** transparent with no visible stroke and muted text plus a 14px icon. Hover brings up the hover tone and full text colour. Delete shows danger red only on hover.
- **Icon button:** a 28px transparent square with a muted icon. Used for Refresh, remove value and the row edit button (24px).
- **Link button:** no box, muted text with a leading 14px icon, darkening on hover. Used for "Add attribute" and "Add value".
- **Disabled:** 40-45% opacity.

### Inputs / Fields
- **Text input:** 28px, 4px corners, `input-border` stroke on surface, blue caret. Focus replaces the border with a 2px accent outline inset by 1px. Mono variant at 12px for DN and attribute-name entry. Selects use the same box.
- **Search field:** the same box and stroke with a faint 14px leading icon. The outline is drawn on the wrapper through `:focus-within`, and the native cancel control is hidden.

### Toolbar and Address Bar
The 40px toolbar holds the address bar as a canvas-toned search field that stretches to fill the row. It contains a domain icon and a mono DN input with the placeholder "Go to distinguished name". The action cluster (New, Move, Delete, Refresh) sits on the right with 4px gaps. Actions stay disabled until an object is selected.

### Directory Tree
- **Rows:** 24px, 4px corners, a 16px twisty column with a 12px chevron that rotates 90 degrees on expand (120ms ease-out), a 15px type-coloured icon, and a label in text colour.
- **Indentation:** 12px per level plus 4px padding, with a 1px guide-coloured rule on each group's leading edge.
- **States:** hover tone. Selected rows use the selection tone, one step stronger while the tree has focus. Keyboard focus draws a 1px inset accent outline. While children load, the twisty pulses.
- **Notes:** loading, empty and error lines sit at row height in faint (or danger) with an inline accent Retry link.

### Property Grid
The central component. It is a full-width, fixed-layout table with Attribute and Value columns and a 36px actions column.
- **Header:** sticky, 26px, sidebar tone, faint 11px label text, with an inset hairline below.
- **Rows:** 3px by 12px cells, a hairline below each row, top-aligned. Names are muted and values are text. Multi-valued attributes stack one value per line with a 2px gap and a "Show more" accent link.
- **DN values:** accent-coloured mono buttons that underline on hover and navigate to that object.
- **Times:** directory timestamps use the grid's locale date format, with seconds, followed by the server's relative age in faint text ("Sep 24, 2026, 12:18:10 PM 2 days ago"). The raw value stays in the tooltip and in the editor.
- **Row actions:** a 24px edit icon button that shows only on row hover or focus (always visible on touch layouts). The column header is named "Actions" for assistive tech only.
- **Footer:** an "Add attribute" link button with 16px leading padding.

### Value Editor
Editing expands inside the row, which switches to the canvas tone. The editor is a vertical stack with 6px gaps: one text input per value (mono for DNs), each with a remove icon button. Below the inputs sits a control line with "Add value" on the left, then a danger "Clear attribute" link, a default Cancel button and a primary Save button. Errors appear inline in 12px danger text.

### Status Bar
Shared by every page and sticky to the bottom of the viewport. 24px, sidebar tone, top hairline, 11px faint text. The left side is a live message (danger or success tone when the message reports an outcome), falling back to the selected object's summary ("23 attributes · Enabled"). The right side is the live connection: a 7px dot (success when connected, danger when disconnected or unreachable), the protocol in 600 muted, `user@domain`, and the LDAP address in mono. Disconnected states turn the protocol and identity danger as well, so colour is never the only signal. The name server and last-checked time live in the tooltip. On mobile only the dot and identity remain.

### Data Grid
Every list page (Users, Computers, Groups, DNS, Certificate authorities, Organizational units, Group policies) shares one grid: a 48px sticky index column, a sticky name column with a strong-border edge, 24px rows (40px on touch layouts) and a sticky 28px sidebar-toned header in muted 500 text.
- **Headers:** a column backed by one field the directory returns shows that field's literal name (`sAMAccountName`, `pKIExtendedKeyUsage`, `ManagerApproval`), because the UI mirrors PowerView's output. Computed columns (Status, Type, Parent, Linked GPOs) use a sentence-case label. When two literal names differ only by case, the rarer one takes a sentence-case label, so DNS `Name` shows as Target. The Fields menu lists literal names in mono and computed labels in sans.
- **Widths:** a header never truncates at its default width; the default grows to fit the label. Dragging a column's right edge resizes it, and the header edge turns accent while hovered or dragged. Double-clicking the edge fits the column to its rendered content, which is the single-pointer alternative to dragging. Widths are remembered per page, and Fields > Reset to default clears them along with the column choice.
- **Selection and focus:** clicking a row selects it and opens the details panel. The selected row takes the selection tone and selection text, one step stronger while the grid holds focus. Arrow keys move a 1px inset accent ring without changing the selection.
- **Filter triggers:** a 20px funnel shows on header hover or focus, and stays while a filter is active. It is hidden while the grid loads or after a load fails.

### State Tag
An 18px fully rounded tag with 8px padding and 12px text that reports an object's state: account Enabled or Disabled, template Enabled, group type, DNS record type and ACE access (Allow or Deny). Success is for an active or positive state, neutral for an inactive or categorical value, danger for findings and Deny, and outline (transparent with a strong-border ring) for a secondary category. A tag holds one short word or phrase and is never a button. The count chip inside toolbar buttons (Fields, Search options) is the same shape in the active tone, with 11px muted numerals.

### Navigation
The sidebar opens with a 40px brand row (20px mark, 14px/650 wordmark with a faint ".py", and the version right-aligned in 11px tabular faint text). Groups are separated by 14px, each under an 11px faint sentence-case label. Links are 28px with 4px corners in muted text. Hover shows the hover tone, and the current page gets the active tone, text colour and weight 500.

### Dialog
420px wide, raised tone, 6px corners, pop shadow over a dimmed overlay. It enters with a 4px rise and a 0.99 scale over 160ms ease-out. Layout is a 14px title, then 12px-gapped labelled fields with a mono context line, then a hairline-topped footer with right-aligned Cancel and a primary (or danger) submit.

### Skeleton
Loading placeholders are 10px bars with 4px corners in the hover tone, at staggered widths (48-70%) and 10px gaps. They do not shimmer.

## Do's and Don'ts

### Do:
- **Do** build new chrome at 40px bars, 24px rows and 28px controls, divided by 1px hairlines.
- **Do** keep dark surfaces on the graphite ramp from `dark-canvas` to `dark-raised`, with no blue cast.
- **Do** make primary actions inverted (ink ground, page-colour text) and keep one per decision point.
- **Do** colour object icons by type using the `type-*` tokens, and leave their labels in text colour.
- **Do** render every distinguished name in 12px mono, and as an accent link when it points to another object.
- **Do** use the 2px accent outline for keyboard focus on every interactive element.
- **Do** give every input, select and search field the `input-border` stroke. Hairline tones are for dividers, not field edges.
- **Do** size grid columns so their headers fit at the default width.
- **Do** respect `prefers-reduced-motion` by turning off dialog entry and twisty rotation.

### Don't:
- **Don't** wrap records or panes in cards. Panes sit flush and edge to edge.
- **Don't** use pills or fully rounded shapes for anything except state tags and count chips, and never make a tag clickable. Other corners stop at 6px.
- **Don't** add hero headings, hint paragraphs or tracked uppercase labels to the workspace.
- **Don't** fill buttons or surfaces with the accent blue. Accent is for links, focus and the resizer.
- **Don't** use mono for labels, headings or ordinary values.
- **Don't** put shadows on resting surfaces. Pop is only for dialogs and the mobile drawer.
