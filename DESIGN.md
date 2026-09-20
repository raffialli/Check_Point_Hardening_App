---
name: Check Point Hardening App — Open Public Edition
description: Independent, evidence-first hardening workbench with text-only identity.
colors:
  primary: "#ca004c"
  canvas: "#eef2f7"
  surface: "#ffffff"
  navigation: "#f4f6fa"
  ink: "#142033"
  muted: "#526278"
  line: "#d8e0ea"
  selection: "#fff0f5"
  action: "#b42335"
  review: "#866000"
  pass: "#217044"
typography:
  body:
    fontFamily: 'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'
    fontSize: "15px"
    lineHeight: 1.5
  headline:
    fontSize: "23px"
    lineHeight: 1.2
  title:
    fontSize: "13px"
    fontWeight: 650
    lineHeight: 1.45
  evidence:
    fontSize: "13px"
    lineHeight: 1.65
  label:
    fontSize: "12px"
  metadata:
    fontSize: "11px"
    fontWeight: 500
rounded:
  control: "6px"
  selection: "5px"
  badge: "999px"
spacing:
  compact: "8px"
  small: "12px"
  medium: "16px"
  detail: "22px"
  outer: "24px"
components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.surface}"
    rounded: "{rounded.control}"
    padding: "11px 15px"
  button-secondary:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.control}"
    padding: "11px 15px"
  filter-input:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.selection}"
    padding: "8px"
  navigation-item:
    rounded: "{rounded.selection}"
    padding: "10px 9px"
  check-row:
    backgroundColor: "{colors.surface}"
    padding: "14px 12px"
  check-row-selected:
    backgroundColor: "{colors.selection}"
    rounded: "{rounded.selection}"
    padding: "14px 12px"
  evidence-panel:
    backgroundColor: "{colors.surface}"
    padding: "22px"
  status-badge:
    rounded: "{rounded.badge}"
    padding: "3px 9px"
---

# Design System: Check Point Hardening App

## Overview

**Creative North Star: "The Evidence Workbench"**

The implemented world is a compact, light, evidence-first administrative interface. Slate navigation, white working surfaces and dark ink support sustained reading; pink identifies selection and the primary action. Fine separators keep the interface structured without turning every datum into a card.

This document records the shipped results presentation from `public/workbench.css`, `public/workbench.js`, `public/styles.css` and `public/index.html`, not a pixel-exact reproduction of the concept image. The surface mode and task sequence remain in `docs/workbench-direction.md`. Legacy login styling, existing dialogs and PDF report design remain separate incumbent surfaces; this document does not authorize redesigning them or changing backend behavior.

**Key Characteristics:**

- Compact, readable system typography.
- Flat working surfaces and restrained pink selection.
- Persistent object context beside original evidence.
- Independent, text-only identity and offline assets.

## Colors

### Primary

Primary pink identifies the scan action. Pale selection pink marks the selected check; navigation selection uses its own slightly stronger pale-pink fill and border. Focus uses a dark pink outline. These selection treatments are not risk indicators.

### Neutral

Canvas is a cool gray; navigation is light slate; evidence and check rows sit on white. Ink provides headings and body contrast, muted slate supports labels, and line defines pane divisions. Workspace-muted text is darker than the legacy global muted token.

### Status

Action red, review amber and pass green accompany explicit text in the check list. Original evidence badges retain their existing status palette and labels, including Manual, Unknown, Reviewed and Informational. Do not equate a selected pink row with a remediation requirement.

**The Semantic Separation Rule.** Selection identifies the current object or check; status identifies its assessment. Always preserve the textual status.

## Typography

Use the local system sans-serif stack in the body token. No downloaded font, icon font or network asset is required. This supports disconnected and air-gapped use; the optional guide hyperlink is not a rendering dependency.

Scope headlines use the headline token; list titles use the title token; evidence prose uses the more generous evidence line height. Filter labels and navigation use compact 12px text, and check metadata uses 11px. The selected evidence heading is 21px with 1.35 line height. Object counts use tabular numerals. Actual workspace identity is 24px on its first line and 13px on its edition line, inherited and overridden separately in the stylesheet cascade.

## Layout

The desktop results surface uses a resizable 340px navigation tree and one evidence pane. Navigation follows object → section → check using native disclosures; Categories omits the redundant section tier. Navigation and evidence scroll independently within the viewport-height workspace. Only the selected branch opens initially; user-opened branches persist. Search matches objects, categories and checks and reveals matching branches. A sticky evidence toolbar provides Previous/Next in the filtered selected-domain order, boundary disabling and position feedback. Moving through checks reveals the selected tree row without rebuilding the tree. Original evidence cards and action listeners are retained. One summary counts every original check, including Informational and unfamiliar statuses; Reviewed remains distinct from Passed. Object-check counts in the tree may exceed unique scan totals because one check can apply to multiple objects.

The tree grows vertically with its visible objects and expanded branches, without an internal clipping viewport. Large trees use document scrolling; the evidence pane sticks beside them and scrolls internally, with persistent Previous/Next. At 1000px and below, navigation defaults to 300px. Up to 760px wide, the tree and evidence become separate views: selecting a check opens evidence; Back restores the tree and selected row. Previous/Next remains available in mobile detail. There is no Expand mode or intermediate checklist. Evidence tables retain unbroken headers, normal word wrapping, and keyboard-focusable horizontal scrolling when content exceeds the available width. Wide tables include a visible scrolling hint.

The header actions form a 320px-wide two-column grid (full available width on mobile). Scan spans both columns; Export and Log out share the next row equally with an 8px gap. When visible, Cancel scan spans both columns. Export uses a native disclosure with a positioned menu spanning the action grid; reports remain full-scan exports independent of selected checks and filters. Browser print styling is not the PDF report generator and must not be described as an equivalent full-scan export.

## Elevation & Depth

Working panes and check rows are flat. Thin borders and changes of background create structure. The inherited active Infrastructure/Categories switch has a small `0 1px 4px rgba(20, 32, 51, 0.12)` shadow. Existing modal dialogs retain `0 24px 70px rgba(20, 32, 51, 0.28)` over a translucent ink overlay; this is not a general card shadow.

## Shapes

Controls and the results container use gently curved six-pixel corners. Selected objects/checks and filter fields use five-pixel corners. Ordinary check rows are square with a fine lower separator. Legacy badges remain pill-shaped; avoid expanding the pill shape to every control.

## Components

### Buttons

Header actions use 13px type, 20px line height, 11px × 12px padding and a 44px minimum height. Primary action is pink with white text; secondary actions remain white with an ink label and thin border. The inherited primary hover uses the global dark accent. Disabled buttons have half opacity and a not-allowed cursor. Workspace keyboard focus is a 2px dark-pink outline offset by 3px.

### Inputs / Fields

Search spans both filter columns; status and severity share the next row. Fields have a 38px minimum height, five-pixel corners and a visible slate border. Domain selection appears when domain groups exist. Search matches check title and category within the selected scope, not hidden evidence text.

### Navigation

API Collection and Hardening Guide are icon links anchored at the bottom of the left rail, below its scrollable object list. API Collection opens and focuses the existing command-details disclosure; the guide uses the original external URL in a new tab. The redundant guide strip is hidden once results are available.

Gateway and physical-member symbols use a brick-wall firewall; logical clusters use layered brick walls. Management uses a two-unit rack-server symbol. All are neutral local outline SVGs, not vendor marks.

Object buttons are flat, left-aligned and include a check count. Selection uses pale pink, dark pink text and a border; hover is light slate. Group headings distinguish policy/management from gateways/clusters. Domain, scope, check and filter choices persist for the active session and reset when session identity changes. Infrastructure and Categories remain explicitly labeled alternatives.

### Check rows and evidence

Rows show title, status and severity, grouped by their actual category. Selection has a pale-pink fill and thin pink border; button selection is exposed with `aria-pressed`. The detail pane displays object/category context and the original check card, retaining evidence, target selectors and action listeners. Only the selected original card is attached to the document. Empty filter results show a clear message and Clear filters action; failed domains expose their existing error text.

During a busy operation the checks host is inert, preventing object, filter and evidence interaction until the existing operation completes. Preserve this interaction lock when altering layout. This is a description of the implementation, not a claim of final review approval.

### Badges and disclosures

Evidence status/severity badges retain their original text and colors. Export is a native disclosure with full-scan scope explained in its menu. The original check disclosure remains a real details element, initially open when selected; its marker is visually suppressed in the evidence pane.

## Do's and Don'ts

### Do:

- Do preserve explicit scope, status and severity text alongside color.
- Do keep the independent third-party, non-affiliation disclaimer visible on login and in the signed-in workspace.
- Do retain system fonts and local assets for offline rendering.
- Do preserve original evidence, action approvals and complete report export scope.

### Don't:

- Don't use a Check Point logo, lookalike, generated brand mark or branded favicon.
- Don't promote synthetic concept content to production data.
- Don't apply this results redesign to legacy login or PDF layout without a separate request.
- Don't claim pixel-exact concept matching or review approval from this design record.
