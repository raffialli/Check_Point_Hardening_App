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

The desktop results surface contains navigation, checks and evidence. Its implemented grid is `225px minmax(300px, .95fr) minmax(360px, 1.3fr)`, with no gutter between panes and a minimum height of 610px. These are implementation measurements, not the provisional 250px/400px concept dimensions. The workspace uses 24px horizontal padding and a 10px section gap. Compact metrics sit above results; guide, API collection and log content follow results.

At 1200px and wider, each pane scrolls vertically within `calc(100vh - 310px)` with a 550px minimum height. At 1199px and below, columns become `190px minmax(260px, 1fr) minmax(310px, 1.2fr)` and workspace horizontal padding becomes 12px. At 900px and below, evidence spans beneath navigation and checks; selection moves keyboard focus into evidence. At 560px and below, panes stack and navigation has a 250px scrolling maximum height. Evidence tables retain their original overflow handling.

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
