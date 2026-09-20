// Presentation only: cards retain the existing evidence and action listeners.
// Unselected cards live off-document, so target selectors can only see the
// evidence the operator is currently reviewing. Scan/export data is untouched.
let saved = { session: "", domain: "", scope: "", check: "", query: "", status: "", severity: "" };

export function statusBucket(status) {
  if (["remediation-required", "remediation-recommended"].includes(status)) return "action";
  if (["needs-review", "remediation-review-recommended"].includes(status)) return "review";
  return status || "unknown";
}

export function summarizeFindings(checks = []) {
  const counts = new Map();
  for (const check of checks) {
    const key = statusBucket(check.status);
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  const labels = {action: 'Remediation needed', review: 'Review recommended', manual: 'Manual validation', unknown: 'Unknown', pass: 'Passed', reviewed: 'Reviewed', informational: 'Informational'};
  const keys = [...Object.keys(labels), ...[...counts.keys()].filter(key => !(key in labels))];
  return [{key: 'total', label: 'Total checks', count: checks.length}, ...keys
    .filter(key => counts.has(key) || ['action', 'review', 'manual', 'unknown', 'pass'].includes(key))
    .map(key => ({key, label: labels[key] || key.replaceAll('-', ' '), count: counts.get(key) || 0}))];
}

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

// Small, neutral UI symbols—not a vendor logo. Kept local for offline use.
function icon(kind) {
  const paths = {
    gateway: '<rect x="2" y="4" width="20" height="16" rx="1"/><path d="M2 9h20M2 15h20M8 4v5m8-5v5m-4 0v6m-4 0v5m8-5v5"/>',
    management: '<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><circle cx="7" cy="6.5" r=".75"/><circle cx="7" cy="17.5" r=".75"/><path d="M12 6.5h5M12 17.5h5M6 10v4m12-4v4"/>',
    cluster: '<rect x="6" y="3" width="16" height="14" rx="1"/><path d="M6 8h16M6 12h16M14 3v5m-4 0v4m8-4v4m-4 0v5M2 7v14h16"/>',
    category: '<path d="M4 5h16M4 12h16M4 19h16"/>',
    chevron: '<path d="m9 5 7 7-7 7"/>',
    api: '<path d="m7 7-5 5 5 5m10-10 5 5-5 5m-3-13-4 20"/>',
    guide: '<path d="M12 5C9 3 5 3 2 4v15c3-1 7-1 10 1 3-2 7-2 10-1V4c-3-1-7-1-10 1Zm0 0v15"/>'
  };
  const node = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  node.setAttribute('viewBox', '0 0 24 24'); node.setAttribute('aria-hidden', 'true');
  node.setAttribute('class', 'wb-icon'); node.setAttribute('fill', 'none');
  node.setAttribute('stroke', 'currentColor'); node.setAttribute('stroke-width', '1.5');
  node.setAttribute('stroke-linecap', 'round'); node.setAttribute('stroke-linejoin', 'round');
  node.innerHTML = paths[kind] || paths.gateway;
  return node;
}

export function scopePresentation(title, section) {
  const member = title.match(/^(.*?) \(cluster member of: (.*)\)$/i);
  if (member) return { name: member[1], subtitle: `Member of ${member[2]}`, kind: 'gateway', parent: member[2] };
  if (title.endsWith(' (Cluster Object)')) return { name: title.slice(0, -17), subtitle: 'Cluster object', kind: 'cluster' };
  if (section === 'Categories') return { name: title, subtitle: '', kind: 'category' };
  return { name: title, subtitle: '', kind: section === 'Policy and Management' ? 'management' : 'gateway' };
}

export function orderNavigationScopes(scopes) {
  const ordered = [];
  for (const scope of scopes) {
    const current = scopePresentation(scope.title, scope.section);
    const hasParent = current.parent && scopes.some(item => {
      const parent = scopePresentation(item.title, item.section);
      return item.section === scope.section && parent.kind === 'cluster' && parent.name === current.parent;
    });
    if (hasParent) continue;
    ordered.push(scope);
    if (current.kind === 'cluster') ordered.push(...scopes.filter(item => item.section === scope.section && scopePresentation(item.title, item.section).parent === current.name));
  }
  return ordered;
}

function record(card) {
  const badges = card.querySelectorAll(":scope > summary .badge");
  const status = [...(badges[0]?.classList || [])].find((name) => name !== "badge") || "unknown";
  const severity = [...(badges[1]?.classList || [])].find((name) => name.startsWith("severity-"))?.slice(9) || "medium";
  return { card, id: card.dataset.checkId, title: card.querySelector("h4")?.textContent || "Check",
    category: card.closest(".check-group")?.dataset.category || "Checks", status, severity,
    statusText: badges[0]?.textContent || "Unknown" };
}

export function matchesFinding(check, filters) {
  return (!filters.query || `${check.title} ${check.category}`.toLowerCase().includes(filters.query.toLowerCase()))
    && (!filters.status || statusBucket(check.status) === filters.status)
    && (!filters.severity || check.severity === filters.severity);
}

function scopesFrom(root, view) {
  const scopes = [];
  const add = (key, title, section, cards, description = "") => {
    if (cards.length) scopes.push({ key, title, section, description, checks: cards.map(record) });
  };
  if (view === "categories") {
    root.querySelectorAll(".check-group").forEach((group) => add(group.dataset.category, group.dataset.category, "Categories", [...group.querySelectorAll(".check-card")]));
  } else {
    root.querySelectorAll(".hierarchy-node").forEach((node) => {
      const ownCards = [...node.querySelectorAll(".check-card")].filter((card) => card.closest(".hierarchy-node") === node);
      const gateway = node.classList.contains("gateway-node") || node.classList.contains("gateways-node");
      const title = node.classList.contains("gateways-node") ? "Gateway Object SIC Status" : node.querySelector(":scope > summary strong")?.textContent || "Management";
      add(node.dataset.hierarchyKey, title, gateway ? "Gateways and clusters" : "Policy and Management", ownCards,
        node.querySelector(":scope > summary small")?.textContent || "");
    });
  }
  return scopes;
}

export function mountWorkbench(host, { view = "hierarchy", sessionKey = "", viewSwitch, commandPanel, guideLink } = {}) {
  if (saved.session !== sessionKey) saved = { session: sessionKey, domain: "", scope: "", check: "", query: "", status: "", severity: "" };
  const domainNodes = [...host.querySelectorAll(".mora-domain-group")];
  const domains = domainNodes.length ? domainNodes.map((node, index) => ({
    key: `${index}:${node.dataset.domainName}`, title: node.dataset.domainName,
    scopes: scopesFrom(node, view), error: node.querySelector(".mora-domain-error")?.textContent
  })) : [{ key: "single", title: "Current environment", scopes: scopesFrom(host, view) }];
  // Hold the original nodes (and listeners) before replacing their wrappers.
  host.replaceChildren();
  host.classList.add("workbench");
  host.parentElement.classList.add('has-workbench');
  const nav = element("nav", "wb-nav");
  nav.setAttribute("aria-label", "Scan objects");
  const center = element("section", "wb-findings");
  const detail = element("section", "wb-detail");
  detail.id = 'selectedCheckEvidence';
  detail.tabIndex = -1;
  detail.setAttribute("aria-label", "Selected check evidence");
  const navList = element("div", "wb-nav-list");
  const heading = element("h2", "wb-scope-title");
  const breadcrumb = element('p', 'wb-breadcrumb');
  const description = element("p", "wb-scope-description");
  const filters = element("div", "wb-filters");
  const query = element("input");
  query.type = "search"; query.placeholder = "Search checks…"; query.value = saved.query;
  query.setAttribute("aria-label", "Search checks in selected object");
  const makeSelect = (label, options, value) => {
    const select = element("select"); select.setAttribute("aria-label", label);
    for (const [id, text] of options) { const option = element("option", "", text); option.value = id; select.append(option); }
    select.value = value; return select;
  };
  const status = makeSelect("Filter by status", [["", "All statuses"], ["action", "Action needed"], ["review", "Review"], ["manual", "Manual"], ["unknown", "Unknown"], ["pass", "Pass"], ["reviewed", "Reviewed"], ["informational", "Informational"]], saved.status);
  const severity = makeSelect("Filter by severity", [["", "All severities"], ["high", "High"], ["medium", "Medium"], ["low", "Low"]], saved.severity);
  filters.append(query, status, severity);
  const count = element("p", "wb-count"); count.setAttribute("role", "status");
  const list = element("div", "wb-check-list");
  const columns = element('div', 'wb-list-columns'); columns.setAttribute('aria-hidden', 'true');
  columns.append(element('span', '', 'Check'), element('span', '', 'Status'), element('span', '', 'Severity'), element('span'));
  center.append(breadcrumb, heading, description, filters, count, columns, list);
  if (viewSwitch) nav.append(viewSwitch);
  else nav.append(element("h2", "wb-nav-title", view === "hierarchy" ? "Infrastructure" : "Categories"));
  let domain = domains.find((item) => item.key === saved.domain) || domains[0];
  let scope;
  const showCheck = (check) => {
    saved.check = check?.id || "";
    detail.replaceChildren();
    list.querySelectorAll("button").forEach((button) => {
      const selected = button.dataset.checkId === saved.check;
      button.classList.toggle("selected", selected);
      button.setAttribute("aria-pressed", String(selected));
    });
    if (!check) { detail.append(element("p", "wb-empty", "Select a check to review its evidence.")); return; }
    const context = element("p", "wb-evidence-context", `${scopePresentation(scope.title, scope.section).name} / ${check.category} · Check ${scope.checks.indexOf(check) + 1} of ${scope.checks.length}`);
    const toolbar = element('div', 'wb-evidence-toolbar');
    const back = element('button', 'wb-back', 'Back to checks'); back.type = 'button';
    back.addEventListener('click', () => {
      if (host.inert) return;
      host.classList.remove('show-evidence');
      list.querySelector('.selected')?.focus({preventScroll: true});
      center.scrollIntoView({block: 'start'});
    });
    toolbar.append(context, back);
    check.card.open = true;
    check.card.querySelectorAll('.evidence-table-wrap').forEach((wrap) => {
      wrap.tabIndex = 0; wrap.setAttribute('role', 'region');
      wrap.setAttribute('aria-label', `${wrap.querySelector('.evidence-title')?.textContent || 'Evidence'} — scroll horizontally for more columns`);
      if (wrap.querySelectorAll('thead th').length > 4 && !wrap.classList.contains('wb-wide-table')) {
        const hint = element('p', 'wb-table-hint', 'Wide table: scroll horizontally to view all columns.');
        wrap.before(hint);
        // Keep a marker on the persistent card wrapper to avoid duplicate hints.
        wrap.classList.add('wb-wide-table');
      }
    });
    detail.append(toolbar, check.card);
    detail.scrollTop = 0;
  };
  const showList = () => {
    list.replaceChildren();
    const checks = (scope?.checks || []).filter((check) => matchesFinding(check, saved));
    count.textContent = `${checks.length} of ${scope?.checks.length || 0} checks`;
    let category = "";
    for (const check of checks) {
      if (category !== check.category) { category = check.category; list.append(element("h3", "wb-category", category)); }
      const button = element("button", "wb-check-row"); button.type = "button"; button.dataset.checkId = check.id;
      button.setAttribute('aria-controls', detail.id);
      const title = element("span", "wb-check-title", check.title);
      const bucket = statusBucket(check.status);
      const statusText = {action:'Action needed', review:'Review'}[bucket] || check.statusText;
      const badge = element('span', `wb-status ${bucket}`, statusText); badge.title = check.statusText;
      button.setAttribute('aria-label', `${check.title} — ${check.statusText}, ${check.severity}`);
      button.append(title, badge, element('span', `wb-severity ${check.severity}`, check.severity), icon('chevron')); button.addEventListener("click", () => {
        if (host.inert) return;
        showCheck(check);
        if (matchMedia("(max-width: 760px), (max-height: 650px)").matches) {
          host.classList.add('show-evidence');
          detail.focus({preventScroll: true}); detail.scrollIntoView({block: 'start'});
        }
      }); list.append(button);
    }
    if (!checks.length) {
      list.append(element("p", "wb-empty", domain.error || (scope ? "No checks match these filters." : "No checks were returned for this domain.")));
      if (scope) { const clear = element("button", "", "Clear filters"); clear.type = "button"; clear.onclick = () => { saved.query = saved.status = saved.severity = ""; query.value = status.value = severity.value = ""; showList(); }; list.append(clear); }
    }
    showCheck(checks.find((check) => check.id === saved.check) || checks[0]);
  };
  const chooseScope = (next) => {
    host.classList.remove('show-evidence');
    scope = next; saved.scope = scope?.key || "";
    const presentation = scope ? scopePresentation(scope.title, scope.section) : null;
    heading.textContent = presentation?.name || domain.title;
    breadcrumb.textContent = scope?.section || domain.title;
    description.textContent = presentation?.subtitle || scope?.description || "Review findings and their supporting evidence.";
    navList.querySelectorAll("button").forEach((button) => { const active = button.dataset.scope === saved.scope; button.classList.toggle("selected", active); button.setAttribute("aria-pressed", String(active)); });
    showList();
  };
  const showDomain = () => {
    saved.domain = domain.key; navList.replaceChildren(); let section = "";
    for (const item of orderNavigationScopes(domain.scopes)) {
      if (item.section !== section) { section = item.section; navList.append(element("h3", "wb-nav-section", section)); }
      const presentation = scopePresentation(item.title, item.section);
      const button = element("button", `wb-object${presentation.parent ? ' wb-member' : ''}`); button.type = "button"; button.dataset.scope = item.key;
      const label = element('span', 'wb-object-label'); label.append(element('span', 'wb-object-name', presentation.name));
      if (presentation.subtitle) label.append(element('small', 'wb-object-type', presentation.subtitle));
      button.append(icon(presentation.kind), label);
      button.append(element("span", "wb-object-count", String(item.checks.length)));
      button.addEventListener("click", () => { if (!host.inert) chooseScope(item); }); navList.append(button);
    }
    chooseScope(domain.scopes.find((item) => item.key === saved.scope) || domain.scopes[0]);
  };
  if (domainNodes.length) {
    const domainSelect = makeSelect("Domain", domains.map((item) => [item.key, `${item.title}${item.error ? " — scan failed" : ""}`]), domain.key);
    domainSelect.addEventListener("change", () => { if (host.inert) return; domain = domains.find((item) => item.key === domainSelect.value); saved.check = ""; showDomain(); });
    nav.append(element("label", "wb-domain-label", "Domain"), domainSelect);
  }
  nav.append(navList);
  const footer = element('div', 'wb-nav-footer');
  if (commandPanel) {
    const api = element('button', 'wb-resource-link'); api.type = 'button';
    api.append(icon('api'), element('span', '', 'API Collection'));
    api.setAttribute('aria-controls', commandPanel.id);
    api.addEventListener('click', () => {
      if (host.inert) return;
      commandPanel.classList.remove('hidden');
      const details = commandPanel.querySelector('details');
      if (details) details.open = true;
      commandPanel.scrollIntoView({block: 'start'});
      commandPanel.querySelector('summary')?.focus({preventScroll: true});
    });
    footer.append(api);
  }
  if (guideLink) {
    const guide = element('a', 'wb-resource-link');
    guide.href = guideLink.href; guide.target = '_blank'; guide.rel = 'noreferrer';
    guide.append(icon('guide'), element('span', '', 'Hardening Guide'));
    footer.append(guide);
  }
  nav.append(footer);
  for (const control of [query, status, severity]) control.addEventListener(control === query ? "input" : "change", () => {
    if (host.inert) return;
    saved.query = query.value; saved.status = status.value; saved.severity = severity.value; showList();
  });
  host.append(nav, center, detail); showDomain();
}
