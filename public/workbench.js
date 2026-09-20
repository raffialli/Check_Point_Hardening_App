// Presentation only: cards retain the existing evidence and action listeners.
// Unselected cards live off-document, so target selectors can only see the
// evidence the operator is currently reviewing. Scan/export data is untouched.
let saved = { session: "", domain: "", scope: "", check: "", query: "", status: "", severity: "" };
const expandedBranches = new Map();
let busyObserver;

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
    information: '<circle cx="12" cy="12" r="9"/><path d="M12 7v6"/><circle cx="12" cy="17" r=".7"/>',
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

export function clusterParentScope(scopes, item) {
  const member = scopePresentation(item.title, item.section);
  if (!member.parent) return null;
  return scopes.find(scope => {
    const parent = scopePresentation(scope.title, scope.section);
    return scope.section === item.section && parent.kind === 'cluster' && parent.name === member.parent;
  }) || null;
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

export function visibleTreeChecks(scopes, filters) {
  return orderNavigationScopes(scopes).flatMap(scope => scope.checks
    .filter(check => matchesFinding({...check, title: `${scope.title} ${check.title}`}, filters))
    .map(check => ({scope, check})));
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
  if (saved.session !== sessionKey) {
    saved = { session: sessionKey, domain: "", scope: "", check: "", query: "", status: "", severity: "" };
    expandedBranches.clear();
  }
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
  const detail = element("section", "wb-detail");
  detail.id = 'selectedCheckEvidence';
  detail.tabIndex = -1;
  detail.setAttribute("aria-label", "Selected check evidence");
  const navList = element("div", "wb-nav-list");
  const filters = element("div", "wb-filters");
  const query = element("input");
  query.type = "search"; query.placeholder = "Find an object or check"; query.value = saved.query;
  query.setAttribute("aria-label", "Find an object or check");
  const makeSelect = (label, options, value) => {
    const select = element("select"); select.setAttribute("aria-label", label);
    for (const [id, text] of options) { const option = element("option", "", text); option.value = id; select.append(option); }
    select.value = value; return select;
  };
  const status = makeSelect("Filter by status", [["", "All statuses"], ["action", "Action needed"], ["review", "Review"], ["manual", "Manual"], ["unknown", "Unknown"], ["pass", "Pass"], ["reviewed", "Reviewed"], ["informational", "Informational"]], saved.status);
  const severity = makeSelect("Filter by severity", [["", "All severities"], ["high", "High"], ["medium", "Medium"], ["low", "Low"]], saved.severity);
  filters.append(query, status, severity);
  const count = element("p", "wb-count"); count.setAttribute("role", "status");
  if (viewSwitch) nav.append(viewSwitch);
  else nav.append(element("h2", "wb-nav-title", view === "hierarchy" ? "Infrastructure" : "Categories"));
  let domain = domains.find((item) => item.key === saved.domain) || domains[0];
  let entries = [];
  let selectedIndex = -1;
  const toolbar = element('div', 'wb-evidence-toolbar');
  const context = element('p', 'wb-evidence-context');
  const pager = element('div', 'wb-pager');
  const previous = element('button', '', 'Previous'); previous.type = 'button';
  const position = element('span', 'wb-position'); position.setAttribute('role', 'status');
  const next = element('button', '', 'Next'); next.type = 'button';
  busyObserver?.disconnect();
  busyObserver = new MutationObserver(() => {
    previous.disabled = host.inert || selectedIndex <= 0;
    next.disabled = host.inert || selectedIndex < 0 || selectedIndex >= entries.length - 1;
  });
  busyObserver.observe(host, {attributes: true, attributeFilter: ['inert']});
  const back = element('button', 'wb-back', 'Back to checks'); back.type = 'button';
  const content = element('div', 'wb-evidence-content');
  pager.append(previous, position, next); toolbar.append(context, pager, back);
  detail.append(toolbar, content);
  const branchKey = (scope, category = '') => JSON.stringify([sessionKey, view, domain.key, scope.key, category]);
  const revealSelection = () => {
    const button = navList.querySelector('.wb-tree-check.selected');
    if (!button) return;
    let parent = button.parentElement;
    while (parent && parent !== navList) {
      if (parent.tagName === 'DETAILS') {
        parent.open = true;
        if (!saved.query && !saved.status && !saved.severity) expandedBranches.set(parent.dataset.branchKey, true);
      }
      parent = parent.parentElement;
    }
    const row = button.getBoundingClientRect();
    if (!matchMedia('(max-width: 760px)').matches && (row.top < 12 || row.bottom > innerHeight)) {
      button.scrollIntoView({block: 'nearest'});
    }
  };
  const showCheck = (index, {reveal = false, mobile = false} = {}) => {
    selectedIndex = index;
    const entry = entries[index];
    const check = entry?.check, scope = entry?.scope;
    saved.check = check?.id || ''; saved.scope = scope?.key || '';
    content.replaceChildren();
    navList.querySelectorAll('.wb-tree-check').forEach(button => {
      const selected = Number(button.dataset.index) === index;
      button.classList.toggle('selected', selected);
      button.setAttribute('aria-current', selected ? 'true' : 'false');
    });
    previous.disabled = index <= 0; next.disabled = index < 0 || index >= entries.length - 1;
    position.textContent = entries.length ? `${index + 1} of ${entries.length}` : '0 checks';
    if (!check) {
      context.textContent = domain.title;
      content.append(element('p', 'wb-empty', domain.error || 'No checks match these filters.'));
      return;
    }
    context.textContent = `${scopePresentation(scope.title, scope.section).name} / ${check.category}`;
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
    content.append(check.card);
    detail.scrollTop = 0;
    if (reveal) revealSelection();
    if (mobile && matchMedia('(max-width: 760px)').matches) {
      host.classList.add('show-evidence');
      detail.focus({preventScroll: true}); host.scrollIntoView({block: 'start'});
    }
    if (reveal || mobile) detail.scrollIntoView({block: 'start'});
  };
  previous.addEventListener('click', () => { if (!host.inert && selectedIndex > 0) showCheck(selectedIndex - 1, {reveal: true}); });
  next.addEventListener('click', () => { if (!host.inert && selectedIndex < entries.length - 1) showCheck(selectedIndex + 1, {reveal: true}); });
  back.addEventListener('click', () => {
    if (host.inert) return;
    host.classList.remove('show-evidence');
    const selected = navList.querySelector('.selected');
    selected?.focus({preventScroll: true});
    selected?.scrollIntoView({block: 'nearest'});
  });
  const showDomain = () => {
    saved.domain = domain.key;
    entries = visibleTreeChecks(domain.scopes, saved);
    const found = entries.findIndex(entry => entry.scope.key === saved.scope && entry.check.id === saved.check);
    const index = entries.length ? Math.max(0, found) : -1;
    const chosen = entries[index];
    const filtering = Boolean(saved.query || saved.status || saved.severity);
    const scroll = navList.scrollTop;
    navList.replaceChildren(); let section = '';
    count.textContent = `${entries.length} ${view === 'categories' ? 'checks' : 'object checks'} in this view`;
    const branch = (key, label, kind, initiallyOpen) => {
      const node = element('details', 'wb-tree-branch');
      node.dataset.branchKey = key;
      if (!expandedBranches.has(key)) expandedBranches.set(key, initiallyOpen);
      node.open = filtering || expandedBranches.get(key);
      const summary = element('summary');
      if (kind) summary.append(icon(kind));
      summary.append(element('span', '', label)); node.append(summary);
      summary.addEventListener('click', event => {
        if (host.inert) { event.preventDefault(); return; }
        if (!filtering) expandedBranches.set(key, !node.open);
      });
      return node;
    };
    const objects = new Map();
    for (const item of orderNavigationScopes(domain.scopes)) {
      const itemEntries = entries.map((entry, i) => ({...entry, index: i})).filter(entry => entry.scope === item);
      const hasMatchingMember = entries.some(entry => clusterParentScope(domain.scopes, entry.scope) === item);
      if (!itemEntries.length && !hasMatchingMember) continue;
      if (item.section !== section) { section = item.section; navList.append(element("h3", "wb-nav-section", section)); }
      const presentation = scopePresentation(item.title, item.section);
      if (view !== 'categories' && item.checks.length === 1 && item.checks[0].id === 'policy.gateway-object-status') {
        const entry = itemEntries[0];
        const button = element('button', 'wb-tree-check wb-direct-check');
        button.type = 'button'; button.dataset.index = entry.index;
        button.setAttribute('aria-controls', detail.id);
        button.setAttribute('aria-label', `${entry.check.title}, ${entry.check.statusText}, ${entry.check.severity}`);
        button.append(icon('information'), element('span', '', entry.check.title));
        button.addEventListener('click', () => { if (!host.inert) showCheck(entry.index, {mobile: true}); });
        navList.append(button);
        continue;
      }
      const selectedChild = chosen && clusterParentScope(domain.scopes, chosen.scope) === item;
      const object = branch(branchKey(item), presentation.name, presentation.kind, chosen?.scope === item || Boolean(selectedChild));
      if (presentation.subtitle) object.querySelector('summary span').append(element('small', 'wb-object-type', presentation.subtitle));
      const parentObject = objects.get(clusterParentScope(domain.scopes, item));
      if (parentObject) object.classList.add('wb-cluster-member');
      (parentObject || navList).append(object);
      objects.set(item, object);
      const categories = new Map();
      for (const entry of itemEntries) {
        let parent = object;
        if (view !== 'categories') {
          if (!categories.has(entry.check.category)) {
            const category = branch(branchKey(item, entry.check.category), entry.check.category, null, chosen?.check.category === entry.check.category);
            object.append(category); categories.set(entry.check.category, category);
          }
          parent = categories.get(entry.check.category);
        }
        const button = element('button', 'wb-tree-check'); button.type = 'button'; button.dataset.index = entry.index;
        button.setAttribute('aria-controls', detail.id);
        button.setAttribute('aria-label', `${entry.check.title}, ${entry.check.statusText}, ${entry.check.severity}`);
        const mark = element('span', `wb-state-mark ${statusBucket(entry.check.status)}`); mark.setAttribute('aria-hidden', 'true');
        button.append(mark, element('span', '', entry.check.title)); button.title = entry.check.statusText;
        button.addEventListener('click', () => { if (!host.inert) showCheck(entry.index, {mobile: true}); }); parent.append(button);
      }
    }
    if (!entries.length) {
      navList.append(element('p', 'wb-empty', domain.error || 'No matching checks.'));
      const clear = element('button', '', 'Clear filters'); clear.type = 'button';
      clear.onclick = () => { if (host.inert) return; saved.query = saved.status = saved.severity = ''; query.value = status.value = severity.value = ''; showDomain(); };
      if (filtering) navList.append(clear);
    }
    showCheck(index); navList.scrollTop = scroll;
  };
  if (domainNodes.length) {
    const domainSelect = makeSelect("Domain", domains.map((item) => [item.key, `${item.title}${item.error ? " — scan failed" : ""}`]), domain.key);
    domainSelect.addEventListener("change", () => { if (host.inert) return; domain = domains.find((item) => item.key === domainSelect.value); saved.check = ""; host.classList.remove('show-evidence'); showDomain(); });
    nav.append(element("label", "wb-domain-label", "Domain"), domainSelect);
  }
  nav.append(filters, count, navList);
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
    saved.query = query.value; saved.status = status.value; saved.severity = severity.value; showDomain();
  });
  host.append(nav, detail); showDomain();
}
