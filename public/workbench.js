// Presentation only: cards retain the existing evidence and action listeners.
// Unselected cards live off-document, so target selectors can only see the
// evidence the operator is currently reviewing. Scan/export data is untouched.
let saved = { session: "", domain: "", scope: "", check: "", query: "", status: "", severity: "" };

export function statusBucket(status) {
  if (["remediation-required", "remediation-recommended"].includes(status)) return "action";
  if (["needs-review", "remediation-review-recommended"].includes(status)) return "review";
  return status || "unknown";
}

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
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

export function mountWorkbench(host, { view = "hierarchy", sessionKey = "" } = {}) {
  if (saved.session !== sessionKey) saved = { session: sessionKey, domain: "", scope: "", check: "", query: "", status: "", severity: "" };
  const domainNodes = [...host.querySelectorAll(".mora-domain-group")];
  const domains = domainNodes.length ? domainNodes.map((node, index) => ({
    key: `${index}:${node.dataset.domainName}`, title: node.dataset.domainName,
    scopes: scopesFrom(node, view), error: node.querySelector(".mora-domain-error")?.textContent
  })) : [{ key: "single", title: "Current environment", scopes: scopesFrom(host, view) }];
  // Hold the original nodes (and listeners) before replacing their wrappers.
  host.replaceChildren();
  host.classList.add("workbench");
  const nav = element("nav", "wb-nav");
  nav.setAttribute("aria-label", "Scan objects");
  const center = element("section", "wb-findings");
  const detail = element("section", "wb-detail");
  detail.setAttribute("aria-label", "Selected check evidence");
  const navList = element("div", "wb-nav-list");
  const heading = element("h2", "wb-scope-title");
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
  center.append(heading, description, filters, count, list);
  nav.append(element("h2", "wb-nav-title", view === "hierarchy" ? "Infrastructure" : "Categories"));
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
    const context = element("p", "wb-evidence-context", `${scope.title} / ${check.category}`);
    check.card.open = true;
    detail.append(context, check.card);
  };
  const showList = () => {
    list.replaceChildren();
    const checks = (scope?.checks || []).filter((check) => matchesFinding(check, saved));
    count.textContent = `${checks.length} of ${scope?.checks.length || 0} checks`;
    let category = "";
    for (const check of checks) {
      if (category !== check.category) { category = check.category; list.append(element("h3", "wb-category", category)); }
      const button = element("button", "wb-check-row"); button.type = "button"; button.dataset.checkId = check.id;
      const title = element("span", "wb-check-title", check.title);
      const meta = element("span", "wb-check-meta");
      meta.append(element("span", `wb-status ${statusBucket(check.status)}`, check.statusText), element("span", `wb-severity ${check.severity}`, check.severity));
      button.append(title, meta); button.addEventListener("click", () => {
        if (host.inert) return;
        showCheck(check);
        if (matchMedia("(max-width: 900px)").matches) { detail.tabIndex = -1; detail.focus(); }
      }); list.append(button);
    }
    if (!checks.length) {
      list.append(element("p", "wb-empty", domain.error || (scope ? "No checks match these filters." : "No checks were returned for this domain.")));
      if (scope) { const clear = element("button", "", "Clear filters"); clear.type = "button"; clear.onclick = () => { saved.query = saved.status = saved.severity = ""; query.value = status.value = severity.value = ""; showList(); }; list.append(clear); }
    }
    showCheck(checks.find((check) => check.id === saved.check) || checks[0]);
  };
  const chooseScope = (next) => {
    scope = next; saved.scope = scope?.key || "";
    heading.textContent = scope?.title || domain.title;
    description.textContent = scope?.description || "Review findings and their supporting evidence.";
    navList.querySelectorAll("button").forEach((button) => { const active = button.dataset.scope === saved.scope; button.classList.toggle("selected", active); button.setAttribute("aria-pressed", String(active)); });
    showList();
  };
  const showDomain = () => {
    saved.domain = domain.key; navList.replaceChildren(); let section = "";
    for (const item of domain.scopes) {
      if (item.section !== section) { section = item.section; navList.append(element("h3", "wb-nav-section", section)); }
      const button = element("button", "wb-object", item.title); button.type = "button"; button.dataset.scope = item.key;
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
  for (const control of [query, status, severity]) control.addEventListener(control === query ? "input" : "change", () => {
    if (host.inert) return;
    saved.query = query.value; saved.status = status.value; saved.severity = severity.value; showList();
  });
  host.append(nav, center, detail); showDomain();
}
