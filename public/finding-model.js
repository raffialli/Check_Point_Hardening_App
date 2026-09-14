// Shared by the server, browser, and PDF generator. Legacy tables are adapted here.
export function checkOwnerScope(check = {}) {
  if (check.ownership?.scope) return check.ownership.scope;
  const id = String(check.id || '');
  if (['updates.dynamic-updates', 'updates.cpdiag'].includes(id)) return 'management';
  if (id.startsWith('policy.') || ['cve.site-to-site-communities', 'advanced.explicit-rules'].includes(id)) return 'policy';
  if (id.startsWith('gaia.') || id.startsWith('updates.') || id.startsWith('security-feature-usage.') || id === 'cve.legacy-clients') {
    return id === 'gaia.management-external-syslog' ? 'management' : 'gateway';
  }
  return 'management';
}
export function displayCellValue(value) {
  if (value == null) return '';
  return typeof value === 'object' ? String(value.value ?? value.label ?? '') : String(value);
}
export function canonicalGatewayName(value) {
  let name = displayCellValue(value).trim();
  const prefix = /^(?:management\s+(?:server\s+)?name|management|gateway\s+name|gateway|firewall\s+name|firewall|target\s+name|target|object\s+name|object)\s*(?::|-)\s*/i;
  while (prefix.test(name)) name = name.replace(prefix, '').trim();
  return name;
}
export const gatewayIdentityKey = value => canonicalGatewayName(value).replace(/\s+/g, ' ').toLowerCase();
export function targetNameFromRow(row = {}) {
  for (const column of ['Gateway', 'Name of Gateway', 'Gateway Name', 'Firewall Name', 'Object Name', 'Target', 'Name']) {
    const value = canonicalGatewayName(row[column]);
    if (value && value !== 'N/A' && value !== 'Not returned') return value;
  }
  return '';
}
export function gatewayTargetsForCheck(check = {}) {
  if (check.ownership?.targets?.length) return check.ownership.targets.map(target => target.name);
  const names = new Map();
  const remember = value => {
    const name = canonicalGatewayName(value);
    if (name) names.set(gatewayIdentityKey(name), name);
  };
  for (const row of check.evidenceTable?.rows || []) remember(targetNameFromRow(row));
  for (const table of check.evidenceTables || []) {
    const rowNames = (table.rows || []).map(targetNameFromRow).filter(Boolean);
    rowNames.forEach(remember);
    if (!rowNames.length) remember(table.title);
  }
  return [...names.values()].sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
}
export function withFindingIdentity(check, { domain = '', inventory = [] } = {}) {
  const byName = new Map(inventory.map(object => [gatewayIdentityKey(object.name), object]));
  const targets = gatewayTargetsForCheck(check).map(name => {
    const object = byName.get(gatewayIdentityKey(name));
    return { name, uid: object?.uid || null, type: object?.type || null, domain,
      key: JSON.stringify([domain, object?.uid || gatewayIdentityKey(name)]), resolved: Boolean(object?.uid) };
  });
  return { ...check, evaluationStatus: check.status, ownership: { scope: checkOwnerScope(check), domain, targets },
    collection: check.collection || { status: 'not-reported', errors: [] } };
}

export function collectionMessage(check) {
  return {
    partial: 'Collection incomplete. Available evidence is shown; uncollected settings are not verified.',
    failed: 'Evidence collection failed. This does not establish whether the setting is secure.',
    unsupported: 'Automated collection is unavailable for this command. Please verify manually using the hardening guide.',
    'not-assessed': 'Not automatically assessed. Follow the manual verification guidance.'
  }[check.collection?.status] || '';
}
