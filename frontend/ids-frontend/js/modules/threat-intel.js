function pct(value) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return 'N/A';
  return `${(Number(value) * 100).toFixed(1)}%`;
}

function safe(value, fallback = 'Unknown') {
  return value === null || value === undefined || value === '' ? fallback : value;
}

function renderMetric(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function renderBlockedIps(items) {
  const list = document.getElementById('blockedIpsList');
  const count = document.getElementById('blockedIpsCount');
  if (!list) return;
  if (count) count.textContent = String(items.length);

  if (!items.length) {
    list.innerHTML = '<div class="intel-empty">No IPs have crossed the block threshold.</div>';
    return;
  }

  list.innerHTML = items.slice(0, 6).map((item) => `
    <div class="intel-row">
      <div>
        <div class="intel-row__primary">${item.ip}</div>
        <div class="intel-row__secondary">${safe(item.latest_type)} - ${safe(item.geo?.country)}</div>
      </div>
      <div class="intel-row__score">${Math.round(item.score)}</div>
    </div>
  `).join('');
}

function renderAttackers(items) {
  const list = document.getElementById('attackerGeoList');
  if (!list) return;

  if (!items.length) {
    list.innerHTML = '<div class="intel-empty">No attacker IPs observed yet.</div>';
    return;
  }

  list.innerHTML = items.slice(0, 6).map((item) => {
    const geo = item.geo || {};
    const location = `${safe(geo.city)} / ${safe(geo.country)}`;
    const risk = safe(geo.vpn_risk);
    const riskClass = risk.toLowerCase() === 'elevated' ? 'intel-pill--risk' : '';
    return `
      <div class="intel-row">
        <div>
          <div class="intel-row__primary">${item.ip}</div>
          <div class="intel-row__secondary">${location} - ${item.alert_count} alerts</div>
        </div>
        <span class="intel-pill ${riskClass}">${risk}</span>
      </div>
    `;
  }).join('');
}

function renderVpnProtection(lines) {
  const list = document.getElementById('vpnProtectionList');
  if (!list) return;
  list.innerHTML = lines.map((line) => `<li>${line}</li>`).join('');
}

async function loadThreatIntel() {
  const [analyticsRes, blockedRes, intelRes] = await Promise.all([
    fetch('/api/model-analytics'),
    fetch('/api/blocked-ips'),
    fetch('/api/threat-intel'),
  ]);

  const analytics = await analyticsRes.json();
  const blocked = await blockedRes.json();
  const intel = await intelRes.json();

  const metrics = analytics.metrics || {};
  const live = analytics.live || {};

  renderMetric('modelAccuracy', pct(metrics.accuracy));
  renderMetric('modelPrecision', pct(metrics.precision));
  renderMetric('modelF1', pct(metrics.f1));
  renderMetric('modelProbability', pct(live.latest_probability ?? metrics.avg_attack_probability));
  renderMetric('modelDataSource', safe(metrics.data_source, 'Not recorded'));
  renderMetric('modelSampleCount', metrics.samples_total ? Number(metrics.samples_total).toLocaleString() : 'N/A');
  renderMetric('modelLatestType', safe(live.latest_type, 'No scored alerts'));

  renderBlockedIps(Array.isArray(blocked) ? blocked : []);
  renderAttackers(Array.isArray(intel.attackers) ? intel.attackers : []);
  renderVpnProtection(Array.isArray(intel.vpn_protection) ? intel.vpn_protection : []);
}

export function initThreatIntel() {
  if (!document.getElementById('modelAnalyticsCard')) return null;

  loadThreatIntel().catch((err) => {
    console.error('[Orion] Threat intel fetch error:', err);
  });

  const interval = setInterval(() => {
    loadThreatIntel().catch((err) => {
      console.error('[Orion] Threat intel fetch error:', err);
    });
  }, 5000);

  return () => clearInterval(interval);
}
