// ========== PAGE 6: SECURITY ==========
// Per-machine security status from Wazuh EDR + broker health scoring.
// No hardcoded machine lists -- reads dynamically from API response + stats.

let lastSecurityHTML = '';

function getSecMachines(healthMap) {
  // Combine machine names from security API + stats polling (via fleet tiles).
  const names = new Set();
  if (healthMap) {
    for (const k of Object.keys(healthMap)) names.add(normalizeMachine(k) || k);
  }
  // Pull from stats-populated tiles (MACHINES array from fleet.js).
  if (typeof MACHINES !== 'undefined') {
    for (const m of MACHINES) names.add(m);
  }
  return Array.from(names).sort();
}

function secDisplayName(id) {
  const map = {
    'omarchy': 'OMARCHY', 'ubuntu-homelab': 'U-HOMELAB', 'raspdeck': 'RASPDECK',
    'thinkbook': 'THINKBOOK', 'willyv4': 'WILLYV4', 'macbook1': 'MACBOOK',
    'sonias-mbp': 'SONIA-MBP',
  };
  return map[id] || id.toUpperCase();
}

function secScoreClass(score) {
  if (score >= 10) return 'critical';
  if (score >= 5) return 'degraded';
  return 'healthy';
}

function secScoreColor(score) {
  if (score >= 10) return 'var(--red)';
  if (score >= 5) return 'var(--warn)';
  return 'var(--green)';
}

function secScorePct(score) {
  return Math.min(100, (score / 15) * 100);
}

function parseEventSeverity(eventStr) {
  if (!eventStr) return { severity: 'info', text: eventStr || '' };
  const lower = eventStr.toLowerCase();
  if (lower.startsWith('critical:')) return { severity: 'critical', text: eventStr.substring(9).trim() };
  if (lower.startsWith('warn:')) return { severity: 'warn', text: eventStr.substring(5).trim() };
  if (lower.startsWith('info:')) return { severity: 'info', text: eventStr.substring(5).trim() };
  return { severity: 'info', text: eventStr };
}

function quarantineDuration(demotedAt) {
  if (!demotedAt) return '';
  const ms = Date.now() - new Date(demotedAt).getTime();
  if (ms < 0) return '0s';
  const s = Math.floor(ms / 1000);
  if (s < 60) return s + 's ago';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
}

function updateSecurityPage(healthMap) {
  const el = document.getElementById('sec-layout');
  if (!el) return;

  const machines = getSecMachines(healthMap);
  const hasData = healthMap && Object.keys(healthMap).length > 0;

  // Tally statuses
  const counts = { healthy: 0, degraded: 0, quarantined: 0 };
  const machineData = [];

  for (const id of machines) {
    const h = hasData ? (healthMap[id] || healthMap[normalizeMachine(id)]) : null;
    const score = h ? h.score : 0;
    const status = h ? h.status : 'healthy';
    const lastEvent = h ? h.last_event_desc : '';
    const lastEventTime = h ? h.last_event : '';
    const events = h ? (h.events || []) : [];
    const demotedAt = h ? h.demoted_at : '';

    counts[status] = (counts[status] || 0) + 1;
    machineData.push({ id, score, status, lastEvent, lastEventTime, events, demotedAt });
  }

  const total = machines.length;
  const anyIssues = counts.degraded > 0 || counts.quarantined > 0;

  // Fleet summary line
  const summaryClass = counts.quarantined > 0 ? 'sec-sum-critical'
    : counts.degraded > 0 ? 'sec-sum-degraded' : 'sec-sum-clear';
  const summaryLabel = counts.quarantined > 0 ? 'QUARANTINE ACTIVE'
    : counts.degraded > 0 ? 'DEGRADED' : 'ALL CLEAR';

  let html = `<div class="sec-header">
    <div class="sec-header-left">
      <span class="sec-title">FLEET SECURITY</span>
      <span class="sec-summary-badge ${summaryClass}">${summaryLabel}</span>
    </div>
    <div class="sec-header-right">
      <span class="sec-stat"><span class="sec-stat-n">${total}</span><span class="sec-stat-l">TOTAL</span></span>
      <span class="sec-stat"><span class="sec-stat-n sec-c-green">${counts.healthy}</span><span class="sec-stat-l">OK</span></span>
      <span class="sec-stat"><span class="sec-stat-n sec-c-warn">${counts.degraded}</span><span class="sec-stat-l">WARN</span></span>
      <span class="sec-stat"><span class="sec-stat-n sec-c-red">${counts.quarantined}</span><span class="sec-stat-l">QRTN</span></span>
      <span class="sec-legend">
        <span class="sec-leg-item"><span class="sec-leg-bar sec-leg-green"></span>0-4</span>
        <span class="sec-leg-item"><span class="sec-leg-bar sec-leg-warn"></span>5-9</span>
        <span class="sec-leg-item"><span class="sec-leg-bar sec-leg-red"></span>10+</span>
      </span>
    </div>
  </div>`;

  // Empty state: all healthy with no events at all
  if (!anyIssues && !hasData) {
    html += `<div class="sec-empty">
      <div class="sec-empty-icon">&#x2714;</div>
      <div class="sec-empty-title">ALL CLEAR</div>
      <div class="sec-empty-sub">${total} machines reporting -- no security events</div>
    </div>`;
  } else {
    // Machine cards grid
    html += '<div class="sec-grid">';
    for (const m of machineData) {
      const isQuarantined = m.status === 'quarantined';
      const isDegraded = m.status === 'degraded';
      const cardClass = isQuarantined ? 'sec-card quarantined'
        : isDegraded ? 'sec-card degraded' : 'sec-card healthy';
      const scoreClass = secScoreClass(m.score);
      const scorePct = secScorePct(m.score);
      const scoreColor = secScoreColor(m.score);

      html += `<div class="${cardClass}">`;

      // Quarantine banner
      if (isQuarantined) {
        const dur = quarantineDuration(m.demotedAt);
        html += `<div class="sec-qrtn-banner">
          <span class="sec-qrtn-label">QUARANTINED</span>
          ${dur ? `<span class="sec-qrtn-since">${dur}</span>` : ''}
        </div>`;
      }

      // Card header: name + status dot
      html += `<div class="sec-card-hdr">
        <span class="sec-dot ${scoreClass}"></span>
        <span class="sec-name">${secDisplayName(m.id)}</span>
        <span class="sec-status-tag ${scoreClass}">${m.status === 'healthy' ? 'SECURE' : m.status.toUpperCase()}</span>
      </div>`;

      // Score gauge -- the big visual
      html += `<div class="sec-gauge-wrap">
        <div class="sec-gauge-score" style="color:${scoreColor}">${m.score}</div>
        <div class="sec-gauge-track">
          <div class="sec-gauge-fill sec-gauge-${scoreClass}" style="width:${scorePct}%"></div>
        </div>
        <div class="sec-gauge-range">
          <span>0</span><span>15</span>
        </div>
      </div>`;

      // Last event
      if (m.lastEvent) {
        const ago = m.lastEventTime ? timeAgo(m.lastEventTime) : '';
        html += `<div class="sec-last-event">
          <span class="sec-last-lbl">LAST</span>
          <span class="sec-last-txt">${esc(m.lastEvent)}</span>
          ${ago ? `<span class="sec-last-ago">${ago}</span>` : ''}
        </div>`;
      }

      // Event list with severity colors
      if (m.events.length > 0) {
        html += '<div class="sec-events">';
        for (const e of m.events.slice(0, 5)) {
          const { severity, text } = parseEventSeverity(e);
          html += `<div class="sec-event sec-ev-${severity}">
            <span class="sec-ev-tag">${severity.toUpperCase()}</span>
            <span class="sec-ev-text">${esc(text)}</span>
          </div>`;
        }
        html += '</div>';
      }

      html += '</div>'; // end card
    }
    html += '</div>'; // end grid
  }

  // Only update DOM if content changed
  if (html !== lastSecurityHTML) {
    el.innerHTML = html;
    lastSecurityHTML = html;
  }
}
