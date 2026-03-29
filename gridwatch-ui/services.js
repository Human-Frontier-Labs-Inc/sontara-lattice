// ========== PAGE 2: SERVICES ==========

function latencyClass(ms) {
  if (ms < 50) return 'lat-green';
  if (ms < 200) return 'lat-yellow';
  return 'lat-red';
}

function latencyBarWidth(ms) {
  // Scale: 0ms = 0%, 500ms+ = 100%
  return Math.min(100, Math.round((ms / 500) * 100));
}

function renderLatency(ms) {
  const cls = latencyClass(ms);
  return `<div class="svc-latency-wrap">
    <div class="svc-latency-bar"><div class="svc-latency-fill ${cls}" style="width:${latencyBarWidth(ms)}%"></div></div>
    <span class="svc-latency-val ${cls}">${ms}ms</span>
  </div>`;
}

function renderFailedBanner(failedUnits) {
  if (!failedUnits || !failedUnits.length) return '';
  const units = failedUnits.map(u => {
    const name = typeof u === 'string' ? u : (u.name || u);
    return `<span class="svc-alert-unit">${esc(name)}</span>`;
  }).join('');
  return `<div class="svc-alert-banner">
    <span class="svc-alert-icon">FAILED</span>
    <div class="svc-alert-units">${units}</div>
  </div>`;
}

function renderInfraPanel(services) {
  if (!services || !services.length) return '';
  let html = `<div class="svc-panel">
    <div class="svc-panel-hdr">INFRASTRUCTURE <span class="svc-panel-count">${services.length}</span></div>`;
  for (const svc of services) {
    const isDown = svc.status === 'down';
    const isDegraded = svc.status === 'degraded';
    const rowCls = isDown ? 'svc-row-down' : isDegraded ? 'svc-row-degraded' : '';
    html += `<div class="svc-row ${rowCls}">
      <span class="svc-dot ${svc.status}"></span>
      <span class="svc-name">${esc(svc.name)}</span>
      ${svc.port ? `<span class="svc-port">:${svc.port}</span>` : ''}
      ${isDown ? `<span class="svc-down-label">${esc(svc.detail || 'DOWN')}</span>` : renderLatency(svc.latency_ms)}
    </div>`;
  }
  html += '</div>';
  return html;
}

function renderDockerPanel(containers) {
  if (!containers || !containers.length) return '';
  let html = `<div class="svc-panel">
    <div class="svc-panel-hdr">DOCKER <span class="svc-panel-count">${containers.length}</span></div>`;
  for (const c of containers) {
    const isUnhealthy = c.health === 'unhealthy';
    const isRunning = c.status === 'running';
    const dotCls = isUnhealthy ? 'unhealthy' : isRunning ? 'running' : 'down';
    const rowCls = isUnhealthy ? 'svc-row-unhealthy' : !isRunning ? 'svc-row-down' : '';

    const healthBadge = c.health === 'healthy'
      ? '<span class="svc-badge healthy">HEALTHY</span>'
      : isUnhealthy
        ? '<span class="svc-badge unhealthy">UNHEALTHY</span>'
        : '';

    const restartBadge = c.restarts > 0
      ? `<span class="svc-badge restart">R:${c.restarts}</span>` : '';

    html += `<div class="svc-row ${rowCls}">
      <span class="svc-dot ${dotCls}"></span>
      <span class="svc-name">${esc(c.name)}</span>
      ${c.port ? `<span class="svc-port">:${c.port}</span>` : ''}
      ${healthBadge}
      ${restartBadge}
      <span class="svc-detail">${esc(c.uptime || '')}</span>
    </div>`;
  }
  html += '</div>';
  return html;
}

function renderTunnelPanel(tunnels) {
  if (!tunnels || !tunnels.length) return '';
  let html = `<div class="svc-panel">
    <div class="svc-panel-hdr">TUNNELS <span class="svc-panel-count">${tunnels.length}</span></div>`;
  for (const t of tunnels) {
    const isDown = t.status === 'down';
    const rowCls = isDown ? 'svc-row-down' : '';
    html += `<div class="svc-row ${rowCls}">
      <span class="svc-dot ${t.status}"></span>
      <span class="svc-name">${esc(t.name)}</span>
      ${isDown ? '<span class="svc-down-label">DOWN</span>' : renderLatency(t.latency_ms)}
    </div>`;
    const conns = t.tunnel_conns != null ? t.tunnel_conns : '';
    html += `<div class="svc-tunnel-meta">
      <span class="svc-tunnel-host">${esc(t.hostname || '')}</span>
      ${conns !== '' ? `<span class="svc-tunnel-conns">${conns} conn${conns !== 1 ? 's' : ''}</span>` : ''}
    </div>`;
  }
  html += '</div>';
  return html;
}

function renderSyncPanel(sync) {
  if (!sync) return '';
  const folders = sync.folders || [];
  let html = '<div class="svc-panel">';

  // Header with conflict badge
  html += '<div class="svc-panel-hdr">SYNC';
  if (sync.conflicts > 0) {
    html += ` <span class="svc-badge conflict">${sync.conflicts} CONFLICT${sync.conflicts > 1 ? 'S' : ''}</span>`;
  }
  html += '</div>';

  // Connection status
  html += `<div class="svc-row ${sync.connected ? '' : 'svc-row-down'}">
    <span class="svc-dot ${sync.connected ? 'up' : 'down'}"></span>
    <span class="svc-name">Syncthing</span>
    <span class="svc-detail">${sync.connected ? 'LINKED' : 'OFFLINE'}</span>
  </div>`;

  // Folders
  for (const f of folders) {
    const inSync = f.need_files === 0;
    const pct = inSync ? 100 : (f.files > 0 ? Math.round((f.files - f.need_files) / f.files * 100) : 0);
    const fillCls = inSync ? 'complete' : 'syncing';

    html += `<div class="sync-folder">
      <div class="sync-top">
        <span class="svc-dot ${inSync ? 'idle' : 'syncing'}"></span>
        <span class="svc-name">${esc(f.id)}</span>
        ${f.conflicts > 0 ? `<span class="sync-folder-conflict">${f.conflicts}C</span>` : ''}
        <span class="svc-detail">${esc(f.state || '')}</span>
      </div>
      <div class="sync-bar"><div class="sync-fill ${fillCls}" style="width:${pct}%"></div></div>
      <div class="sync-meta">
        <span>${fmtK(f.files)} files &middot; ${f.size_gb.toFixed(1)}GB</span>
        <span>${f.need_files > 0 ? f.need_files + ' pending' : timeAgo(f.last_scan)}</span>
      </div>
    </div>`;
  }
  html += '</div>';
  return html;
}

function renderChezmoiSection(chez) {
  if (!chez || !chez.last_commit) return '';
  const mod = chez.modified || 0;
  const add = chez.added || 0;
  const isClean = mod === 0 && add === 0;

  let html = '<div class="svc-bottom-row">';
  html += '<div class="svc-panel-hdr">DOTFILES</div>';
  html += `<div class="svc-chezmoi">
    <span class="svc-dot ${isClean ? 'up' : 'degraded'}"></span>
    <span class="svc-name">chezmoi</span>
    ${mod > 0 ? `<span class="svc-chezmoi-stat modified">${mod}M</span>` : ''}
    ${add > 0 ? `<span class="svc-chezmoi-stat added">${add}A</span>` : ''}
    ${isClean ? '<span class="svc-chezmoi-stat clean">clean</span>' : ''}
  </div>`;
  html += `<div class="svc-chezmoi-commit">${esc(chez.last_commit)}</div>`;
  html += '</div>';
  return html;
}

function updateServicesPage(data) {
  const el = document.getElementById('svc-layout');
  if (!el || !data || !data.timestamp) return;

  let html = '';

  // Failed units banner -- top, full width, impossible to miss
  html += renderFailedBanner(data.failed_units);

  // Determine grid columns based on content
  const hasTunnels = data.tunnels && data.tunnels.length > 0;
  const colClass = hasTunnels ? 'cols-3' : 'cols-2';

  html += `<div class="svc-grid ${colClass}">`;

  // Column 1: Infrastructure + Docker stacked
  html += '<div style="display:flex;flex-direction:column;gap:4px;min-height:0;overflow:hidden">';
  html += renderInfraPanel(data.services);
  html += renderDockerPanel(data.docker);
  html += '</div>';

  // Column 2 (or 2+3): Tunnels + Sync
  if (hasTunnels) {
    html += renderTunnelPanel(data.tunnels);
    html += renderSyncPanel(data.sync);
  } else {
    html += renderSyncPanel(data.sync);
  }

  html += '</div>';

  // Chezmoi at bottom, full width
  html += renderChezmoiSection(data.chezmoi);

  el.innerHTML = html;
}
