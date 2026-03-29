// ========== PAGE 3: NATS ==========

// Track previous msg counts for rate calculation.
let _natsPrev = { in_msgs: 0, out_msgs: 0, ts: 0 };

function updateNATSPage(data) {
  const el = document.getElementById('nats-layout');
  if (!el || !data || !data.timestamp) return;

  const s = data.server || {};
  const conns = data.connections || [];
  const streams = data.streams || [];

  // Calculate message rates.
  const now = Date.now();
  let inRate = 0, outRate = 0;
  if (_natsPrev.ts > 0) {
    const dt = (now - _natsPrev.ts) / 1000;
    if (dt > 0 && dt < 30) {
      inRate = Math.max(0, ((s.in_msgs || 0) - _natsPrev.in_msgs) / dt);
      outRate = Math.max(0, ((s.out_msgs || 0) - _natsPrev.out_msgs) / dt);
    }
  }
  _natsPrev = { in_msgs: s.in_msgs || 0, out_msgs: s.out_msgs || 0, ts: now };

  // --- Top bar: server vitals ---
  const serverBar = `<div class="nats-topbar">
    <span class="nats-vital"><span class="nats-vl">NATS</span> <span class="nats-vv">${esc(s.version || '?')}</span></span>
    <span class="nats-vital"><span class="nats-vl">UP</span> <span class="nats-vv">${esc(s.uptime || '?')}</span></span>
    <span class="nats-vital"><span class="nats-vl">CONN</span> <span class="nats-vv">${s.connections || 0}<span class="nats-vdim">/${s.total_connections || 0}</span></span></span>
    <span class="nats-vital"><span class="nats-vl">SLOW</span> <span class="${s.slow_consumers > 0 ? 'nats-verr' : 'nats-vv'}">${s.slow_consumers || 0}</span></span>
    <span class="nats-vital"><span class="nats-vl">API</span> <span class="nats-vv">${fmtK(s.api_total || 0)}${s.api_errors > 0 ? ' <span class="nats-verr">' + s.api_errors + ' err</span>' : ''}</span></span>
    <span class="nats-vital"><span class="nats-vl">IN</span> <span class="nats-vv">${fB(s.in_bytes || 0)}</span></span>
    <span class="nats-vital"><span class="nats-vl">OUT</span> <span class="nats-vv">${fB(s.out_bytes || 0)}</span></span>
  </div>`;

  // --- Message flow gauges ---
  const maxRate = Math.max(inRate, outRate, 1);
  const inPct = Math.min(100, (inRate / maxRate) * 100);
  const outPct = Math.min(100, (outRate / maxRate) * 100);

  const flowBar = `<div class="nats-flow">
    <div class="nats-flow-row">
      <span class="nats-flow-label">IN</span>
      <div class="nats-flow-track"><div class="nats-flow-fill nats-flow-in" style="width:${inPct}%"></div></div>
      <span class="nats-flow-rate">${fmtK(Math.round(inRate))}/s</span>
      <span class="nats-flow-total">${fmtK(s.in_msgs || 0)}</span>
    </div>
    <div class="nats-flow-row">
      <span class="nats-flow-label">OUT</span>
      <div class="nats-flow-track"><div class="nats-flow-fill nats-flow-out" style="width:${outPct}%"></div></div>
      <span class="nats-flow-rate">${fmtK(Math.round(outRate))}/s</span>
      <span class="nats-flow-total">${fmtK(s.out_msgs || 0)}</span>
    </div>
  </div>`;

  // --- Streams with inline consumers ---
  let streamsHtml = '<div class="nats-streams"><div class="nats-section-hdr">STREAMS</div>';
  if (streams.length === 0) {
    streamsHtml += '<div class="nats-empty">no streams</div>';
  } else {
    for (const st of streams) {
      const consumers = st.consumers || [];
      streamsHtml += `<div class="nats-stream-block">
        <div class="nats-stream-head">
          <span class="nats-stream-name">${esc(st.name)}</span>
          <span class="nats-stream-meta">${fmtK(st.messages || 0)} msgs</span>
          <span class="nats-stream-meta">${fB(st.bytes || 0)}</span>
          <span class="nats-stream-meta">${consumers.length} consumers</span>
        </div>
        ${st.first_seq !== undefined ? `<div class="nats-stream-seq">seq ${st.first_seq.toLocaleString()} &rarr; ${st.last_seq.toLocaleString()}</div>` : ''}
        <div class="nats-consumers-grid">`;

      if (consumers.length === 0) {
        streamsHtml += '<div class="nats-empty">no consumers</div>';
      } else {
        for (const c of consumers) {
          const pending = c.num_pending !== undefined ? c.num_pending : (c.ack_pending || 0);
          const delivered = c.delivered || c.num_delivered || 0;
          const level = pending === 0 ? 'ok' : pending <= 100 ? 'warn' : 'crit';
          const pendingLabel = pending === 0 ? 'CLEAR' : pending.toLocaleString() + ' pending';

          streamsHtml += `<div class="nats-consumer-card nats-c-${level}">
            <div class="nats-consumer-top">
              <span class="nats-consumer-name">${esc(c.name || c.consumer_name || '?')}</span>
              <span class="nats-consumer-badge nats-cb-${level}">${pendingLabel}</span>
            </div>
            <div class="nats-consumer-stats">
              <span class="nats-cs-label">delivered</span>
              <span class="nats-cs-val">${fmtK(delivered)}</span>
              ${c.ack_pending !== undefined ? `<span class="nats-cs-label">ack pend</span><span class="nats-cs-val">${c.ack_pending}</span>` : ''}
            </div>
            <div class="nats-consumer-indicator nats-ci-${level}"></div>
          </div>`;
        }
      }
      streamsHtml += '</div></div>';
    }
  }
  streamsHtml += '</div>';

  // --- Connections ---
  let connsHtml = '<div class="nats-connections"><div class="nats-section-hdr">CONNECTIONS</div>';
  if (conns.length === 0) {
    connsHtml += '<div class="nats-empty">no connections</div>';
  } else {
    for (const c of conns) {
      const rawName = c.name || c.client_id || 'unknown';
      const displayName = rawName.replace(/^claude-peers-/, '');
      const ip = (c.ip || '').replace(/^::ffff:/, '');
      const lang = c.lang || '?';
      connsHtml += `<div class="nats-conn-row">
        <div class="nats-conn-dot"></div>
        <span class="nats-conn-name">${esc(displayName)}</span>
        <span class="nats-conn-lang">${esc(lang)}</span>
        <span class="nats-conn-ip">${esc(ip)}</span>
        <span class="nats-conn-io"><span class="nats-conn-in">&darr;${fmtK(c.in_msgs || 0)}</span> <span class="nats-conn-out">&uarr;${fmtK(c.out_msgs || 0)}</span></span>
      </div>`;
    }
  }
  connsHtml += '</div>';

  // --- Assemble layout ---
  el.innerHTML = serverBar + flowBar + `<div class="nats-body">${streamsHtml}${connsHtml}</div>`;
}
