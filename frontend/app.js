let currentFilter = 'ALL';

document.addEventListener('DOMContentLoaded', () => {
  loadSummary();
  loadHistory();
  loadBlocklist();

  // Refresh summary button
  document.getElementById('refreshSummaryBtn').addEventListener('click', () => {
    loadSummary();
    loadHistory();
  });

  // URL Inspect form
  document.getElementById('urlInspectForm').addEventListener('submit', handleInspectUrl);

  // Tab switching
  document.querySelectorAll('.tab-chip').forEach(btn => {
    btn.addEventListener('click', (e) => {
      document.querySelectorAll('.tab-chip').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));

      e.target.classList.add('active');
      const tabId = e.target.getAttribute('data-tab');
      document.getElementById(tabId).classList.add('active');
    });
  });

  // History filter pills
  document.querySelectorAll('.f-pill').forEach(pill => {
    pill.addEventListener('click', (e) => {
      document.querySelectorAll('.f-pill').forEach(p => p.classList.remove('active'));
      e.target.classList.add('active');
      currentFilter = e.target.getAttribute('data-filter');
      loadHistory();
    });
  });

  // Add blocklist rule form
  document.getElementById('addRuleForm').addEventListener('submit', handleAddBlocklistRule);
});

async function loadSummary() {
  try {
    const res = await fetch('/api/v1/inspect/summary');
    if (!res.ok) return;
    const data = await res.json();
    document.getElementById('statTotalScans').textContent = data.total_scans;
    document.getElementById('statMalicious').textContent = data.malicious_count;
    document.getElementById('statSuspicious').textContent = data.suspicious_count;
    document.getElementById('statBenign').textContent = data.benign_count;
    document.getElementById('statAvgScore').textContent = data.average_threat_score.toFixed(1);
  } catch (err) {
    console.error('Failed to load summary:', err);
  }
}

async function handleInspectUrl(e) {
  e.preventDefault();
  const input = document.getElementById('targetUrlInput');
  const url = input.value.trim();
  if (!url) return;

  const btn = document.getElementById('inspectBtn');
  btn.disabled = true;
  btn.textContent = 'Inspecting...';

  try {
    const res = await fetch('/api/v1/inspect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    if (res.ok) {
      const data = await res.json();
      renderResult(data);
      loadSummary();
      loadHistory();
    }
  } catch (err) {
    console.error('Inspection failed:', err);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Run Inspection';
  }
}

function renderResult(data) {
  const section = document.getElementById('analysisResultSection');
  section.classList.remove('hidden');

  document.getElementById('resultScore').textContent = data.threat_score;
  const badge = document.getElementById('resultClassification');
  badge.textContent = data.classification;
  badge.className = `classification-badge class-${data.classification}`;

  const circle = document.getElementById('scoreCircle');
  if (data.classification === 'MALICIOUS') {
    circle.style.borderColor = 'var(--crit-color)';
  } else if (data.classification === 'SUSPICIOUS') {
    circle.style.borderColor = 'var(--high-color)';
  } else {
    circle.style.borderColor = 'var(--green-color)';
  }

  document.getElementById('resultHostname').textContent = data.hostname || data.url;
  document.getElementById('resultEntropy').textContent = data.domain_entropy.toFixed(2);
  document.getElementById('resultTLD').textContent = data.tld ? `.${data.tld}` : 'None';
  document.getElementById('resultLength').textContent = data.url_length;

  const homo = data.homoglyph_analysis;
  const homoEl = document.getElementById('resultHomoglyph');
  if (homo.is_spoofed) {
    homoEl.textContent = `DETECTED (${homo.confusables_found.length} glyphs)`;
    homoEl.style.color = 'var(--crit-color)';
  } else {
    homoEl.textContent = 'Clean / ASCII';
    homoEl.style.color = 'var(--green-color)';
  }

  const list = document.getElementById('riskFactorsList');
  if (!data.risk_factors || data.risk_factors.length === 0) {
    list.innerHTML = '<div class="empty-state">No risk factors triggered. URL appears standard and benign.</div>';
    return;
  }

  list.innerHTML = data.risk_factors.map(rf => `
    <div class="factor-item">
      <div class="factor-text">
        <span class="factor-rule">${escapeHtml(rf.rule)}</span>
        <span class="factor-desc">${escapeHtml(rf.description)}</span>
      </div>
      <span class="factor-weight">+${rf.weight}</span>
    </div>
  `).join('');
}

async function loadHistory() {
  try {
    let url = '/api/v1/inspect/history?limit=40';
    if (currentFilter !== 'ALL') {
      url += `&classification=${currentFilter}`;
    }

    const res = await fetch(url);
    if (!res.ok) return;
    const items = await res.json();
    const container = document.getElementById('historyContainer');

    if (!items || items.length === 0) {
      container.innerHTML = `<div class="empty-state">No scans recorded for filter [${currentFilter}].</div>`;
      return;
    }

    container.innerHTML = items.map(item => `
      <div class="history-item">
        <div class="hist-left">
          <span class="hist-url">${escapeHtml(item.url)}</span>
          <div class="hist-meta">
            <span>Host: <strong>${escapeHtml(item.hostname)}</strong></span>
            <span>Entropy: <strong>${item.domain_entropy.toFixed(2)}</strong></span>
            <span>Risk Flags: <strong>${item.risk_factor_count}</strong></span>
            <span>${new Date(item.created_at).toLocaleTimeString()}</span>
          </div>
        </div>
        <div class="hist-right">
          <span class="score-badge class-${item.classification}">${item.threat_score} • ${item.classification}</span>
        </div>
      </div>
    `).join('');
  } catch (err) {
    console.error('Failed to load history:', err);
  }
}

async function loadBlocklist() {
  try {
    const res = await fetch('/api/v1/blocklist');
    if (!res.ok) return;
    const rules = await res.json();
    const container = document.getElementById('blocklistContainer');

    if (!rules || rules.length === 0) {
      container.innerHTML = '<div class="empty-state">No blocklist rules configured.</div>';
      return;
    }

    container.innerHTML = rules.map(r => `
      <div class="rule-card" id="rule-${r.id}">
        <div>
          <span class="rule-pat">${escapeHtml(r.pattern)}</span>
          <div class="rule-reason">${escapeHtml(r.reason)}</div>
        </div>
        <button class="btn-del" onclick="deleteBlocklistRule('${r.id}')">Delete</button>
      </div>
    `).join('');
  } catch (err) {
    console.error('Failed to load blocklist:', err);
  }
}

function toggleAddBlocklistModal() {
  const box = document.getElementById('addRuleBox');
  box.classList.toggle('hidden');
}

async function handleAddBlocklistRule(e) {
  e.preventDefault();
  const pattern = document.getElementById('rulePattern').value.trim();
  const reason = document.getElementById('ruleReason').value.trim();
  if (!pattern || !reason) return;

  try {
    const res = await fetch('/api/v1/blocklist', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pattern, reason })
    });
    if (res.ok) {
      document.getElementById('addRuleForm').reset();
      toggleAddBlocklistModal();
      loadBlocklist();
      loadSummary();
    }
  } catch (err) {
    console.error('Failed to add rule:', err);
  }
}

async function deleteBlocklistRule(ruleId) {
  try {
    const res = await fetch(`/api/v1/blocklist/${ruleId}`, { method: 'DELETE' });
    if (res.ok) {
      loadBlocklist();
      loadSummary();
    }
  } catch (err) {
    console.error('Failed to delete rule:', err);
  }
}

function injectSample(type) {
  const samples = {
    paypal: 'http://paypal-security-update.xyz/login/verify.php?session=update',
    homoglyph: 'http://xn--pple-43d.com/authenticate/id-recovery',
    dga: 'http://x9q8m2z1k7v4w6p0.biz/auth/portal?token=9283401',
    ip: 'http://198.51.100.42/secure-account/signin?redirect=bank',
    benign: 'https://en.wikipedia.org/wiki/Computer_security'
  };

  const url = samples[type];
  if (url) {
    const input = document.getElementById('targetUrlInput');
    input.value = url;
    document.getElementById('urlInspectForm').dispatchEvent(new Event('submit'));
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
