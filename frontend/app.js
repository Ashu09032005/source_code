const projectNameEl = document.getElementById('projectName');
const criticalCountEl = document.getElementById('criticalCount');
const highCountEl = document.getElementById('highCount');
const totalCountEl = document.getElementById('totalCount');
const findingsListEl = document.getElementById('findingsList');
const reportPreviewEl = document.getElementById('reportPreview');
const statusBadgeEl = document.getElementById('statusBadge');
const demoBtn = document.getElementById('demoBtn');
const zipUpload = document.getElementById('zipUpload');
const downloadReportBtn = document.getElementById('downloadReportBtn');

defaultState();

async function requestProject(endpoint, options = {}) {
  setStatus('loading', 'Loading');
  try {
    const response = await fetch(endpoint, options);
    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Analysis failed.');
    }

    renderResults(data);
    setStatus('ready', 'Ready');
    return data;
  } catch (error) {
    findingsListEl.innerHTML = `<div class="empty-state">${error.message}</div>`;
    setStatus('idle', 'Idle');
    throw error;
  }
}

function setStatus(type, label) {
  statusBadgeEl.className = `status-badge ${type}`;
  statusBadgeEl.textContent = label;
}

function defaultState() {
  projectNameEl.textContent = 'Ready';
  criticalCountEl.textContent = '0';
  highCountEl.textContent = '0';
  totalCountEl.textContent = '0';
}

demoBtn.addEventListener('click', async () => {
  await requestProject('/api/demo');
});

zipUpload.addEventListener('change', async (event) => {
  const file = event.target.files[0];
  if (!file) return;

  const form = new FormData();
  form.append('project', file);

  await requestProject('/api/upload', {
    method: 'POST',
    body: form
  });
});

downloadReportBtn.addEventListener('click', async () => {
  try {
    const response = await fetch('/api/report');
    if (!response.ok) {
      throw new Error('No report available yet. Analyze a project first.');
    }

    const report = await response.json();
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${(report.projectName || 'security-report').replace(/\s+/g, '-').toLowerCase()}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  } catch (error) {
    findingsListEl.innerHTML = `<div class="empty-state">${error.message}</div>`;
  }
});

function renderReportPreview(data) {
  const summary = data.summary || { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const findings = data.findings || [];
  const firstFixes = findings.slice(0, 3).map(item => item.ai?.fixSuggestion || item.fix || 'No fix suggestion available.');

  reportPreviewEl.innerHTML = `
    <div class="section-head">
      <h2>AI Security Report</h2>
    </div>
    <div class="report-summary">
      <div class="report-item">
        <h4>Project</h4>
        <p>${escapeHtml(data.projectName || 'Analyzed project')}</p>
      </div>
      <div class="report-item">
        <h4>Total Findings</h4>
        <p>${summary.total || 0}</p>
      </div>
      <div class="report-item">
        <h4>Critical</h4>
        <p>${summary.critical || 0}</p>
      </div>
      <div class="report-item">
        <h4>High</h4>
        <p>${summary.high || 0}</p>
      </div>
    </div>
    <div class="report-item" style="margin-top: 12px;">
      <h4>Fix Preview</h4>
      <ul>
        ${firstFixes.map(fix => `<li>${escapeHtml(fix)}</li>`).join('') || '<li>No fix suggestions available.</li>'}
      </ul>
    </div>
  `;
}

function renderResults(data) {
  const summary = data.summary || { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };

  projectNameEl.textContent = data.projectName || 'Analyzed Project';
  criticalCountEl.textContent = summary.critical || 0;
  highCountEl.textContent = summary.high || 0;
  totalCountEl.textContent = summary.total || 0;
  renderReportPreview(data);

  const findings = data.findings || [];

  if (!findings.length) {
    findingsListEl.innerHTML = `<div class="empty-state">No vulnerability patterns were detected in this project.</div>`;
    return;
  }

  findingsListEl.innerHTML = findings.map((item) => {
    const ai = item.ai || {};
    const aiExplanation = ai.explanation || 'AI explanation not available.';
    const aiValidation = ai.validation || 'Validation not available.';
    const aiFix = ai.fixSuggestion || item.fix || 'No suggestion available.';

    return `
      <article class="finding-card">
        <div class="finding-head">
          <div class="finding-type">${item.type}</div>
          <span class="badge ${item.severity}">${item.severity}</span>
        </div>
        <div class="meta">
          <span>File: ${item.file}</span>
          <span>Line: ${item.line}</span>
          <span>Confidence: ${item.confidence}</span>
        </div>
        <p class="desc">${item.description}</p>
        <div class="code-block">${escapeHtml(item.snippet || 'No code snippet available')}</div>
        <div class="detail-grid">
          <div class="detail-box">
            <h4>Source</h4>
            <p>${item.source}</p>
          </div>
          <div class="detail-box">
            <h4>Sink</h4>
            <p>${item.sink}</p>
          </div>
          <div class="detail-box">
            <h4>Data Flow</h4>
            <p>${(item.dataFlow || []).join(' → ') || 'Not available'}</p>
          </div>
          <div class="detail-box">
            <h4>Impact</h4>
            <p>${item.impact}</p>
          </div>
          <div class="detail-box">
            <h4>AI Explanation</h4>
            <p>${escapeHtml(aiExplanation)}</p>
          </div>
          <div class="detail-box">
            <h4>AI Validation</h4>
            <p>${escapeHtml(aiValidation)}</p>
          </div>
          <div class="detail-box">
            <h4>AI Fix</h4>
            <p>${escapeHtml(aiFix)}</p>
          </div>
        </div>
      </article>
    `;
  }).join('');
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
