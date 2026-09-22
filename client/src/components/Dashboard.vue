<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue';

const ATTACK_TYPES = [
  'sql_injection',
  'path_traversal',
  'xss',
  'command_injection',
  'scanner_bot',
  'brute_force',
  'sensitive_file_probe',
  'unknown',
];

const stats = ref(null);
const events = ref([]);
const eventsTotal = ref(0);
const reports = ref([]);

const filterType = ref('');
const filterSeverity = ref('');
const limit = ref(50);

const loading = ref(false);
const analyzing = ref(false);
const error = ref('');
const notice = ref('');
const expandedId = ref(null);
const autoRefresh = ref(true);
let timer = null;

const lastReport = computed(() => reports.value[0] || null);

// The model may return markdown despite being told not to — cleaned before display.
function cleanMarkdown(text) {
  return text
    .replace(/\*\*|__|`/g, '') // bold/code markers
    .replace(/^#{1,6}\s*/gm, '') // heading prefixes
    .replace(/^\s*[=-]{3,}\s*$/gm, '') // markdown underline rules
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

// Splits the "Recommendations:" part out of the summary so it can be shown as a list.
const reportParts = computed(() => {
  if (!lastReport.value) return { text: '', tips: [] };
  const raw = cleanMarkdown(lastReport.value.summary || '');
  const idx = raw.search(/recommendations/i);
  if (idx === -1) return { text: raw, tips: [] };

  const tips = raw
    .slice(idx)
    .replace(/^recommendations\s*:?/i, '') // drop the heading itself
    .split('\n')
    .map((line) => line.replace(/^\s*[-•*\d.)]+\s*/, '').trim())
    .filter(Boolean);

  return { text: raw.slice(0, idx).trim(), tips };
});

async function getJson(url, options) {
  const res = await fetch(url, options);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `${res.status} ${res.statusText}`);
  return data;
}

async function loadAll({ silent = false } = {}) {
  if (!silent) loading.value = true;
  try {
    const params = new URLSearchParams({ limit: String(limit.value) });
    if (filterType.value) params.set('attackType', filterType.value);
    if (filterSeverity.value) params.set('severity', filterSeverity.value);

    const [s, e, r] = await Promise.all([
      getJson('/api/stats'),
      getJson(`/api/events?${params.toString()}`),
      getJson('/api/reports?limit=10'),
    ]);
    stats.value = s;
    events.value = e.events;
    eventsTotal.value = e.total;
    reports.value = r.reports;
    error.value = '';
  } catch (err) {
    error.value = `Failed to load data: ${err.message}`;
  } finally {
    loading.value = false;
  }
}

// reanalyze=true → old events are re-classified with the current prompt as well.
async function analyze(reanalyze = false) {
  analyzing.value = true;
  error.value = '';
  notice.value = '';
  try {
    const data = await getJson('/api/analyze', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ reanalyze }),
    });
    const verb = reanalyze ? 're-classified' : 'classified';
    notice.value = data.fallback
      ? `Analysis finished, but the model response could not be parsed — ${data.report.eventCount} events marked unknown/low.`
      : `Analysis finished: ${data.report.eventCount} events ${verb} (${data.report.model}).`;
    await loadAll({ silent: true });
  } catch (err) {
    error.value = `Analysis failed: ${err.message}`;
  } finally {
    analyzing.value = false;
  }
}

function toggleRow(id) {
  expandedId.value = expandedId.value === id ? null : id;
}

function fmtTime(iso) {
  const d = new Date(iso);
  return d.toLocaleString('en-GB', {
    day: '2-digit',
    month: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function fmtJson(value) {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function severityClass(sev) {
  if (sev === 'high') return 'sev sev-high';
  if (sev === 'medium') return 'sev sev-med';
  if (sev === 'low') return 'sev sev-low';
  return 'sev sev-none';
}

function setupTimer() {
  clearInterval(timer);
  if (autoRefresh.value) {
    timer = setInterval(() => loadAll({ silent: true }), 10000);
  }
}

onMounted(() => {
  loadAll();
  setupTimer();
});

onUnmounted(() => clearInterval(timer));
</script>

<template>
  <div class="wrap">
    <header class="topbar">
      <div class="brand">
        <span class="dot" :class="{ live: autoRefresh }"></span>
        <div>
          <h1>HONEYPOD</h1>
          <p>Web honeypot · event console</p>
        </div>
      </div>

      <div class="actions">
        <label class="toggle">
          <input type="checkbox" v-model="autoRefresh" @change="setupTimer" />
          <span>Auto-refresh</span>
        </label>
        <button class="btn ghost" :disabled="loading" @click="loadAll()">
          {{ loading ? 'Loading…' : 'Refresh' }}
        </button>
        <button
          class="btn ghost"
          :disabled="analyzing"
          title="Re-classifies every event, including already analyzed ones, with the current model"
          @click="analyze(true)"
        >
          Re-analyze
        </button>
        <button class="btn primary" :disabled="analyzing" @click="analyze(false)">
          {{ analyzing ? 'Analyzing…' : 'Analyze' }}
        </button>
      </div>
    </header>

    <p v-if="error" class="banner err">{{ error }}</p>
    <p v-if="notice" class="banner ok">{{ notice }}</p>

    <!-- Stat cards -->
    <section class="cards">
      <div class="card">
        <span class="k">Total requests</span>
        <strong class="v">{{ stats?.totalEvents ?? '—' }}</strong>
        <span class="sub">last 24h: {{ stats?.last24hEvents ?? '—' }}</span>
      </div>
      <div class="card">
        <span class="k">Unique IPs</span>
        <strong class="v">{{ stats?.uniqueIps ?? '—' }}</strong>
        <span class="sub">distinct source addresses</span>
      </div>
      <div class="card">
        <span class="k">Top attack type</span>
        <strong class="v mono small">{{ stats?.topAttackType ?? '—' }}</strong>
        <span class="sub">per AI classification</span>
      </div>
      <div class="card" :class="{ warn: (stats?.unanalyzedEvents ?? 0) > 0 }">
        <span class="k">Pending analysis</span>
        <strong class="v">{{ stats?.unanalyzedEvents ?? '—' }}</strong>
        <span class="sub">analyzed: {{ stats?.analyzedEvents ?? '—' }}</span>
      </div>
    </section>

    <div class="grid">
      <!-- Latest report -->
      <section class="panel report">
        <div class="panel-head">
          <h2>Latest AI report</h2>
          <span v-if="lastReport" class="tag mono">{{ lastReport.model }}</span>
        </div>

        <div v-if="!lastReport" class="empty">
          No report yet. Once the honeypot receives requests, press “Analyze”.
        </div>

        <template v-else>
          <div class="report-meta mono">
            {{ fmtTime(lastReport.createdAt) }} · {{ lastReport.eventCount }} events
          </div>
          <p class="summary">{{ reportParts.text }}</p>
          <ul v-if="reportParts.tips.length" class="tips">
            <li v-for="(tip, i) in reportParts.tips" :key="i">{{ tip }}</li>
          </ul>
          <div class="chips">
            <span
              v-for="(b, i) in lastReport.breakdown"
              :key="i"
              class="chip"
              :class="severityClass(b.severity)"
            >
              {{ b.type }} · {{ b.count }}
            </span>
          </div>
        </template>
      </section>

      <!-- Top lists -->
      <section class="panel">
        <div class="panel-head"><h2>Most active sources</h2></div>
        <div class="list-head">IP address</div>
        <ul class="bars">
          <li v-for="row in stats?.topIps ?? []" :key="row.value">
            <span class="mono label">{{ row.value }}</span>
            <span class="bar">
              <i :style="{ width: `${(row.count / (stats.topIps[0]?.count || 1)) * 100}%` }"></i>
            </span>
            <span class="num">{{ row.count }}</span>
          </li>
        </ul>

        <div class="list-head">Most requested paths</div>
        <ul class="bars">
          <li v-for="row in stats?.topPaths ?? []" :key="row.value">
            <span class="mono label" :title="row.value">{{ row.value }}</span>
            <span class="bar">
              <i :style="{ width: `${(row.count / (stats.topPaths[0]?.count || 1)) * 100}%` }"></i>
            </span>
            <span class="num">{{ row.count }}</span>
          </li>
        </ul>
      </section>
    </div>

    <!-- Event table -->
    <section class="panel">
      <div class="panel-head">
        <h2>Events</h2>
        <div class="filters">
          <select v-model="filterType" @change="loadAll()">
            <option value="">all types</option>
            <option v-for="t in ATTACK_TYPES" :key="t" :value="t">{{ t }}</option>
          </select>
          <select v-model="filterSeverity" @change="loadAll()">
            <option value="">all severities</option>
            <option value="high">high</option>
            <option value="medium">medium</option>
            <option value="low">low</option>
          </select>
          <select v-model.number="limit" @change="loadAll()">
            <option :value="25">25</option>
            <option :value="50">50</option>
            <option :value="100">100</option>
            <option :value="200">200</option>
          </select>
          <span class="count mono">{{ events.length }} / {{ eventsTotal }}</span>
        </div>
      </div>

      <div class="table-scroll">
        <table>
          <thead>
            <tr>
              <th class="w-time">Time</th>
              <th class="w-ip">IP</th>
              <th class="w-method">Method</th>
              <th>Path</th>
              <th class="w-type">Attack type</th>
              <th class="w-sev">Severity</th>
            </tr>
          </thead>
          <tbody>
            <template v-for="ev in events" :key="ev.id">
              <tr class="row" :class="{ open: expandedId === ev.id }" @click="toggleRow(ev.id)">
                <td class="mono dim">{{ fmtTime(ev.createdAt) }}</td>
                <td class="mono">{{ ev.ip }}</td>
                <td class="mono method">{{ ev.method }}</td>
                <td class="mono path">
                  {{ ev.path }}<span v-if="ev.query" class="q">?{{ ev.query }}</span>
                </td>
                <td class="mono type">{{ ev.attackType || '—' }}</td>
                <td>
                  <span :class="severityClass(ev.severity)">{{ ev.severity || 'n/a' }}</span>
                </td>
              </tr>
              <tr v-if="expandedId === ev.id" class="detail">
                <td colspan="6">
                  <div class="detail-grid">
                    <div>
                      <span class="k">Trap (route)</span>
                      <code class="mono">{{ ev.route || '—' }}</code>
                    </div>
                    <div>
                      <span class="k">User-Agent</span>
                      <code class="mono">{{ ev.userAgent || '—' }}</code>
                    </div>
                    <div class="full">
                      <span class="k">Body</span>
                      <pre class="mono">{{ ev.body || '—' }}</pre>
                    </div>
                    <div class="full">
                      <span class="k">Headers</span>
                      <pre class="mono">{{ fmtJson(ev.headers) }}</pre>
                    </div>
                  </div>
                </td>
              </tr>
            </template>
            <tr v-if="!events.length">
              <td colspan="6" class="empty">
                No events yet. Send traffic to the honeypot: <code class="mono">npm run demo</code>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <footer class="foot">
      The honeypot runs only on your own server, for defensive/educational purposes. Nothing is
      executed and no real secrets are stored.
    </footer>
  </div>
</template>

<style scoped>
.wrap {
  max-width: 1400px;
  margin: 0 auto;
  padding: 24px 28px 60px;
}

/* ── Top bar ───────────────────────────────────────────── */
.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 20px;
  padding-bottom: 18px;
  border-bottom: 1px solid var(--line);
  margin-bottom: 22px;
}
.brand {
  display: flex;
  align-items: center;
  gap: 14px;
}
.brand h1 {
  margin: 0;
  font-size: 17px;
  letter-spacing: 0.18em;
  font-weight: 600;
}
.brand p {
  margin: 2px 0 0;
  font-size: 12px;
  color: var(--text-faint);
}
.dot {
  width: 9px;
  height: 9px;
  border-radius: 50%;
  background: var(--text-faint);
  box-shadow: 0 0 0 4px rgba(255, 255, 255, 0.03);
}
.dot.live {
  background: var(--teal);
  box-shadow: 0 0 0 4px rgba(63, 185, 163, 0.14);
  animation: pulse 2.4s ease-in-out infinite;
}
@keyframes pulse {
  50% {
    opacity: 0.45;
  }
}

.actions {
  display: flex;
  align-items: center;
  gap: 10px;
}
.toggle {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: var(--text-dim);
  cursor: pointer;
  user-select: none;
}
.toggle input {
  accent-color: var(--teal);
}

.btn {
  border: 1px solid var(--line);
  background: var(--ink-700);
  color: var(--text);
  font-family: inherit;
  font-size: 13px;
  padding: 8px 16px;
  border-radius: 6px;
  cursor: pointer;
  transition: background 0.15s, border-color 0.15s, opacity 0.15s;
}
.btn:hover:not(:disabled) {
  background: var(--ink-600);
  border-color: #2d3d55;
}
.btn:disabled {
  opacity: 0.55;
  cursor: not-allowed;
}
.btn.primary {
  background: var(--amber);
  border-color: var(--amber);
  color: #1a1204;
  font-weight: 600;
}
.btn.primary:hover:not(:disabled) {
  background: #ffbb3c;
  border-color: #ffbb3c;
}

/* ── Banner ────────────────────────────────────────────── */
.banner {
  margin: 0 0 16px;
  padding: 10px 14px;
  border-radius: 6px;
  font-size: 13px;
  border: 1px solid;
}
.banner.err {
  background: rgba(240, 85, 61, 0.09);
  border-color: var(--red-dim);
  color: #ff9d8b;
}
.banner.ok {
  background: rgba(63, 185, 163, 0.09);
  border-color: var(--teal-dim);
  color: #7fd8c6;
}

/* ── Cards ─────────────────────────────────────────────── */
.cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 14px;
  margin-bottom: 18px;
}
.card {
  background: var(--ink-800);
  border: 1px solid var(--line-soft);
  border-radius: 8px;
  padding: 16px 18px;
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.card.warn {
  border-color: var(--amber-dim);
}
.card .k {
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: var(--text-faint);
}
.card .v {
  font-size: 28px;
  font-weight: 600;
  line-height: 1;
}
.card .v.small {
  font-size: 16px;
  color: var(--amber);
}
.card .sub {
  font-size: 11px;
  color: var(--text-faint);
}

/* ── Grid / panels ─────────────────────────────────────── */
.grid {
  display: grid;
  grid-template-columns: 1.4fr 1fr;
  gap: 14px;
  margin-bottom: 18px;
}
@media (max-width: 980px) {
  .grid {
    grid-template-columns: 1fr;
  }
}

.panel {
  background: var(--ink-800);
  border: 1px solid var(--line-soft);
  border-radius: 8px;
  padding: 16px 18px 18px;
  margin-bottom: 18px;
}
.panel-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 14px;
  flex-wrap: wrap;
}
.panel-head h2 {
  margin: 0;
  font-size: 13px;
  text-transform: uppercase;
  letter-spacing: 0.12em;
  color: var(--text-dim);
  font-weight: 600;
}
.tag {
  font-size: 11px;
  color: var(--text-faint);
  border: 1px solid var(--line);
  padding: 3px 8px;
  border-radius: 4px;
}

.report-meta {
  font-size: 11px;
  color: var(--text-faint);
  margin-bottom: 10px;
}
.summary {
  margin: 0 0 12px;
  font-size: 14px;
  line-height: 1.65;
  color: var(--text);
  white-space: pre-line;
}
.tips {
  margin: 0 0 14px;
  padding-left: 0;
  list-style: none;
}
.tips li {
  position: relative;
  padding-left: 18px;
  font-size: 13px;
  line-height: 1.6;
  color: var(--text-dim);
  margin-bottom: 4px;
}
.tips li::before {
  content: '▸';
  position: absolute;
  left: 0;
  color: var(--amber);
}
.chips {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}
.chip {
  font-family: var(--mono);
  font-size: 11px;
  padding: 3px 8px;
  border-radius: 4px;
  border: 1px solid;
}

/* ── Bar lists ─────────────────────────────────────────── */
.list-head {
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: var(--text-faint);
  margin: 6px 0 8px;
}
.bars {
  list-style: none;
  margin: 0 0 14px;
  padding: 0;
}
.bars li {
  display: grid;
  grid-template-columns: minmax(0, 150px) 1fr 36px;
  align-items: center;
  gap: 10px;
  padding: 3px 0;
}
.bars .label {
  font-size: 12px;
  color: var(--text-dim);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.bars .bar {
  height: 6px;
  background: var(--ink-600);
  border-radius: 3px;
  overflow: hidden;
}
.bars .bar i {
  display: block;
  height: 100%;
  background: linear-gradient(90deg, var(--amber-dim), var(--amber));
}
.bars .num {
  font-family: var(--mono);
  font-size: 11px;
  color: var(--text-faint);
  text-align: right;
}

/* ── Table ─────────────────────────────────────────────── */
.filters {
  display: flex;
  align-items: center;
  gap: 8px;
}
.filters select {
  background: var(--ink-700);
  color: var(--text);
  border: 1px solid var(--line);
  border-radius: 5px;
  padding: 5px 8px;
  font-family: var(--mono);
  font-size: 11px;
}
.count {
  font-size: 11px;
  color: var(--text-faint);
}

.table-scroll {
  overflow-x: auto;
}
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12.5px;
}
thead th {
  text-align: left;
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: var(--text-faint);
  font-weight: 500;
  padding: 0 10px 8px;
  border-bottom: 1px solid var(--line);
  white-space: nowrap;
}
tbody td {
  padding: 8px 10px;
  border-bottom: 1px solid var(--line-soft);
  vertical-align: top;
}
.row {
  cursor: pointer;
}
.row:hover td {
  background: var(--ink-700);
}
.row.open td {
  background: var(--ink-700);
}
.dim {
  color: var(--text-faint);
}
.method {
  color: var(--text-dim);
}
.path {
  max-width: 460px;
  overflow-wrap: anywhere;
}
.path .q {
  color: var(--amber);
}
.type {
  color: var(--text-dim);
  font-size: 11.5px;
}
.w-time {
  width: 140px;
}
.w-ip {
  width: 130px;
}
.w-method {
  width: 70px;
}
.w-type {
  width: 160px;
}
.w-sev {
  width: 90px;
}

.detail td {
  background: var(--ink-900);
  padding: 14px 16px;
}
.detail-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px 20px;
}
.detail-grid .full {
  grid-column: 1 / -1;
}
.detail-grid .k {
  display: block;
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: var(--text-faint);
  margin-bottom: 4px;
}
.detail-grid code,
.detail-grid pre {
  font-size: 11.5px;
  color: var(--text-dim);
  background: var(--ink-800);
  border: 1px solid var(--line-soft);
  border-radius: 4px;
  padding: 8px 10px;
  display: block;
  margin: 0;
  max-height: 220px;
  overflow: auto;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

/* ── Severity badges ───────────────────────────────────── */
.sev {
  font-family: var(--mono);
  font-size: 10.5px;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  padding: 2px 7px;
  border-radius: 3px;
  border: 1px solid;
  display: inline-block;
}
.sev-high {
  color: #ff8f78;
  background: rgba(240, 85, 61, 0.12);
  border-color: var(--red-dim);
}
.sev-med {
  color: var(--amber);
  background: rgba(240, 169, 43, 0.1);
  border-color: var(--amber-dim);
}
.sev-low {
  color: #6fc9b8;
  background: rgba(63, 185, 163, 0.08);
  border-color: var(--teal-dim);
}
.sev-none {
  color: var(--text-faint);
  background: transparent;
  border-color: var(--line);
}

.empty {
  color: var(--text-faint);
  font-size: 13px;
  padding: 18px 4px;
  text-align: center;
}
.foot {
  text-align: center;
  font-size: 11px;
  color: var(--text-faint);
  margin-top: 26px;
}
.mono {
  font-family: var(--mono);
}
</style>
