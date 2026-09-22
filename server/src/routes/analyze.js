// AI analysis — uses a pre-trained model, NOTHING IS EVER TRAINED.
import express from 'express';
import { prisma } from '../prisma.js';
import { askLLM, llmLabel } from '../lib/llm.js';

const router = express.Router();

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

const SEVERITIES = ['low', 'medium', 'high'];

const MAX_EVENTS = 80;

function trim(value, max) {
  if (!value) return '';
  const str = String(value).replace(/\s+/g, ' ').trim();
  return str.length > max ? `${str.slice(0, max)}…` : str;
}

// Turns the events into a short, one-per-line list for the model.
// Numbers 1..N are used instead of real uuids (saves tokens + easier to parse).
function formatEvents(events) {
  return events
    .map((e, i) => {
      const parts = [
        `${i + 1}.`,
        `${e.method} ${trim(e.path, 200)}`,
        e.query ? `query="${trim(e.query, 200)}"` : '',
        `ip=${e.ip}`,
        `ua="${trim(e.userAgent, 120) || '-'}"`,
        e.route ? `trap=${e.route}` : '',
        e.body ? `body="${trim(e.body, 300)}"` : '',
      ];
      return parts.filter(Boolean).join(' | ');
    })
    .join('\n');
}

function buildClassifyPrompt(events) {
  return `You are a security analyst reviewing HTTP requests captured by a web honeypot.
Classify EVERY request below into exactly ONE attackType.

attackType definitions and telltale signs — match on the PAYLOAD, not the URL path:
- sql_injection: SQL syntax in input. Signs: ' OR '1'='1, UNION SELECT, --, /*, ; DROP,
  SLEEP(, information_schema, ' or 1=1. Only if SQL keywords/quotes are present.
- command_injection: OS/shell command execution. Signs: ; | & || \`\` $(...), \${IFS},
  cat /etc/passwd, /etc/shadow, whoami, ping, nc, curl|bash, wget. Shell metacharacters
  or unix commands = command_injection, NOT sql_injection.
- path_traversal: escaping directories to read files. Signs: ../, ..\\, %2e%2e%2f,
  ....//, /etc/passwd or win.ini reached via ../ sequences (no shell command).
- xss: HTML/JS injection. Signs: <script>, onerror=, onload=, javascript:, <img src=x,
  alert(, document.cookie.
- scanner_bot: automated scanning of well-known paths with no injection payload.
  Signs: scanner User-Agents (sqlmap, nikto, nmap, zgrab, masscan), probing /wp-login.php,
  /phpmyadmin, /vendor/..., /wp-admin, or many random 404 paths.
- brute_force: repeated login/credential attempts. Signs: POST to login/admin with
  username/password or email/password fields, common passwords (admin, 123456, password).
- sensitive_file_probe: requesting secret/config files directly (no shell, no ../).
  Signs: /.env, /config.php, /.git/config, /.aws/credentials, backup files (.bak, .sql).
- unknown: normal traffic or anything that fits none of the above (e.g. GET / , /shop,
  /product/2, viewing pages with no attack payload).

Decision rule: if multiple could apply, pick the payload's PRIMARY technique.
Shell metacharacters (\${IFS}, ;, |, \`) always mean command_injection, never sql_injection.

Allowed attackType values (use these exact strings): ${ATTACK_TYPES.join(', ')}
Allowed severity values: low, medium, high
Severity guide: high = working exploit attempt (sqli/rce/traversal/xss payload);
medium = credential brute force or targeted probing; low = generic scanning or normal traffic.

Requests:
${formatEvents(events)}

Answer with JSON ONLY — no markdown, no explanation, no code fences.
Return a JSON array with one object per request, using the request number as "id":
[{"id":1,"attackType":"sql_injection","severity":"high"}]
The array must contain exactly ${events.length} objects.`;
}

function buildSummaryPrompt(breakdown, eventCount, topIps, topPaths) {
  const lines = breakdown
    .map((b) => `- ${b.type} / ${b.severity}: ${b.count}`)
    .join('\n');
  return `You are a cybersecurity analyst. Below is the classification of ${eventCount} requests captured by a web honeypot.

Classification (type / severity: count):
${lines}

Most active IPs: ${topIps.join(', ') || 'none'}
Most requested paths: ${topPaths.join(', ') || 'none'}

Answer in ENGLISH:
1) A short 3-5 sentence summary — what happened, which attack types dominate, the overall threat level.
2) Then, under a "Recommendations:" heading, exactly 3 practical defensive recommendations (one per line, each starting with "- ").

Return plain text only: no markdown headings (#), no bold markers (**), no code blocks and no tables.
Do not repeat the classification list verbatim — interpret it.`;
}

// Strips ```json fences and any extra prose from the model response.
function extractJsonArray(raw) {
  if (typeof raw !== 'string') return null;
  let text = raw.trim();

  // remove the ```json ... ``` fence
  const fence = text.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence) text = fence[1].trim();

  const start = text.indexOf('[');
  const end = text.lastIndexOf(']');
  if (start === -1 || end === -1 || end < start) return null;

  try {
    const parsed = JSON.parse(text.slice(start, end + 1));
    return Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

// Maps the model's classification back onto the events.
// If parsing fails or a value is outside the allowed list — unknown/low fallback.
function mapClassifications(events, parsed) {
  const result = events.map((e) => ({ id: e.id, attackType: 'unknown', severity: 'low' }));
  if (!parsed) return { result, fallback: true };

  let matched = 0;
  for (const item of parsed) {
    const index = Number(item?.id) - 1;
    if (!Number.isInteger(index) || index < 0 || index >= events.length) continue;

    const attackType = String(item?.attackType || '').toLowerCase().trim();
    const severity = String(item?.severity || '').toLowerCase().trim();

    result[index].attackType = ATTACK_TYPES.includes(attackType) ? attackType : 'unknown';
    result[index].severity = SEVERITIES.includes(severity) ? severity : 'low';
    matched += 1;
  }

  return { result, fallback: matched === 0 };
}

// [{type, severity, count}] breakdown
function buildBreakdown(classifications) {
  const map = new Map();
  for (const c of classifications) {
    const key = `${c.attackType}|${c.severity}`;
    map.set(key, (map.get(key) || 0) + 1);
  }
  return [...map.entries()]
    .map(([key, count]) => {
      const [type, severity] = key.split('|');
      return { type, severity, count };
    })
    .sort((a, b) => b.count - a.count);
}

// Events sharing the same (attackType, severity) pair are updated in one updateMany.
async function persistClassifications(classifications) {
  const groups = new Map();
  for (const c of classifications) {
    const key = `${c.attackType}|${c.severity}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(c.id);
  }

  const updates = [...groups.entries()].map(([key, ids]) => {
    const [attackType, severity] = key.split('|');
    return prisma.honeypotEvent.updateMany({
      where: { id: { in: ids } },
      data: { attackType, severity, analyzed: true },
    });
  });

  await prisma.$transaction(updates);
}

// Classifies one batch of events and updates them in the database.
async function classifyBatch(events) {
  const rawClassification = await askLLM(buildClassifyPrompt(events));
  const parsed = extractJsonArray(rawClassification);
  const { result: classifications, fallback } = mapClassifications(events, parsed);

  if (fallback) {
    console.warn('[analyze] Could not parse the model response — this batch was marked unknown/low.');
  }
  await persistClassifications(classifications);
  return { classifications, fallback };
}

// POST /api/analyze
//   body.reanalyze=true  → old (already analyzed) events are re-classified with the
//                          current prompt too (all of them, batch by batch).
//   default               → only unanalyzed events (the newest ${MAX_EVENTS}).
router.post('/api/analyze', async (req, res, next) => {
  try {
    const reanalyze = req.body?.reanalyze === true;

    // A re-analysis takes every event, otherwise only the new ones.
    const allEvents = await prisma.honeypotEvent.findMany({
      where: reanalyze ? {} : { analyzed: false },
      orderBy: { createdAt: 'desc' },
      // Re-analysis takes all of them, normal mode takes a single batch.
      take: reanalyze ? undefined : MAX_EVENTS,
    });

    if (allEvents.length === 0) {
      res.status(400).json({
        error: reanalyze ? 'No events in the database.' : 'No new events to analyze.',
      });
      return;
    }

    // Split the events into batches of ${MAX_EVENTS} (to fit the LLM context).
    const classifications = [];
    let fallback = false;
    for (let i = 0; i < allEvents.length; i += MAX_EVENTS) {
      const batch = allEvents.slice(i, i + MAX_EVENTS);
      const res2 = await classifyBatch(batch);
      classifications.push(...res2.classifications);
      fallback = fallback || res2.fallback;
    }

    const events = allEvents; // used as context below

    // Breakdown + context
    const breakdown = buildBreakdown(classifications);
    const topIps = [...new Set(events.map((e) => e.ip))].slice(0, 5);
    const topPaths = [...new Set(events.map((e) => trim(e.path, 60)))].slice(0, 8);

    // 4) Second LLM call for the summary — the report is created even if it fails.
    let summary;
    try {
      summary = (await askLLM(buildSummaryPrompt(breakdown, events.length, topIps, topPaths))).trim();
    } catch (err) {
      console.error('[analyze] Summary failed:', err.message);
      summary =
        `The summary model did not respond (${err.message}). ` +
        `${events.length} events were classified: ` +
        breakdown.map((b) => `${b.type}/${b.severity}: ${b.count}`).join(', ') + '.';
    }

    if (fallback) {
      summary = `[Note: the model response could not be parsed, events were marked unknown/low.]\n\n${summary}`;
    }

    // 5) Store the report
    const report = await prisma.report.create({
      data: {
        model: llmLabel(),
        eventCount: events.length,
        summary,
        breakdown,
      },
    });

    res.json({ report, fallback });
  } catch (err) {
    next(err);
  }
});

export default router;

// Helpers exported for tests/debugging.
export {
  extractJsonArray,
  mapClassifications,
  buildBreakdown,
  buildClassifyPrompt,
  ATTACK_TYPES,
  SEVERITIES,
};

