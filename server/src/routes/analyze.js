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

// The honeypot already knows which trap a request hit, so a few categories are certain
// without asking the model. These are used when the model returns no verdict for an
// event, or answers "unknown" for a request that provably went after a trap.
const TRAP_CLASSIFICATION = {
  'sensitive-file-probe': { attackType: 'sensitive_file_probe', severity: 'medium' },
  'admin-lure': { attackType: 'scanner_bot', severity: 'low' },
};

function trapClassification(event) {
  // A POST to a login/admin lure carries credentials — a brute-force attempt.
  if ((event.route === 'login-lure' || event.route === 'admin-lure') && event.method === 'POST') {
    return { attackType: 'brute_force', severity: 'medium' };
  }
  return TRAP_CLASSIFICATION[event.route] || null;
}

// One LLM request per batch. A hosted free tier has a tight tokens-per-minute budget
// (Groq's free tier: 8000 TPM) and ~80 events in a single prompt already exceed it, so
// the batch is kept small and llm.js waits out the rate limit between batches.
const BATCH_SIZE = Number(process.env.ANALYZE_BATCH_SIZE) || 25;

// Upper bound for one /api/analyze call, so re-analysing a large database cannot run
// for an unbounded time. Whatever is left over is picked up by the next run.
const MAX_EVENTS = Number(process.env.ANALYZE_MAX_EVENTS) || 200;

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

// Maps the model's classification back onto the events. The model decides, but an event
// it skipped or called "unknown" still gets the category its trap proves, so a probe of
// /.env is never left without one. Everything else — unknown/low.
function mapClassifications(events, parsed) {
  const byIndex = new Map();
  for (const item of parsed || []) {
    const index = Number(item?.id) - 1;
    if (!Number.isInteger(index) || index < 0 || index >= events.length) continue;

    const attackType = String(item?.attackType || '').toLowerCase().trim();
    const severity = String(item?.severity || '').toLowerCase().trim();

    byIndex.set(index, {
      attackType: ATTACK_TYPES.includes(attackType) ? attackType : 'unknown',
      severity: SEVERITIES.includes(severity) ? severity : 'low',
    });
  }

  const result = events.map((event, index) => {
    const fromModel = byIndex.get(index);
    if (fromModel && fromModel.attackType !== 'unknown') return { id: event.id, ...fromModel };

    const fromTrap = trapClassification(event);
    if (fromTrap) return { id: event.id, ...fromTrap };

    return { id: event.id, ...(fromModel || { attackType: 'unknown', severity: 'low' }) };
  });

  return { result, fallback: byIndex.size === 0 };
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
    console.warn('[analyze] Could not parse the model response — this batch fell back to trap categories.');
  }
  await persistClassifications(classifications);
  return { classifications, fallback };
}

// POST /api/analyze
//   body.reanalyze=true  -> already analyzed events are re-classified with the current
//                          prompt as well.
//   default               -> only unanalyzed events.
// Either way at most MAX_EVENTS events (newest first) are handled per call, in batches
// of BATCH_SIZE. Whatever a batch classified is already saved, so a provider failure
// halfway through never throws away the work that succeeded.
router.post('/api/analyze', async (req, res, next) => {
  try {
    const reanalyze = req.body?.reanalyze === true;
    const where = reanalyze ? {} : { analyzed: false };

    const [allEvents, matchingTotal] = await Promise.all([
      prisma.honeypotEvent.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        take: MAX_EVENTS,
      }),
      prisma.honeypotEvent.count({ where }),
    ]);

    if (allEvents.length === 0) {
      res.status(400).json({
        error: reanalyze ? 'No events in the database.' : 'No new events to analyze.',
      });
      return;
    }

    const classifications = [];
    let fallback = false;
    let failure = null;

    for (let i = 0; i < allEvents.length; i += BATCH_SIZE) {
      const batch = allEvents.slice(i, i + BATCH_SIZE);
      try {
        const batchResult = await classifyBatch(batch);
        classifications.push(...batchResult.classifications);
        fallback = fallback || batchResult.fallback;
      } catch (err) {
        // Unreachable, misconfigured, or still rate limited after the retries in llm.js.
        // Stop here and keep the batches that did go through.
        console.error('[analyze] Classification failed:', err.message);
        failure = err;
        break;
      }
    }

    // Not a single batch got through — report the actual reason instead of a generic 500.
    // The message names the provider, never a credential.
    if (classifications.length === 0) {
      res.status(502).json({
        error: `LLM request failed (${llmLabel()}): ${trim(failure.message, 300)}`,
      });
      return;
    }

    // The report covers only the events that really were classified.
    const events = allEvents.slice(0, classifications.length);
    const pending = Math.max(matchingTotal - events.length, 0);

    const warnings = [];
    if (failure) {
      warnings.push(
        `Stopped after ${events.length} of ${allEvents.length} events: ${trim(failure.message, 200)}`,
      );
    }
    if (pending > 0) warnings.push(`${pending} event(s) left for the next run.`);

    // Breakdown + context
    const breakdown = buildBreakdown(classifications);
    const topIps = [...new Set(events.map((e) => e.ip))].slice(0, 5);
    const topPaths = [...new Set(events.map((e) => trim(e.path, 60)))].slice(0, 8);

    // Second LLM call for the summary. If classification already hit a wall there is no
    // point spending another rate-limited request — the breakdown is summarised locally.
    const localSummary = () =>
      `${events.length} events were classified: ` +
      breakdown.map((b) => `${b.type}/${b.severity}: ${b.count}`).join(', ') + '.';

    let summary;
    if (failure) {
      summary = localSummary();
    } else {
      try {
        summary = (
          await askLLM(buildSummaryPrompt(breakdown, events.length, topIps, topPaths))
        ).trim();
      } catch (err) {
        console.error('[analyze] Summary failed:', err.message);
        summary = `The summary model did not respond (${err.message}). ${localSummary()}`;
      }
    }

    // Anything the operator needs to know about this run goes on top of the summary.
    const notes = [];
    if (fallback) {
      notes.push(
        'Note: the model response could not be parsed; events fell back to the category ' +
          'their trap proves, or to unknown/low.',
      );
    }
    notes.push(...warnings);
    if (notes.length) {
      summary = `[${notes.join(' ')}]\n\n${summary}`;
    }

    // Store the report
    const report = await prisma.report.create({
      data: {
        model: llmLabel(),
        eventCount: events.length,
        summary,
        breakdown,
      },
    });

    res.json({
      report,
      fallback,
      analyzed: events.length,
      pending,
      warning: warnings.join(' ') || null,
    });
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

