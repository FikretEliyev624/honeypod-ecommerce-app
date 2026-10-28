// Calls a pre-trained model. NO MODEL IS EVER TRAINED HERE.
// The provider is selected with the `LLM_PROVIDER` env variable: ollama | groq | gemini.

const DEFAULTS = {
  ollama: 'llama3.1',
  groq: 'openai/gpt-oss-120b',
  gemini: 'gemini-2.0-flash',
};

// A local model can be slow to answer — generous timeout.
const TIMEOUT_MS = Number(process.env.LLM_TIMEOUT_MS) || 180_000;

// Hosted providers enforce a rate limit (Groq's free tier allows only 8000 tokens per
// minute). That answer is not a real failure — it only asks us to wait, so a limited
// number of retries is made, using the delay the provider itself reports.
const MAX_RETRIES = Number(process.env.LLM_MAX_RETRIES) || 3;
const MAX_RETRY_WAIT_MS = Number(process.env.LLM_MAX_RETRY_WAIT_MS) || 70_000;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export function llmProvider() {
  return (process.env.LLM_PROVIDER || 'ollama').toLowerCase().trim();
}

export function llmModelName() {
  const provider = llmProvider();
  if (provider === 'groq') return process.env.GROQ_MODEL || DEFAULTS.groq;
  if (provider === 'gemini') return process.env.GEMINI_MODEL || DEFAULTS.gemini;
  return process.env.OLLAMA_MODEL || DEFAULTS.ollama;
}

// Label stored on the report, e.g. "ollama/llama3.1".
export function llmLabel() {
  return `${llmProvider()}/${llmModelName()}`;
}

// Providers wrap the real reason in {"error":{"message":"…"}} — show only that part.
function providerMessage(text) {
  try {
    const parsed = JSON.parse(text);
    const message = parsed?.error?.message ?? parsed?.error ?? parsed?.message;
    if (typeof message === 'string' && message.trim()) return message.trim().slice(0, 400);
  } catch {
    // not JSON — fall through to the raw body
  }
  return text.slice(0, 400);
}

// How long to wait before retrying: the Retry-After header, or the delay named in the
// rate-limit message ("Please try again in 50.67s").
function retryAfterMs(response, text) {
  const header = response.headers.get('retry-after');
  const seconds = Number(header);
  if (header && Number.isFinite(seconds)) return seconds * 1000;

  const match = text.match(/try again in ([\d.]+)\s*(ms|s)\b/i);
  if (match) {
    const value = Number(match[1]);
    if (Number.isFinite(value)) return match[2].toLowerCase() === 'ms' ? value : value * 1000;
  }
  return null;
}

async function postJson(url, { headers = {}, body }) {
  let response;
  try {
    response = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...headers },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (err) {
    if (err.name === 'TimeoutError') {
      throw new Error(`The LLM did not respond (${TIMEOUT_MS} ms timeout): ${url}`);
    }
    throw new Error(`Could not connect to the LLM (${url}): ${err.message}`);
  }

  const text = await response.text();
  if (!response.ok) {
    const error = new Error(
      `LLM error ${response.status} ${response.statusText}: ${providerMessage(text)}`,
    );
    error.status = response.status;
    error.retryAfterMs = retryAfterMs(response, text);
    throw error;
  }

  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`LLM response is not JSON: ${text.slice(0, 500)}`);
  }
}

async function askOllama(prompt) {
  const base = (process.env.OLLAMA_URL || 'http://localhost:11434').replace(/\/+$/, '');
  const data = await postJson(`${base}/api/generate`, {
    body: {
      model: llmModelName(),
      prompt,
      stream: false,
      options: { temperature: 0.2 },
    },
  });
  const out = data?.response;
  if (typeof out !== 'string') {
    throw new Error(`Ollama returned an unexpected response: ${JSON.stringify(data).slice(0, 300)}`);
  }
  return out;
}

async function askGroq(prompt) {
  const key = process.env.GROQ_API_KEY;
  if (!key) throw new Error('GROQ_API_KEY is not set (env variable or .env file).');

  const data = await postJson('https://api.groq.com/openai/v1/chat/completions', {
    headers: { authorization: `Bearer ${key}` },
    body: {
      model: llmModelName(),
      temperature: 0.2,
      messages: [{ role: 'user', content: prompt }],
    },
  });
  const out = data?.choices?.[0]?.message?.content;
  if (typeof out !== 'string') {
    throw new Error(`Groq returned an unexpected response: ${JSON.stringify(data).slice(0, 300)}`);
  }
  return out;
}

async function askGemini(prompt) {
  const key = process.env.GEMINI_API_KEY;
  if (!key) throw new Error('GEMINI_API_KEY is not set (env variable or .env file).');

  const url =
    `https://generativelanguage.googleapis.com/v1beta/models/${llmModelName()}:generateContent` +
    `?key=${encodeURIComponent(key)}`;

  const data = await postJson(url, {
    body: {
      contents: [{ role: 'user', parts: [{ text: prompt }] }],
      generationConfig: { temperature: 0.2 },
    },
  });
  const out = data?.candidates?.[0]?.content?.parts?.map((p) => p.text).join('');
  if (typeof out !== 'string' || !out) {
    throw new Error(`Gemini returned an unexpected response: ${JSON.stringify(data).slice(0, 300)}`);
  }
  return out;
}

/**
 * Sends a prompt to the model and returns its text answer.
 * @param {string} prompt
 * @returns {Promise<string>}
 */
export async function askLLM(prompt) {
  const provider = llmProvider();
  let ask;
  switch (provider) {
    case 'ollama':
      ask = askOllama;
      break;
    case 'groq':
      ask = askGroq;
      break;
    case 'gemini':
      ask = askGemini;
      break;
    default:
      throw new Error(
        `Unknown LLM_PROVIDER: "${provider}". Allowed values: ollama, groq, gemini.`,
      );
  }

  for (let attempt = 0; ; attempt += 1) {
    try {
      return await ask(prompt);
    } catch (err) {
      // 429 = rate limited, 5xx = a hiccup on the provider's side. Anything else
      // (bad key, unknown model, bad request) will not get better by waiting.
      const retriable = err.status === 429 || (err.status >= 500 && err.status <= 599);
      if (!retriable || attempt >= MAX_RETRIES) throw err;

      // +500 ms so we do not knock the very millisecond the window resets.
      const wait = Math.min(err.retryAfterMs ?? 2000 * 2 ** attempt, MAX_RETRY_WAIT_MS) + 500;
      console.warn(
        `[llm] ${err.status} from ${llmLabel()} — retrying in ${Math.round(wait / 1000)}s ` +
          `(attempt ${attempt + 1}/${MAX_RETRIES}).`,
      );
      await sleep(wait);
    }
  }
}

export default askLLM;
