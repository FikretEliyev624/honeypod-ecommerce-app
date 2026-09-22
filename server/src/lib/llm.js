// Calls a pre-trained model. NO MODEL IS EVER TRAINED HERE.
// The provider is selected with the `LLM_PROVIDER` env variable: ollama | groq | gemini.

const DEFAULTS = {
  ollama: 'llama3.1',
  groq: 'openai/gpt-oss-120b',
  gemini: 'gemini-2.0-flash',
};

// A local model can be slow to answer — generous timeout.
const TIMEOUT_MS = Number(process.env.LLM_TIMEOUT_MS) || 180_000;

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
    throw new Error(`LLM error ${response.status} ${response.statusText}: ${text.slice(0, 500)}`);
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
  switch (provider) {
    case 'ollama':
      return askOllama(prompt);
    case 'groq':
      return askGroq(prompt);
    case 'gemini':
      return askGemini(prompt);
    default:
      throw new Error(
        `Unknown LLM_PROVIDER: "${provider}". Allowed values: ollama, groq, gemini.`,
      );
  }
}

export default askLLM;
