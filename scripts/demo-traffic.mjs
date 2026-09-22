// Demo traffic — sends sample attack requests to the honeypot (YOUR OWN server only).
// Usage:  npm run demo
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.resolve(__dirname, '../.env') });

const PORT = Number(process.env.HONEYPOT_PORT) || 8080;
const BASE = `http://localhost:${PORT}`;

const UA = {
  sqlmap: 'sqlmap/1.7.2#stable (http://sqlmap.org)',
  nikto: 'Mozilla/5.00 (Nikto/2.1.6)',
  curl: 'curl/8.4.0',
  bot: 'Mozilla/5.0 (compatible; Zgrab/0.x)',
  browser:
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36',
};

const requests = [
  // Normal shopping traffic (background noise)
  { m: 'GET', p: '/', ua: UA.browser },
  { m: 'GET', p: '/shop', ua: UA.browser },
  { m: 'GET', p: '/product/2', ua: UA.browser },
  { m: 'GET', p: '/cart', ua: UA.browser },

  // SQL injection — via product id and search
  { m: 'GET', p: "/product/1' OR '1'='1", ua: UA.sqlmap },
  { m: 'GET', p: '/search?q=1 UNION SELECT card_number,cvv FROM payments--', ua: UA.sqlmap },
  { m: 'POST', p: '/account/login', ua: UA.sqlmap, body: "email=admin'--&password=x" },

  // Fake payment form — the (made-up) card data an attacker submits
  { m: 'POST', p: '/checkout', ua: UA.curl,
    body: 'card_name=John Doe&card_number=4242424242424242&card_expiry=12/34&card_cvv=123&email=a@b.co' },
  { m: 'POST', p: '/checkout', ua: UA.curl,
    body: 'card_name=Test&card_number=4000000000000002&card_expiry=01/30&card_cvv=999&email=x@y.co' },
  { m: 'POST', p: '/api/pay', ua: UA.curl, json: true,
    body: '{"card_number":"5555555555554444","cvv":"321","amount":9999}' },
  // SQL injection attempt in a payment field
  { m: 'POST', p: '/checkout', ua: UA.sqlmap,
    body: "card_number=1' OR '1'='1&card_cvv=1&card_expiry=1&card_name=x&email=x" },

  // Path traversal
  { m: 'GET', p: '/download?file=../../../../etc/passwd', ua: UA.curl },
  { m: 'GET', p: '/static/..%2f..%2f..%2fwindows/win.ini', ua: UA.curl },

  // XSS
  { m: 'GET', p: '/search?q=<script>alert(document.cookie)</script>', ua: UA.browser },
  { m: 'POST', p: '/comment', ua: UA.browser, body: 'text=<img src=x onerror=alert(1)>' },

  // Command injection
  { m: 'GET', p: '/ping?host=127.0.0.1;cat /etc/shadow', ua: UA.curl },
  { m: 'POST', p: '/api/exec', ua: UA.curl, body: '{"cmd":"| whoami"}', json: true },

  // Sensitive file probe
  { m: 'GET', p: '/.env', ua: UA.bot },
  { m: 'GET', p: '/.git/config', ua: UA.bot },
  { m: 'GET', p: '/config.php', ua: UA.bot },

  // Skaner / bot
  { m: 'GET', p: '/phpmyadmin', ua: UA.nikto },
  { m: 'GET', p: '/wp-login.php', ua: UA.nikto },
  { m: 'GET', p: '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php', ua: UA.nikto },

  // Brute force (repeated login attempts against the admin panel)
  ...['admin:admin', 'admin:123456', 'admin:password', 'root:toor', 'admin:qwerty'].map((pair) => {
    const [u, pw] = pair.split(':');
    return { m: 'POST', p: '/admin', ua: UA.curl, body: `username=${u}&password=${pw}` };
  }),
];

async function send({ m, p, ua, body, json }) {
  const url = `${BASE}${p}`;
  const headers = { 'user-agent': ua };
  if (body) {
    headers['content-type'] = json ? 'application/json' : 'application/x-www-form-urlencoded';
  }
  try {
    const res = await fetch(url, { method: m, headers, body });
    console.log(`${String(res.status).padEnd(4)} ${m.padEnd(5)} ${p}`);
  } catch (err) {
    console.error(`ERR  ${m.padEnd(5)} ${p} → ${err.message}`);
  }
}

console.log(`Sending demo traffic to the honeypot: ${BASE}\n`);
for (const req of requests) {
  await send(req);
}
console.log(
  `\n${requests.length} requests sent.\n` +
    'Database writes happen in the background — wait until "Pending analysis" on the ' +
    `dashboard reads ${requests.length}, then press "Analyze".`,
);
