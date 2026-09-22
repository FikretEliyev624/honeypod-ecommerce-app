// THE FAKE SITE — the internet-facing honeypot (disguised as an e-commerce store).
// This router contains ONLY lure pages and logging.
// There is NO admin/dashboard endpoint, NO execution (exec/eval), NO real secret
// and NO real payment processing. All card/product data is made up.
import express from 'express';
import { prisma } from '../prisma.js';
import {
  homePage,
  shopPage,
  searchPage,
  productPage,
  cartPage,
  checkoutPage,
  paymentDeclinedPage,
  accountLoginPage,
  notFoundPage,
} from '../lib/storefront.js';

const router = express.Router();

// Every body (JSON, form, XML, plain text) is taken as a plain STRING —
// nothing is parsed or executed, it is only stored.
router.use(express.text({ type: () => true, limit: '512kb' }));

// Admin/management lures — scanner targets that look like the store's "back door".
const ADMIN_LURES = [
  '/admin',
  '/administrator',
  '/wp-login.php',
  '/wp-admin',
  '/phpmyadmin',
  '/.env.bak',
];

// Payment endpoints — the (fake) card data an attacker submits lands here.
const PAYMENT_PATHS = ['/checkout', '/pay', '/api/pay', '/api/checkout', '/payment'];

// Fake "sensitive file" responses — the content is completely WORTHLESS and made up.
const SENSITIVE_FILES = {
  '/.env': {
    type: 'text/plain',
    body: [
      'APP_NAME=NovaShop',
      'APP_ENV=production',
      'APP_DEBUG=false',
      'DB_HOST=127.0.0.1',
      'DB_DATABASE=novashop',
      'DB_USERNAME=shop_ro',
      'DB_PASSWORD=CHANGEME_placeholder_not_a_real_secret',
      'STRIPE_KEY=sk_test_00000000000000000000_placeholder',
      '',
    ].join('\n'),
  },
  '/config.php': {
    type: 'text/plain',
    body: [
      '<?php',
      '// legacy config — do not edit',
      "$db_host = '127.0.0.1';",
      "$db_user = 'shop_ro';",
      "$db_pass = 'CHANGEME_placeholder_not_a_real_secret';",
      "$db_name = 'novashop';",
      '',
    ].join('\n'),
  },
  '/.git/config': {
    type: 'text/plain',
    body: [
      '[core]',
      '\trepositoryformatversion = 0',
      '\tfilemode = false',
      '\tbare = false',
      '[remote "origin"]',
      '\turl = https://example.invalid/novashop/store.git',
      '\tfetch = +refs/heads/*:refs/remotes/origin/*',
      '',
    ].join('\n'),
  },
};

const ACCOUNT_LOGIN_PATHS = ['/account/login', '/login', '/account/register'];

function normalizePath(rawPath) {
  const lower = rawPath.toLowerCase();
  if (lower.length > 1 && lower.endsWith('/')) return lower.slice(0, -1);
  return lower;
}

// Determines which lure was triggered.
function detectRoute(req) {
  const p = normalizePath(req.path);
  const method = req.method;

  if (SENSITIVE_FILES[p]) return 'sensitive-file-probe';
  if (ADMIN_LURES.includes(p)) return 'admin-lure';
  // Payment: POST = fake card submission, GET = the payment page.
  if (PAYMENT_PATHS.includes(p)) return method === 'GET' ? 'checkout' : 'fake-payment';
  if (ACCOUNT_LOGIN_PATHS.includes(p)) return 'login-lure';
  if (p === '/' || p === '/shop' || p === '/products') return 'storefront';
  if (p === '/search') return 'storefront';
  if (p.startsWith('/product/') || p === '/product') return 'product';
  if (p === '/cart') return 'cart';
  return 'catch-all';
}

function clientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  const raw = (typeof forwarded === 'string' && forwarded.split(',')[0].trim()) || req.ip || '';
  return raw.replace(/^::ffff:/, '') || 'unknown';
}

// Writes every request to the database. It does not await the write, and the request
// is answered even if logging fails — the honeypot must never look "broken" or slow.
function logRequest(req, route) {
  const body = typeof req.body === 'string' ? req.body : '';
  const queryIndex = req.originalUrl.indexOf('?');

  prisma.honeypotEvent
    .create({
      data: {
        ip: clientIp(req),
        method: req.method,
        path: req.path.slice(0, 1000),
        query: queryIndex === -1 ? null : req.originalUrl.slice(queryIndex + 1, queryIndex + 1001),
        userAgent: (req.headers['user-agent'] || '').slice(0, 500) || null,
        headers: req.headers,
        body: body ? body.slice(0, 2000) : null,
        route,
      },
    })
    .catch((err) => {
      console.error('[honeypot] logging error:', err.message.replace(/\s+/g, ' ').slice(0, 200));
    });
}

// Catch-all: every method, every path.
router.all(/.*/, (req, res) => {
  const route = detectRoute(req);
  logRequest(req, route);

  if (req.method === 'HEAD') {
    res.status(route === 'catch-all' ? 404 : 200).end();
    return;
  }
  if (req.method === 'OPTIONS') {
    res.set('Allow', 'GET, POST, PUT, DELETE, HEAD, OPTIONS');
    res.status(200).end();
    return;
  }

  // Headers that make it look like a real store.
  res.set('Server', 'nginx/1.24.0');
  res.set('X-Powered-By', 'Express');

  const p = normalizePath(req.path);

  // Sensitive file — fake, worthless content.
  if (route === 'sensitive-file-probe') {
    const file = SENSITIVE_FILES[p];
    res.status(200).type(file.type).send(file.body);
    return;
  }

  // Admin lure — a fake account login is shown, POST always fails.
  if (route === 'admin-lure') {
    if (req.method === 'POST') {
      res.status(401).type('html').send(accountLoginPage({ error: 'Invalid username or password.' }));
      return;
    }
    res.status(200).type('html').send(accountLoginPage());
    return;
  }

  // Account login / registration lure.
  if (route === 'login-lure') {
    if (req.method === 'POST') {
      res.status(401).type('html').send(accountLoginPage({ error: 'Incorrect email or password.' }));
      return;
    }
    res.status(200).type('html').send(accountLoginPage());
    return;
  }

  // FAKE payment: the card data posted here has already been logged. NOTHING is processed —
  // it always shows "declined" so the attacker keeps trying more cards.
  if (route === 'fake-payment') {
    res.status(402).type('html').send(paymentDeclinedPage());
    return;
  }
  if (route === 'checkout') {
    res.status(200).type('html').send(checkoutPage());
    return;
  }

  if (route === 'product') {
    const id = p.startsWith('/product/') ? p.slice('/product/'.length) : (req.query.id ?? '');
    const { html, found } = productPage(id);
    res.status(found ? 200 : 404).type('html').send(html);
    return;
  }

  if (route === 'cart') {
    res.status(200).type('html').send(cartPage());
    return;
  }

  if (route === 'storefront') {
    if (p === '/search') {
      res.status(200).type('html').send(searchPage(req.query.q));
      return;
    }
    if (p === '/shop' || p === '/products') {
      res.status(200).type('html').send(shopPage());
      return;
    }
    res.status(200).type('html').send(homePage());
    return;
  }

  // Everything else — a fake 404.
  res.status(404).type('html').send(notFoundPage());
});

export default router;
