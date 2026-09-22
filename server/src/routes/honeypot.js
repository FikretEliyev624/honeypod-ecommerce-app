// SAXTA SAYT — internetə açılan honeypot (e-commerce mağaza görkəmində).
// Bu routerdə YALNIZ tələ səhifələri və loglama var.
// Heç bir admin/dashboard endpointi, heç bir icra (exec/eval), heç bir real sirr,
// heç bir real ödəniş emalı YOXDUR. Bütün kart/məhsul datası uydurmadır.
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

// Bütün body-ləri (JSON, form, XML, düz mətn) sadəcə STRİNQ kimi qəbul edirik —
// heç nə parse/icra olunmur, sadəcə saxlanılır.
router.use(express.text({ type: () => true, limit: '512kb' }));

// Admin/idarəetmə tələləri — mağazanın "arxa qapısı" kimi görünən skaner hədəfləri.
const ADMIN_LURES = [
  '/admin',
  '/administrator',
  '/wp-login.php',
  '/wp-admin',
  '/phpmyadmin',
  '/.env.bak',
];

// Ödəniş endpointləri — hücumçunun formadan göndərdiyi (saxta) kart datası bura düşür.
const PAYMENT_PATHS = ['/checkout', '/pay', '/api/pay', '/api/checkout', '/payment'];

// Saxta "həssas fayl" cavabları — məzmun tamamilə DƏYƏRSİZ və uydurmadır.
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

// Hansı tələnin işə düşdüyünü təyin edir.
function detectRoute(req) {
  const p = normalizePath(req.path);
  const method = req.method;

  if (SENSITIVE_FILES[p]) return 'sensitive-file-probe';
  if (ADMIN_LURES.includes(p)) return 'admin-lure';
  // Ödəniş: POST = saxta kart göndərişi, GET = ödəniş səhifəsi.
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

// Hər sorğunu bazaya yazır. Cavab gözləmir və loglama uğursuz olsa belə sorğu
// cavablandırılır — honeypot heç vaxt "sınmış" və ya yavaş görünməməlidir.
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

// Catch-all: bütün metodlar, bütün yollar.
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

  // Real bir mağaza kimi görünmək üçün başlıqlar.
  res.set('Server', 'nginx/1.24.0');
  res.set('X-Powered-By', 'Express');

  const p = normalizePath(req.path);

  // Həssas fayl — saxta, dəyərsiz məzmun.
  if (route === 'sensitive-file-probe') {
    const file = SENSITIVE_FILES[p];
    res.status(200).type(file.type).send(file.body);
    return;
  }

  // Admin tələsi — saxta hesab girişi göstərilir, POST həmişə uğursuz.
  if (route === 'admin-lure') {
    if (req.method === 'POST') {
      res.status(401).type('html').send(accountLoginPage({ error: 'Invalid username or password.' }));
      return;
    }
    res.status(200).type('html').send(accountLoginPage());
    return;
  }

  // Hesaba giriş / qeydiyyat tələsi.
  if (route === 'login-lure') {
    if (req.method === 'POST') {
      res.status(401).type('html').send(accountLoginPage({ error: 'Incorrect email or password.' }));
      return;
    }
    res.status(200).type('html').send(accountLoginPage());
    return;
  }

  // SAXTA ödəniş: POST-la gələn kart datası artıq loglandı. HEÇ NƏ emal olunmur —
  // həmişə "rədd edildi" göstərilir ki, hücumçu başqa kartlar sınamağa davam etsin.
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

  // Qalan hər şey — saxta 404.
  res.status(404).type('html').send(notFoundPage());
});

export default router;
