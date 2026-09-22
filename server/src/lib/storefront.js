// SAXTA e-commerce mağazasının HTML səhifələri — honeypot tələsi.
// Burada HEÇ BİR real ödəniş, real məhsul, real kart emalı yoxdur.
// Göstərilən "test kartı" hamıya məlum ictimai test nömrəsidir (real kart deyil).
// Məqsəd: saytı inandırıcı göstərib hücumçunun sorğularını cəlb etmək və loglamaq.

export const STORE_NAME = 'NovaShop';

// Uydurma məhsullar. Qiymətlər/anbarlar tamamilə saxtadır.
export const PRODUCTS = [
  { id: 1, name: 'Aurora Wireless Headphones', price: 149.99, emoji: '🎧', cat: 'Audio',
    desc: 'Active noise cancelling, 30-hour battery, Bluetooth 5.3.' },
  { id: 2, name: 'Nimbus Mechanical Keyboard', price: 89.5, emoji: '⌨️', cat: 'Accessories',
    desc: 'Hot-swap switches, RGB, aluminium chassis.' },
  { id: 3, name: 'Volt 20000mAh Power Bank', price: 39.0, emoji: '🔋', cat: 'Power',
    desc: '65W fast charging, USB-C PD, dual port.' },
  { id: 4, name: 'Pixel 4K Webcam', price: 74.25, emoji: '📷', cat: 'Video',
    desc: 'Autofocus, HDR, built-in microphone.' },
  { id: 5, name: 'Strata SSD 1TB', price: 112.0, emoji: '💾', cat: 'Storage',
    desc: 'NVMe Gen4, 7000MB/s read.' },
  { id: 6, name: 'Halo Smart Bulb', price: 29.99, emoji: '💡', cat: 'Home',
    desc: '16 million colours, voice control, app support.' },
];

// Bütün səhifələr üçün ümumi çərçivə.
function layout(title, body) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title} — ${STORE_NAME}</title>
<style>
  :root { --bg:#f6f7fb; --card:#fff; --ink:#1c2430; --dim:#6a7686; --line:#e4e8ef;
          --brand:#3454d1; --brand-d:#2740a8; --accent:#16a34a; }
  * { box-sizing:border-box; }
  body { margin:0; font-family:'Segoe UI',Roboto,Arial,sans-serif; background:var(--bg); color:var(--ink); }
  a { color:inherit; text-decoration:none; }
  header { background:var(--card); border-bottom:1px solid var(--line); position:sticky; top:0; z-index:5; }
  .bar { max-width:1080px; margin:0 auto; display:flex; align-items:center; gap:20px;
         padding:14px 20px; }
  .logo { font-size:20px; font-weight:800; letter-spacing:-.5px; color:var(--brand); }
  .logo span { color:var(--ink); }
  nav { display:flex; gap:18px; font-size:14px; color:var(--dim); }
  nav a:hover { color:var(--ink); }
  .search { margin-left:auto; display:flex; }
  .search input { border:1px solid var(--line); border-radius:6px 0 0 6px; padding:8px 12px;
                  font-size:14px; width:200px; }
  .search button { border:1px solid var(--brand); background:var(--brand); color:#fff;
                   border-radius:0 6px 6px 0; padding:0 14px; cursor:pointer; }
  .cart-link { display:flex; align-items:center; gap:6px; font-weight:600; }
  .badge { background:var(--accent); color:#fff; font-size:11px; border-radius:10px; padding:1px 7px; }
  main { max-width:1080px; margin:0 auto; padding:26px 20px 60px; }
  .hero { background:linear-gradient(120deg,#3454d1,#6a3fd1); color:#fff; border-radius:14px;
          padding:34px 30px; margin-bottom:26px; }
  .hero h1 { margin:0 0 6px; font-size:26px; }
  .hero p { margin:0; opacity:.9; }
  .grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(220px,1fr)); gap:18px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:12px; overflow:hidden;
          display:flex; flex-direction:column; transition:box-shadow .15s,transform .15s; }
  .card:hover { box-shadow:0 8px 24px rgba(28,36,48,.1); transform:translateY(-2px); }
  .thumb { font-size:64px; text-align:center; padding:28px 0; background:#eef1f8; }
  .card .body { padding:14px 16px; display:flex; flex-direction:column; gap:6px; flex:1; }
  .cat { font-size:11px; text-transform:uppercase; letter-spacing:.08em; color:var(--dim); }
  .name { font-weight:600; font-size:15px; }
  .price { font-size:18px; font-weight:700; color:var(--brand-d); margin-top:auto; }
  .btn { display:inline-block; text-align:center; background:var(--brand); color:#fff; border:0;
         border-radius:8px; padding:10px 16px; font-size:14px; font-weight:600; cursor:pointer; }
  .btn:hover { background:var(--brand-d); }
  .btn.block { display:block; width:100%; }
  .btn.ghost { background:#fff; color:var(--brand); border:1px solid var(--brand); }
  .detail { display:grid; grid-template-columns:340px 1fr; gap:30px; background:var(--card);
            border:1px solid var(--line); border-radius:14px; padding:26px; }
  .detail .thumb { font-size:120px; border-radius:12px; }
  .detail h1 { margin:0 0 8px; }
  .muted { color:var(--dim); font-size:14px; line-height:1.6; }
  table.cart { width:100%; border-collapse:collapse; background:var(--card); border:1px solid var(--line);
               border-radius:12px; overflow:hidden; }
  table.cart th, table.cart td { text-align:left; padding:12px 16px; border-bottom:1px solid var(--line); }
  table.cart th { font-size:12px; text-transform:uppercase; color:var(--dim); }
  .sum { text-align:right; margin-top:16px; font-size:18px; }
  .sum b { font-size:22px; color:var(--brand-d); }
  .pay { display:grid; grid-template-columns:1.3fr 1fr; gap:26px; }
  .panel { background:var(--card); border:1px solid var(--line); border-radius:14px; padding:24px; }
  .panel h2 { margin:0 0 16px; font-size:16px; }
  form.pay-form label { display:block; font-size:13px; color:var(--dim); margin:12px 0 5px; }
  form.pay-form input, form.pay-form select {
    width:100%; padding:10px 12px; border:1px solid var(--line); border-radius:8px; font-size:14px; }
  .row2 { display:grid; grid-template-columns:1fr 1fr; gap:14px; }
  .lock { font-size:12px; color:var(--accent); margin-top:14px; }
  .hint { font-size:12px; color:var(--dim); background:#f0f3fb; border:1px dashed #c7d1ea;
          border-radius:8px; padding:10px 12px; margin-top:16px; }
  .notice { border-radius:10px; padding:14px 16px; margin-bottom:18px; font-size:14px; }
  .notice.warn { background:#fff4e5; border:1px solid #f2c98a; color:#8a5a00; }
  .notice.err { background:#fdecea; border:1px solid #f1a9a0; color:#a12419; }
  footer { border-top:1px solid var(--line); color:var(--dim); font-size:12px; text-align:center;
           padding:24px; }
  .crumb { font-size:13px; color:var(--dim); margin-bottom:14px; }
  @media (max-width:720px){ .detail,.pay{ grid-template-columns:1fr; } }
</style>
</head>
<body>
<header>
  <div class="bar">
    <a class="logo" href="/">Nova<span>Shop</span></a>
    <nav>
      <a href="/">Home</a>
      <a href="/shop">Shop</a>
      <a href="/account/login">Account</a>
    </nav>
    <form class="search" method="get" action="/search">
      <input name="q" placeholder="Search products...">
      <button type="submit">Search</button>
    </form>
    <a class="cart-link" href="/cart" style="margin-left:16px;">🛒 <span class="badge">2</span></a>
  </div>
</header>
<main>
${body}
</main>
<footer>
  © 2026 ${STORE_NAME} · All rights reserved · Cards secured with SSL 🔒<br>
  <span style="opacity:.6">This site is an educational honeypot demo — not a real store.</span>
</footer>
</body>
</html>`;
}

function productCard(p) {
  return `<a class="card" href="/product/${p.id}">
    <div class="thumb">${p.emoji}</div>
    <div class="body">
      <span class="cat">${p.cat}</span>
      <span class="name">${p.name}</span>
      <span class="price">$${p.price.toFixed(2)}</span>
    </div>
  </a>`;
}

export function homePage() {
  const grid = PRODUCTS.map(productCard).join('\n');
  const body = `
  <div class="hero">
    <h1>Tech deals — up to 40% off</h1>
    <p>The latest gadgets, fast delivery, secure checkout.</p>
  </div>
  <h2 style="margin:0 0 14px;">Popular products</h2>
  <div class="grid">${grid}</div>`;
  return layout('Home', body);
}

export function shopPage() {
  const grid = PRODUCTS.map(productCard).join('\n');
  const body = `<div class="crumb">Home / Shop</div>
  <h1 style="margin:0 0 16px;">All products</h1>
  <div class="grid">${grid}</div>`;
  return layout('Shop', body);
}

// Axtarış nəticəsi — hücumçunun yazdığı sorğu (q) səhifədə göstərilmir (XSS-i əks
// etdirmirik), sadəcə mətn kimi qaçış edilib göstərilir.
export function searchPage(rawQuery) {
  const safe = String(rawQuery || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .slice(0, 120);
  const grid = PRODUCTS.slice(0, 3).map(productCard).join('\n');
  const body = `<div class="crumb">Search</div>
  <h1 style="margin:0 0 6px;">Results for: "${safe}"</h1>
  <p class="muted" style="margin:0 0 18px;">No matching products. You might like these:</p>
  <div class="grid">${grid}</div>`;
  return layout('Search', body);
}

export function productPage(id) {
  const p = PRODUCTS.find((x) => String(x.id) === String(id));
  if (!p) {
    const body = `<div class="crumb">Shop</div>
    <h1>Product not found</h1>
    <p class="muted">The product you are looking for does not exist or is no longer sold.</p>
    <a class="btn ghost" href="/shop">Back to shop</a>`;
    return { html: layout('Not found', body), found: false };
  }
  const body = `<div class="crumb"><a href="/shop">Shop</a> / ${p.cat} / ${p.name}</div>
  <div class="detail">
    <div class="thumb">${p.emoji}</div>
    <div>
      <span class="cat">${p.cat}</span>
      <h1>${p.name}</h1>
      <div class="price" style="font-size:26px;">$${p.price.toFixed(2)}</div>
      <p class="muted">${p.desc}</p>
      <p class="muted">In stock · 2-4 day delivery · 24-month warranty</p>
      <div style="display:flex; gap:12px; margin-top:18px;">
        <a class="btn" href="/checkout">Buy now</a>
        <a class="btn ghost" href="/cart">Add to cart</a>
      </div>
    </div>
  </div>`;
  return { html: layout(p.name, body), found: true };
}

export function cartPage() {
  const items = PRODUCTS.slice(0, 2);
  const rows = items
    .map(
      (p) => `<tr><td>${p.emoji} ${p.name}</td><td>1</td><td>$${p.price.toFixed(2)}</td></tr>`,
    )
    .join('\n');
  const total = items.reduce((s, p) => s + p.price, 0);
  const body = `<div class="crumb">Cart</div>
  <h1 style="margin:0 0 16px;">Your cart</h1>
  <table class="cart">
    <thead><tr><th>Product</th><th>Qty</th><th>Price</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>
  <div class="sum">Total: <b>$${total.toFixed(2)}</b></div>
  <div style="text-align:right; margin-top:14px;">
    <a class="btn" href="/checkout">Proceed to checkout →</a>
  </div>`;
  return layout('Cart', body);
}

// SAXTA ödəniş formu. Real emal YOXDUR. Göstərilən nümunə kart ictimai test kartıdır.
export function checkoutPage({ error = '' } = {}) {
  const items = PRODUCTS.slice(0, 2);
  const total = items.reduce((s, p) => s + p.price, 0);
  const errBlock = error ? `<div class="notice err">${error}</div>` : '';
  const body = `<div class="crumb"><a href="/cart">Cart</a> / Checkout</div>
  <h1 style="margin:0 0 18px;">Checkout</h1>
  ${errBlock}
  <div class="pay">
    <div class="panel">
      <h2>Card details</h2>
      <form class="pay-form" method="post" action="/checkout">
        <label>Cardholder name</label>
        <input name="card_name" placeholder="FULL NAME" autocomplete="off">
        <label>Card number</label>
        <input name="card_number" inputmode="numeric" placeholder="0000 0000 0000 0000" autocomplete="off">
        <div class="row2">
          <div>
            <label>Expiry date</label>
            <input name="card_expiry" placeholder="MM/YY" autocomplete="off">
          </div>
          <div>
            <label>CVV</label>
            <input name="card_cvv" inputmode="numeric" placeholder="123" autocomplete="off">
          </div>
        </div>
        <label>Email</label>
        <input name="email" type="email" placeholder="you@example.com" autocomplete="off">
        <button class="btn block" type="submit" style="margin-top:18px;">Pay $${total.toFixed(2)}</button>
        <div class="lock">🔒 Secure payment encrypted with 256-bit SSL</div>
        <div class="hint">Demo test card: 4242 4242 4242 4242 · 12/34 · 123
          (a public test number, not a real card)</div>
      </form>
    </div>
    <div class="panel">
      <h2>Order summary</h2>
      ${items.map((p) => `<div style="display:flex;justify-content:space-between;margin-bottom:8px;">
        <span class="muted">${p.name}</span><span>$${p.price.toFixed(2)}</span></div>`).join('')}
      <hr style="border:none;border-top:1px solid var(--line);margin:12px 0;">
      <div style="display:flex;justify-content:space-between;">
        <span>Shipping</span><span>Free</span></div>
      <div class="sum" style="margin-top:14px;">Total: <b>$${total.toFixed(2)}</b></div>
    </div>
  </div>`;
  return layout('Checkout', body);
}

// Ödəniş "nəticəsi" — həmişə uğursuz. Heç bir kart emal olunmur.
export function paymentDeclinedPage() {
  const body = `<div class="notice warn">
    The payment could not be processed. Your bank declined the transaction (code: DO_NOT_HONOR).
    Please try again with a different card.
  </div>
  <div class="panel" style="text-align:center;">
    <div style="font-size:52px;">⚠️</div>
    <h1 style="margin:8px 0;">Payment failed</h1>
    <p class="muted">No amount was charged to your card.</p>
    <a class="btn" href="/checkout">Try again</a>
    <a class="btn ghost" href="/" style="margin-left:8px;">Home</a>
  </div>`;
  return layout('Payment failed', body);
}

export function notFoundPage() {
  const body = `<div class="panel" style="text-align:center;">
    <div style="font-size:52px;">🔍</div>
    <h1 style="margin:8px 0;">404 — Page not found</h1>
    <p class="muted">No such page exists.</p>
    <a class="btn" href="/">Back to home</a>
  </div>`;
  return layout('404', body);
}

// E-commerce hesab girişi (admin deyil) — saxta login.
export function accountLoginPage({ error = '' } = {}) {
  const errBlock = error ? `<div class="notice err">${error}</div>` : '';
  const body = `<div style="max-width:380px;margin:20px auto;">
    <div class="panel">
      <h2>Sign in</h2>
      ${errBlock}
      <form class="pay-form" method="post" action="/account/login">
        <label>Email</label>
        <input name="email" type="email" autocomplete="off">
        <label>Password</label>
        <input name="password" type="password" autocomplete="off">
        <button class="btn block" type="submit" style="margin-top:16px;">Sign in</button>
      </form>
      <p class="muted" style="text-align:center;margin-top:14px;">
        Don&#39;t have an account? <a href="/account/register" style="color:var(--brand);">Register</a></p>
    </div>
  </div>`;
  return layout('Sign in', body);
}
