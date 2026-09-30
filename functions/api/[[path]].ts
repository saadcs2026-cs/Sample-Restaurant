import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { handle } from 'hono/cloudflare-pages';

type E = { DB: D1Database; SESSIONS: KVNamespace; SUPER_KEY: string };

const app = new Hono<{ Bindings: E }>().basePath('/api');
app.use('*', cors({ origin: '*', credentials: true }));

const sha = async (s: string) => {
  const b = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
};
const sign = async (slug: string, table: string, secret: string) =>
  (await sha(`${slug}:${table}:${secret}`)).slice(0, 16);

const sess = async (c: any) => {
  const m = (c.req.header('Cookie') || '').match(/sid=([^;]+)/);
  if (!m) return null;
  const d = await c.env.SESSIONS.get(`s:${m[1]}`);
  return d ? { token: m[1], ...JSON.parse(d) } : null;
};
const adm = async (c: any) => {
  const t = (c.req.header('Authorization') || '').replace('Bearer ', '');
  const d = await c.env.SESSIONS.get(`a:${t}`);
  return d ? JSON.parse(d) : null;
};

// ---------- PUBLIC ----------

// Verify QR + get restaurant + menu in one call
app.get('/menu/:slug', async (c) => {
  const { slug } = c.req.param();
  const r: any = await c.env.DB.prepare(
    'SELECT id, name, name_urdu, currency, pin_enabled FROM restaurants WHERE slug=?'
  ).bind(slug).first();
  if (!r) return c.json({ error: 'Restaurant not found' }, 404);

  const items = await c.env.DB.prepare(
    'SELECT id, name, name_urdu, description, description_urdu, price, category, category_urdu, image_url FROM menu_items WHERE rid=? AND available=1 ORDER BY category, id'
  ).bind(r.id).all();

  return c.json({
    restaurant: {
      name: r.name, name_urdu: r.name_urdu,
      currency: r.currency, pin_enabled: !!r.pin_enabled,
    },
    items: items.results,
  });
});

// Create session (verifies QR signature and PIN)
app.post('/session', async (c) => {
  const { slug, table, k, pin } = await c.req.json();
  const r: any = await c.env.DB.prepare(
    'SELECT * FROM restaurants WHERE slug=?'
  ).bind(slug).first();
  if (!r) return c.json({ error: 'Restaurant not found' }, 404);

  // Verify QR signature
  const expected = await sign(slug, table, c.env.SUPER_KEY);
  if (k !== expected) return c.json({ error: 'Invalid QR code' }, 403);

  // Verify PIN if enabled
  if (r.pin_enabled) {
    const t: any = await c.env.DB.prepare(
      'SELECT pin FROM tables WHERE rid=? AND number=?'
    ).bind(r.id, table).first();
    if (!t) return c.json({ error: 'Table not found' }, 400);
    if (t.pin !== pin) return c.json({ error: 'Wrong PIN' }, 403);
  }

  const token = crypto.randomUUID();
  await c.env.SESSIONS.put(
    `s:${token}`,
    JSON.stringify({ rid: r.id, slug, table }),
    { expirationTtl: 10800 } // 3 hours
  );
  c.header('Set-Cookie',
    `sid=${token}; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=10800`);
  return c.json({ ok: true, table });
});

// Place order
app.post('/order', async (c) => {
  const s: any = await sess(c);
  if (!s) return c.json({ error: 'Session required' }, 401);

  const { items } = await c.req.json();
  if (!items?.length) return c.json({ error: 'Cart is empty' }, 400);

  // Rate limit: 3 orders / minute / table
  const minute = Math.floor(Date.now() / 60000);
  const key = `rl:${s.rid}:${s.table}:${minute}`;
  const cnt = parseInt((await c.env.SESSIONS.get(key)) || '0');
  if (cnt >= 3) return c.json({ error: 'Too many orders, please wait.' }, 429);
  await c.env.SESSIONS.put(key, String(cnt + 1), { expirationTtl: 120 });

  // Server-side price lookup
  let total = 0;
  const valid: any[] = [];
  for (const it of items) {
    const m: any = await c.env.DB.prepare(
      'SELECT id, price FROM menu_items WHERE id=? AND rid=? AND available=1'
    ).bind(it.id, s.rid).first();
    if (!m) return c.json({ error: 'An item is unavailable' }, 400);
    total += m.price * it.qty;
    valid.push({ id: m.id, qty: it.qty, price: m.price });
  }

  const o: any = await c.env.DB.prepare(
    'INSERT INTO orders (rid, table_num, session, total) VALUES (?,?,?,?)'
  ).bind(s.rid, s.table, s.token, total).run();
  const oid = o.meta.last_row_id;

  for (const v of valid) {
    await c.env.DB.prepare(
      'INSERT INTO order_items (order_id, item_id, qty, price) VALUES (?,?,?,?)'
    ).bind(oid, v.id, v.qty, v.price).run();
  }

  return c.json({ order_id: oid, total, table: s.table }, 201);
});

app.get('/my-orders', async (c) => {
  const s: any = await sess(c);
  if (!s) return c.json([]);
  const r = await c.env.DB.prepare(
    'SELECT id, status, total, created_at FROM orders WHERE session=? ORDER BY id DESC'
  ).bind(s.token).all();
  return c.json(r.results);
});

// Call waiter / request bill
app.post('/request', async (c) => {
  const s: any = await sess(c);
  if (!s) return c.json({ error: 'Session required' }, 401);
  const { type } = await c.req.json();
  if (!['call_waiter', 'request_bill'].includes(type))
    return c.json({ error: 'Invalid type' }, 400);
  await c.env.DB.prepare(
    'INSERT INTO requests (rid, table_num, type) VALUES (?,?,?)'
  ).bind(s.rid, s.table, type).run();
  return c.json({ ok: true });
});

// ---------- ADMIN ----------

app.post('/admin/login', async (c) => {
  const { slug, password } = await c.req.json();
  const r: any = await c.env.DB.prepare(
    'SELECT id, password_hash, name FROM restaurants WHERE slug=?'
  ).bind(slug).first();
  if (!r) return c.json({ error: 'Restaurant not found' }, 404);
  if ((await sha(password)) !== r.password_hash)
    return c.json({ error: 'Wrong password' }, 401);

  const token = crypto.randomUUID();
  await c.env.SESSIONS.put(
    `a:${token}`,
    JSON.stringify({ rid: r.id, slug }),
    { expirationTtl: 43200 } // 12 hours
  );
  return c.json({ token, name: r.name, slug });
});

app.get('/admin/orders', async (c) => {
  const a: any = await adm(c);
  if (!a) return c.json({ error: 'Unauthorized' }, 401);
  const status = c.req.query('status');
  let sql = `SELECT o.*, (SELECT json_group_array(json_object(
    'name', m.name, 'name_urdu', m.name_urdu, 'qty', oi.qty, 'price', oi.price))
    FROM order_items oi JOIN menu_items m ON oi.item_id=m.id WHERE oi.order_id=o.id)
    AS items FROM orders o WHERE o.rid=?`;
  const p: any[] = [a.rid];
  if (status) { sql += ' AND o.status=?'; p.push(status); }
  sql += ' ORDER BY o.id DESC LIMIT 100';
  const r = await c.env.DB.prepare(sql).bind(...p).all();
  return c.json(r.results);
});

app.patch('/admin/orders/:id', async (c) => {
  const a: any = await adm(c);
  if (!a) return c.json({ error: 'Unauthorized' }, 401);
  const { status } = await c.req.json();
  await c.env.DB.prepare(
    'UPDATE orders SET status=? WHERE id=? AND rid=?'
  ).bind(status, c.req.param('id'), a.rid).run();
  return c.json({ ok: true });
});

// End session for a table (admin action)
app.post('/admin/end-session', async (c) => {
  const a: any = await adm(c);
  if (!a) return c.json({ error: 'Unauthorized' }, 401);
  const { table } = await c.req.json();
  const list = await c.env.SESSIONS.list({ prefix: 's:' });
  for (const k of list.keys) {
    const v = await c.env.SESSIONS.get(k.name);
    if (v) {
      const d = JSON.parse(v);
      if (d.rid === a.rid && d.table === table)
        await c.env.SESSIONS.delete(k.name);
    }
  }
  return c.json({ ok: true });
});

// Menu CRUD
app.get('/admin/menu', async (c) => {
  const a: any = await adm(c);
  if (!a) return c.json({ error: 'Unauthorized' }, 401);
  const r = await c.env.DB.prepare(
    'SELECT * FROM menu_items WHERE rid=? ORDER BY category, id'
  ).bind(a.rid).all();
  return c.json(r.results);
});

app.post('/admin/menu', async (c) => {
  const a: any = await adm(c);
  if (!a) return c.json({ error: 'Unauthorized' }, 401);
  const b = await c.req.json();
  const r: any = await c.env.DB.prepare(
    'INSERT INTO menu_items (rid, name, name_urdu, description, description_urdu, price, category, category_urdu, image_url) VALUES (?,?,?,?,?,?,?,?,?)'
  ).bind(a.rid, b.name, b.name_urdu || '', b.description || '',
    b.description_urdu || '', b.price, b.category,
    b.category_urdu || '', b.image_url || '').run();
  return c.json({ id: r.meta.last_row_id }, 201);
});

app.put('/admin/menu/:id', async (c) => {
  const a: any = await adm(c);
  if (!a) return c.json({ error: 'Unauthorized' }, 401);
  const b = await c.req.json();
  await c.env.DB.prepare(
    'UPDATE menu_items SET name=?, name_urdu=?, description=?, description_urdu=?, price=?, category=?, category_urdu=?, image_url=?, available=? WHERE id=? AND rid=?'
  ).bind(b.name, b.name_urdu || '', b.description || '',
    b.description_urdu || '', b.price, b.category,
    b.category_urdu || '', b.image_url || '',
    b.available ? 1 : 0, c.req.param('id'), a.rid).run();
  return c.json({ ok: true });
});

app.delete('/admin/menu/:id', async (c) => {
  const a: any = await adm(c);
  if (!a) return c.json({ error: 'Unauthorized' }, 401);
  await c.env.DB.prepare(
    'DELETE FROM menu_items WHERE id=? AND rid=?'
  ).bind(c.req.param('id'), a.rid).run();
  return c.json({ ok: true });
});

// Tables + QR URLs
app.get('/admin/tables', async (c) => {
  const a: any = await adm(c);
  if (!a) return c.json({ error: 'Unauthorized' }, 401);
  const tables = await c.env.DB.prepare(
    'SELECT number, pin FROM tables WHERE rid=? ORDER BY CAST(number AS INTEGER)'
  ).bind(a.rid).all();
  const origin = new URL(c.req.url).origin;
  const urls = await Promise.all((tables.results as any[]).map(async (t) => {
    const k = await sign(a.slug, t.number, c.env.SUPER_KEY);
    return { number: t.number, pin: t.pin,
      url: `${origin}/?r=${a.slug}&t=${t.number}&k=${k}` };
  }));
  return c.json(urls);
});

app.post('/admin/tables/regenerate', async (c) => {
  const a: any = await adm(c);
  if (!a) return c.json({ error: 'Unauthorized' }, 401);
  const { count } = await c.req.json();
  await c.env.DB.prepare('DELETE FROM tables WHERE rid=?').bind(a.rid).run();
  for (let i = 1; i <= count; i++) {
    const pin = String(Math.floor(1000 + Math.random() * 9000));
    await c.env.DB.prepare(
      'INSERT INTO tables (rid, number, pin) VALUES (?,?,?)'
    ).bind(a.rid, String(i), pin).run();
  }
  await c.env.DB.prepare(
    'UPDATE restaurants SET table_count=? WHERE id=?'
  ).bind(count, a.rid).run();
  return c.json({ ok: true });
});

// Settings
app.get('/admin/settings', async (c) => {
  const a: any = await adm(c);
  if (!a) return c.json({ error: 'Unauthorized' }, 401);
  const r = await c.env.DB.prepare(
    'SELECT slug, name, name_urdu, address, phone, google_place_id, table_count, pin_enabled, currency, cloud_name, upload_preset FROM restaurants WHERE id=?'
  ).bind(a.rid).first();
  return c.json(r);
});

app.put('/admin/settings', async (c) => {
  const a: any = await adm(c);
  if (!a) return c.json({ error: 'Unauthorized' }, 401);
  const b = await c.req.json();
  await c.env.DB.prepare(
    'UPDATE restaurants SET name=?, name_urdu=?, address=?, phone=?, google_place_id=?, pin_enabled=?, currency=?, cloud_name=?, upload_preset=? WHERE id=?'
  ).bind(b.name, b.name_urdu || '', b.address || '', b.phone || '',
    b.google_place_id || '', b.pin_enabled ? 1 : 0, b.currency || 'Rs',
    b.cloud_name || '', b.upload_preset || '', a.rid).run();
  return c.json({ ok: true });
});

// Service requests
app.get('/admin/requests', async (c) => {
  const a: any = await adm(c);
  if (!a) return c.json({ error: 'Unauthorized' }, 401);
  const r = await c.env.DB.prepare(
    'SELECT * FROM requests WHERE rid=? AND done=0 ORDER BY id DESC'
  ).bind(a.rid).all();
  return c.json(r.results);
});

app.patch('/admin/requests/:id', async (c) => {
  const a: any = await adm(c);
  if (!a) return c.json({ error: 'Unauthorized' }, 401);
  await c.env.DB.prepare(
    'UPDATE requests SET done=1 WHERE id=? AND rid=?'
  ).bind(c.req.param('id'), a.rid).run();
  return c.json({ ok: true });
});

// ---------- SUPER ADMIN (create restaurant via curl) ----------
app.post('/super/restaurant', async (c) => {
  if (c.req.header('X-Super-Key') !== c.env.SUPER_KEY)
    return c.json({ error: 'Forbidden' }, 403);
  const b = await c.req.json();
  if (!b.slug || !b.name || !b.password)
    return c.json({ error: 'slug, name, password required' }, 400);

  try {
    const hash = await sha(b.password);
    const r: any = await c.env.DB.prepare(
      'INSERT INTO restaurants (slug, name, name_urdu, address, phone, google_place_id, table_count, pin_enabled, currency, password_hash, cloud_name, upload_preset) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)'
    ).bind(b.slug, b.name, b.name_urdu || '', b.address || '',
      b.phone || '', b.google_place_id || '', b.table_count || 10,
      1, b.currency || 'Rs', hash, b.cloud_name || '',
      b.upload_preset || '').run();

    const rid = r.meta.last_row_id;
    for (let i = 1; i <= (b.table_count || 10); i++) {
      const pin = String(Math.floor(1000 + Math.random() * 9000));
      await c.env.DB.prepare(
        'INSERT INTO tables (rid, number, pin) VALUES (?,?,?)'
      ).bind(rid, String(i), pin).run();
    }
    return c.json({ ok: true, slug: b.slug });
  } catch (e: any) {
    if (String(e).includes('UNIQUE'))
      return c.json({ error: 'Slug already exists' }, 409);
    return c.json({ error: 'Create failed' }, 500);
  }
});

app.get('/health', (c) => c.json({ ok: true }));

export const onRequest = handle(app);
