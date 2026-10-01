// Pure Cloudflare Worker — zero dependencies

type E = {
  DB: D1Database;
  SESSIONS: KVNamespace;
  SUPER_KEY: string;
  CLOUDINARY_CLOUD_NAME?: string;
  CLOUDINARY_API_KEY?: string;
  CLOUDINARY_API_SECRET?: string;
};

const json = (data: any, status = 200, headers: any = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });

const sha = async (s: string) => {
  const b = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
};

const sha1 = async (s: string) => {
  const b = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(s));
  return [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
};

const sign = async (slug: string, table: string, secret: string) =>
  (await sha(`${slug}:${table}:${secret}`)).slice(0, 16);

const getCookie = (req: Request, name: string) => {
  const c = req.headers.get('Cookie') || '';
  const m = c.match(new RegExp(`${name}=([^;]+)`));
  return m ? m[1] : null;
};

const getSession = async (req: Request, env: E) => {
  const sid = getCookie(req, 'sid');
  if (!sid) return null;
  const d = await env.SESSIONS.get(`s:${sid}`);
  return d ? { token: sid, ...JSON.parse(d) } : null;
};

const getAdmin = async (req: Request, env: E) => {
  const auth = req.headers.get('Authorization') || '';
  if (!auth.startsWith('Bearer ')) return null;
  const t = auth.slice(7);
  const d = await env.SESSIONS.get(`a:${t}`);
  return d ? JSON.parse(d) : null;
};

const generateUniquePin = async (env: E, rid: number, excludeNumber?: string) => {
  const others = await env.DB.prepare(
    'SELECT pin FROM tables WHERE rid=? AND number!=?'
  ).bind(rid, excludeNumber || '').all();
  const used = new Set((others.results as any[]).map(r => String(r.pin)));
  for (let i = 0; i < 100; i++) {
    const candidate = String(Math.floor(1000 + Math.random() * 9000));
    if (!used.has(candidate)) return candidate;
  }
  return String(Math.floor(1000 + Math.random() * 9000));
};

// Pakistan-time today as YYYY-MM-DD
const pktToday = () => {
  const pad = (n: number) => String(n).padStart(2, '0');
  const nowPkt = new Date(Date.now() + 5 * 60 * 60 * 1000);
  return `${nowPkt.getUTCFullYear()}-${pad(nowPkt.getUTCMonth() + 1)}-${pad(nowPkt.getUTCDate())}`;
};

// Convert YYYY-MM-DD (Pakistan midnight) → UTC datetime string
const pktToUtc = (dateStr: string) =>
  new Date(`${dateStr}T00:00:00+05:00`).toISOString().slice(0, 19).replace('T', ' ');

export const onRequest = async (context: any) => {
  const { request, env, params } = context;
  const url = new URL(request.url);
  const path = '/' + (params.path || []).join('/');
  const method = request.method;

  if (method === 'OPTIONS') {
    return new Response(null, {
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type,Authorization',
        'Access-Control-Allow-Credentials': 'true',
      },
    });
  }
  const CORS = { 'Access-Control-Allow-Origin': '*' };

  try {
    // ==================== PUBLIC ====================

    let m = path.match(/^\/menu\/([^/]+)$/);
    if (m && method === 'GET') {
      const slug = m[1];
      const r: any = await env.DB.prepare(
        'SELECT id, name, name_urdu, currency, pin_enabled, address, phone, google_place_id FROM restaurants WHERE slug=?'
      ).bind(slug).first();
      if (!r) return json({ error: 'Restaurant not found' }, 404, CORS);

      const items = await env.DB.prepare(
        'SELECT id, name, name_urdu, description, description_urdu, price, category, category_urdu, image_url FROM menu_items WHERE rid=? AND available=1 ORDER BY category, id'
      ).bind(r.id).all();

      return json({
        restaurant: {
          name: r.name, name_urdu: r.name_urdu,
          currency: r.currency, pin_enabled: !!r.pin_enabled,
          address: r.address || '', phone: r.phone || '',
          google_place_id: r.google_place_id || '',
        },
        items: items.results,
      }, 200, CORS);
    }

    if (path === '/session' && method === 'POST') {
      const b: any = await request.json();
      const r: any = await env.DB.prepare(
        'SELECT * FROM restaurants WHERE slug=?'
      ).bind(b.slug).first();
      if (!r) return json({ error: 'Restaurant not found' }, 404, CORS);

      const expected = await sign(b.slug, b.table, env.SUPER_KEY);
      if (b.k !== expected) return json({ error: 'Invalid QR code' }, 403, CORS);

      if (r.pin_enabled) {
        const t: any = await env.DB.prepare(
          'SELECT pin FROM tables WHERE rid=? AND number=?'
        ).bind(r.id, b.table).first();
        if (!t) return json({ error: 'Table not found' }, 400, CORS);
        if (t.pin !== b.pin) return json({ error: 'Wrong PIN' }, 403, CORS);
      }

      const token = crypto.randomUUID();
      await env.SESSIONS.put(
        `s:${token}`,
        JSON.stringify({ rid: r.id, slug: b.slug, table: b.table }),
        { expirationTtl: 10800 }
      );

      return json({ ok: true, table: b.table }, 200, {
        ...CORS,
        'Set-Cookie': `sid=${token}; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=10800`,
      });
    }

    // POST /order — with daily resetting order number
    if (path === '/order' && method === 'POST') {
      const s: any = await getSession(request, env);
      if (!s) return json({ error: 'Session required' }, 401, CORS);

      const body: any = await request.json();
      const items = body.items || [];
      if (!items.length) return json({ error: 'Cart is empty' }, 400, CORS);

      // Rate limit
      const minute = Math.floor(Date.now() / 60000);
      const rlKey = `rl:${s.rid}:${s.table}:${minute}`;
      const cnt = parseInt((await env.SESSIONS.get(rlKey)) || '0');
      if (cnt >= 3) return json({ error: 'Too many orders, please wait.' }, 429, CORS);
      await env.SESSIONS.put(rlKey, String(cnt + 1), { expirationTtl: 120 });

      // Validate items and compute total
      let total = 0;
      const valid: any[] = [];
      for (const it of items) {
        const mi: any = await env.DB.prepare(
          'SELECT id, price FROM menu_items WHERE id=? AND rid=? AND available=1'
        ).bind(it.id, s.rid).first();
        if (!mi) return json({ error: 'An item is unavailable' }, 400, CORS);
        total += mi.price * it.qty;
        valid.push({ id: mi.id, qty: it.qty, price: mi.price });
      }

      // Compute daily order number (resets at Pakistan midnight or on admin clear)
      const today = pktToday();
      const rest: any = await env.DB.prepare(
        'SELECT order_seq_date, order_seq FROM restaurants WHERE id=?'
      ).bind(s.rid).first();

      let dailyNumber: number;
      if (rest.order_seq_date !== today) {
        dailyNumber = 1;
        await env.DB.prepare(
          'UPDATE restaurants SET order_seq_date=?, order_seq=? WHERE id=?'
        ).bind(today, 1, s.rid).run();
      } else {
        dailyNumber = (rest.order_seq || 0) + 1;
        await env.DB.prepare(
          'UPDATE restaurants SET order_seq=? WHERE id=?'
        ).bind(dailyNumber, s.rid).run();
      }

      const o: any = await env.DB.prepare(
        'INSERT INTO orders (rid, table_num, session, total, daily_number) VALUES (?,?,?,?,?)'
      ).bind(s.rid, s.table, s.token, total, dailyNumber).run();
      const oid = o.meta.last_row_id;

      for (const v of valid) {
        await env.DB.prepare(
          'INSERT INTO order_items (order_id, item_id, qty, price) VALUES (?,?,?,?)'
        ).bind(oid, v.id, v.qty, v.price).run();
      }

      return json({
        order_id: oid,
        daily_number: dailyNumber,
        total,
        table: s.table,
      }, 201, CORS);
    }

    if (path === '/my-orders' && method === 'GET') {
      const s: any = await getSession(request, env);
      if (!s) return json([], 200, CORS);
      const r = await env.DB.prepare(
        'SELECT id, daily_number, status, total, created_at FROM orders WHERE session=? ORDER BY id DESC'
      ).bind(s.token).all();
      return json(r.results, 200, CORS);
    }

    if (path === '/request' && method === 'POST') {
      const s: any = await getSession(request, env);
      if (!s) return json({ error: 'Session required' }, 401, CORS);
      const b: any = await request.json();
      if (!['call_waiter', 'request_bill'].includes(b.type))
        return json({ error: 'Invalid type' }, 400, CORS);
      await env.DB.prepare(
        'INSERT INTO requests (rid, table_num, type) VALUES (?,?,?)'
      ).bind(s.rid, s.table, b.type).run();
      return json({ ok: true }, 200, CORS);
    }

    // ==================== ADMIN ====================

    if (path === '/admin/login' && method === 'POST') {
      const b: any = await request.json();
      const r: any = await env.DB.prepare(
        'SELECT id, password_hash, name FROM restaurants WHERE slug=?'
      ).bind(b.slug).first();
      if (!r) return json({ error: 'Restaurant not found' }, 404, CORS);
      if ((await sha(b.password)) !== r.password_hash)
        return json({ error: 'Wrong password' }, 401, CORS);

      const token = crypto.randomUUID();
      await env.SESSIONS.put(
        `a:${token}`,
        JSON.stringify({ rid: r.id, slug: b.slug }),
        { expirationTtl: 43200 }
      );
      return json({ token, name: r.name, slug: b.slug }, 200, CORS);
    }

    // GET /admin/orders — non-archived orders
    if (path === '/admin/orders' && method === 'GET') {
      const a: any = await getAdmin(request, env);
      if (!a) return json({ error: 'Unauthorized' }, 401, CORS);
      const status = url.searchParams.get('status');
      let sql = `SELECT o.*, (SELECT json_group_array(json_object(
        'name', m.name, 'name_urdu', m.name_urdu, 'qty', oi.qty, 'price', oi.price))
        FROM order_items oi JOIN menu_items m ON oi.item_id=m.id WHERE oi.order_id=o.id)
        AS items FROM orders o WHERE o.rid=? AND o.archived=0`;
      const p: any[] = [a.rid];
      if (status) { sql += ' AND o.status=?'; p.push(status); }
      sql += ' ORDER BY o.id DESC LIMIT 200';
      const r = await env.DB.prepare(sql).bind(...p).all();
      return json(r.results, 200, CORS);
    }

    m = path.match(/^\/admin\/orders\/(\d+)$/);
    if (m && method === 'PATCH') {
      const a: any = await getAdmin(request, env);
      if (!a) return json({ error: 'Unauthorized' }, 401, CORS);
      const b: any = await request.json();
      await env.DB.prepare(
        'UPDATE orders SET status=? WHERE id=? AND rid=?'
      ).bind(b.status, m[1], a.rid).run();
      return json({ ok: true }, 200, CORS);
    }

    // POST /admin/orders/clear — archive all non-archived orders + reset daily counter
    if (path === '/admin/orders/clear' && method === 'POST') {
      const a: any = await getAdmin(request, env);
      if (!a) return json({ error: 'Unauthorized' }, 401, CORS);

      // Archive all non-archived orders
      await env.DB.prepare(
        'UPDATE orders SET archived=1 WHERE rid=? AND archived=0'
      ).bind(a.rid).run();

      // Reset daily counter to 0
      await env.DB.prepare(
        'UPDATE restaurants SET order_seq_date=?, order_seq=0 WHERE id=?'
      ).bind(pktToday(), a.rid).run();

      return json({ ok: true }, 200, CORS);
    }

    // POST /admin/end-session
    if (path === '/admin/end-session' && method === 'POST') {
      const a: any = await getAdmin(request, env);
      if (!a) return json({ error: 'Unauthorized' }, 401, CORS);
      const b: any = await request.json();
      const table = String(b.table);

      await env.DB.prepare(
        'UPDATE orders SET archived=1 WHERE rid=? AND table_num=? AND archived=0'
      ).bind(a.rid, table).run();

      const list = await env.SESSIONS.list({ prefix: 's:' });
      for (const k of list.keys) {
        const v = await env.SESSIONS.get(k.name);
        if (v) {
          const d = JSON.parse(v);
          if (d.rid === a.rid && String(d.table) === table) {
            await env.SESSIONS.delete(k.name);
          }
        }
      }

      const row: any = await env.DB.prepare(
        'SELECT session_count FROM tables WHERE rid=? AND number=?'
      ).bind(a.rid, table).first();

      const newCount = (row?.session_count || 0) + 1;
      let newPin: string | null = null;

      if (newCount >= 3) {
        newPin = await generateUniquePin(env, a.rid, table);
        await env.DB.prepare(
          'UPDATE tables SET pin=?, session_count=0 WHERE rid=? AND number=?'
        ).bind(newPin, a.rid, table).run();
      } else {
        await env.DB.prepare(
          'UPDATE tables SET session_count=? WHERE rid=? AND number=?'
        ).bind(newCount, a.rid, table).run();
      }

      return json({ ok: true, new_pin: newPin, count: newCount }, 200, CORS);
    }

    // ==================== ANALYTICS ====================
    if (path === '/admin/analytics' && method === 'GET') {
      const a: any = await getAdmin(request, env);
      if (!a) return json({ error: 'Unauthorized' }, 401, CORS);

      const todayStr = pktToday();
      const pad = (n: number) => String(n).padStart(2, '0');
      const nowPkt = new Date(Date.now() + 5 * 60 * 60 * 1000);
      const weekStr = (() => {
        const d = new Date(nowPkt.getTime() - 6 * 24 * 60 * 60 * 1000);
        return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
      })();
      const monthStr = `${nowPkt.getUTCFullYear()}-${pad(nowPkt.getUTCMonth() + 1)}-01`;

      const stats = async (dateStr: string) => {
        const sinceUtc = pktToUtc(dateStr);
        const r: any = await env.DB.prepare(
          `SELECT COUNT(*) as orders, COALESCE(SUM(total),0) as revenue
           FROM orders WHERE rid=? AND created_at >= ?`
        ).bind(a.rid, sinceUtc).first();
        const orders = r.orders || 0;
        const revenue = r.revenue || 0;
        return { orders, revenue, avg: orders ? Math.round(revenue / orders) : 0 };
      };

      const today = await stats(todayStr);
      const week = await stats(weekStr);
      const month = await stats(monthStr);
      const allTime = await stats("1970-01-01");

      const top = await env.DB.prepare(
        `SELECT m.name, m.name_urdu,
                SUM(oi.qty) as qty,
                SUM(oi.qty * oi.price) as revenue
         FROM order_items oi
         JOIN menu_items m ON oi.item_id=m.id
         JOIN orders o ON oi.order_id=o.id
         WHERE o.rid=? AND o.created_at >= ?
         GROUP BY m.id
         ORDER BY qty DESC LIMIT 8`
      ).bind(a.rid, pktToUtc(monthStr)).all();

      return json({ today, week, month, allTime, top_items: top.results }, 200, CORS);
    }

    // ==================== MENU ====================

    if (path === '/admin/menu' && method === 'GET') {
      const a: any = await getAdmin(request, env);
      if (!a) return json({ error: 'Unauthorized' }, 401, CORS);
      const r = await env.DB.prepare(
        'SELECT * FROM menu_items WHERE rid=? ORDER BY category, id'
      ).bind(a.rid).all();
      return json(r.results, 200, CORS);
    }

    if (path === '/admin/menu' && method === 'POST') {
      const a: any = await getAdmin(request, env);
      if (!a) return json({ error: 'Unauthorized' }, 401, CORS);
      const b: any = await request.json();
      const r: any = await env.DB.prepare(
        'INSERT INTO menu_items (rid, name, name_urdu, description, description_urdu, price, category, category_urdu, image_url) VALUES (?,?,?,?,?,?,?,?,?)'
      ).bind(a.rid, b.name, b.name_urdu || '', b.description || '',
        b.description_urdu || '', b.price, b.category,
        b.category_urdu || '', b.image_url || '').run();
      return json({ id: r.meta.last_row_id }, 201, CORS);
    }

    m = path.match(/^\/admin\/menu\/(\d+)$/);
    if (m && method === 'PUT') {
      const a: any = await getAdmin(request, env);
      if (!a) return json({ error: 'Unauthorized' }, 401, CORS);
      const b: any = await request.json();
      await env.DB.prepare(
        'UPDATE menu_items SET name=?, name_urdu=?, description=?, description_urdu=?, price=?, category=?, category_urdu=?, image_url=?, available=? WHERE id=? AND rid=?'
      ).bind(b.name, b.name_urdu || '', b.description || '',
        b.description_urdu || '', b.price, b.category,
        b.category_urdu || '', b.image_url || '',
        b.available ? 1 : 0, m[1], a.rid).run();
      return json({ ok: true }, 200, CORS);
    }

    if (m && method === 'DELETE') {
      const a: any = await getAdmin(request, env);
      if (!a) return json({ error: 'Unauthorized' }, 401, CORS);
      await env.DB.prepare(
        'DELETE FROM menu_items WHERE id=? AND rid=?'
      ).bind(m[1], a.rid).run();
      return json({ ok: true }, 200, CORS);
    }

    if (path === '/admin/menu/delete-image' && method === 'POST') {
      const a: any = await getAdmin(request, env);
      if (!a) return json({ error: 'Unauthorized' }, 401, CORS);
      const body: any = await request.json();
      const publicId = body.public_id;
      if (!publicId) return json({ error: 'public_id is required' }, 400, CORS);

      const cloudName = env.CLOUDINARY_CLOUD_NAME;
      const apiKey = env.CLOUDINARY_API_KEY;
      const apiSecret = env.CLOUDINARY_API_SECRET;
      if (!cloudName || !apiKey || !apiSecret) {
        return json({ error: 'Cloudinary credentials not configured' }, 500, CORS);
      }

      try {
        const timestamp = Math.round(Date.now() / 1000);
        const paramsToSign = `public_id=${publicId}&timestamp=${timestamp}`;
        const signature = await sha1(paramsToSign + apiSecret);
        const formData = new FormData();
        formData.append('public_id', publicId);
        formData.append('timestamp', String(timestamp));
        formData.append('api_key', apiKey);
        formData.append('signature', signature);

        const response = await fetch(
          `https://api.cloudinary.com/v1_1/${cloudName}/image/destroy`,
          { method: 'POST', body: formData }
        );
        const result = await response.json();
        if (result.result === 'ok' || result.result === 'not found') {
          return json({ ok: true, result: result.result }, 200, CORS);
        }
        return json({ error: 'Cloudinary deletion failed', details: result }, 500, CORS);
      } catch (e: any) {
        return json({ error: 'Deletion failed: ' + String(e.message || e) }, 500, CORS);
      }
    }

    // ==================== TABLES ====================

    if (path === '/admin/tables' && method === 'GET') {
      const a: any = await getAdmin(request, env);
      if (!a) return json({ error: 'Unauthorized' }, 401, CORS);
      const tables = await env.DB.prepare(
        'SELECT number, pin, session_count FROM tables WHERE rid=? ORDER BY CAST(number AS INTEGER)'
      ).bind(a.rid).all();
      const origin = url.origin;
      const urls = await Promise.all((tables.results as any[]).map(async (t) => {
        const k = await sign(a.slug, t.number, env.SUPER_KEY);
        return {
          number: t.number,
          pin: t.pin,
          session_count: t.session_count || 0,
          url: `${origin}/?r=${a.slug}&t=${t.number}&k=${k}`,
        };
      }));
      return json(urls, 200, CORS);
    }

    if (path === '/admin/tables/regenerate' && method === 'POST') {
      const a: any = await getAdmin(request, env);
      if (!a) return json({ error: 'Unauthorized' }, 401, CORS);
      const b: any = await request.json();
      const count = parseInt(b.count);

      const existing = await env.DB.prepare(
        'SELECT number FROM tables WHERE rid=? ORDER BY CAST(number AS INTEGER) LIMIT ?'
      ).bind(a.rid, count).all();

      const numbers = (existing.results as any[]).map(r => String(r.number));
      await env.DB.prepare('DELETE FROM tables WHERE rid=?').bind(a.rid).run();

      for (const num of numbers) {
        const pin = await generateUniquePin(env, a.rid);
        await env.DB.prepare(
          'INSERT INTO tables (rid, number, pin, session_count) VALUES (?,?,?,0)'
        ).bind(a.rid, num, pin).run();
      }

      await env.DB.prepare(
        'UPDATE restaurants SET table_count=? WHERE id=?'
      ).bind(numbers.length, a.rid).run();
      return json({ ok: true, count: numbers.length }, 200, CORS);
    }

    if (path === '/admin/tables/pin' && method === 'POST') {
      const a: any = await getAdmin(request, env);
      if (!a) return json({ error: 'Unauthorized' }, 401, CORS);
      const b: any = await request.json();
      if (!b.number || !b.pin) return json({ error: 'number and pin required' }, 400, CORS);
      if (!/^\d{4}$/.test(String(b.pin)))
        return json({ error: 'PIN must be exactly 4 digits' }, 400, CORS);
      await env.DB.prepare(
        'UPDATE tables SET pin=? WHERE rid=? AND number=?'
      ).bind(String(b.pin), a.rid, String(b.number)).run();
      return json({ ok: true }, 200, CORS);
    }

    if (path === '/admin/tables/add' && method === 'POST') {
      const a: any = await getAdmin(request, env);
      if (!a) return json({ error: 'Unauthorized' }, 401, CORS);
      const existing = await env.DB.prepare(
        'SELECT number FROM tables WHERE rid=?'
      ).bind(a.rid).all();
      const nums = (existing.results as any[]).map(r => parseInt(r.number));
      const next = nums.length ? Math.max(...nums) + 1 : 1;
      const pin = await generateUniquePin(env, a.rid);
      await env.DB.prepare(
        'INSERT INTO tables (rid, number, pin, session_count) VALUES (?,?,?,0)'
      ).bind(a.rid, String(next), pin).run();
      await env.DB.prepare(
        'UPDATE restaurants SET table_count=(SELECT COUNT(*) FROM tables WHERE rid=?) WHERE id=?'
      ).bind(a.rid, a.rid).run();
      return json({ ok: true, number: next, pin }, 200, CORS);
    }

    if (path === '/admin/tables/remove' && method === 'POST') {
      const a: any = await getAdmin(request, env);
      if (!a) return json({ error: 'Unauthorized' }, 401, CORS);
      const b: any = await request.json();
      if (!b.number) return json({ error: 'number required' }, 400, CORS);
      await env.DB.prepare(
        'DELETE FROM tables WHERE rid=? AND number=?'
      ).bind(a.rid, String(b.number)).run();
      await env.DB.prepare(
        'UPDATE restaurants SET table_count=(SELECT COUNT(*) FROM tables WHERE rid=?) WHERE id=?'
      ).bind(a.rid, a.rid).run();
      return json({ ok: true }, 200, CORS);
    }

    // ==================== SETTINGS ====================

    if (path === '/admin/settings' && method === 'GET') {
      const a: any = await getAdmin(request, env);
      if (!a) return json({ error: 'Unauthorized' }, 401, CORS);
      const r = await env.DB.prepare(
        'SELECT slug, name, name_urdu, address, phone, google_place_id, table_count, pin_enabled, currency, cloud_name, upload_preset FROM restaurants WHERE id=?'
      ).bind(a.rid).first();
      return json(r, 200, CORS);
    }

    if (path === '/admin/settings' && method === 'PUT') {
      const a: any = await getAdmin(request, env);
      if (!a) return json({ error: 'Unauthorized' }, 401, CORS);
      const b: any = await request.json();
      await env.DB.prepare(
        'UPDATE restaurants SET name=?, name_urdu=?, address=?, phone=?, google_place_id=?, pin_enabled=?, currency=?, cloud_name=?, upload_preset=? WHERE id=?'
      ).bind(b.name, b.name_urdu || '', b.address || '', b.phone || '',
        b.google_place_id || '', b.pin_enabled ? 1 : 0, b.currency || 'Rs',
        b.cloud_name || '', b.upload_preset || '', a.rid).run();
      return json({ ok: true }, 200, CORS);
    }

    // ==================== REQUESTS ====================

    if (path === '/admin/requests' && method === 'GET') {
      const a: any = await getAdmin(request, env);
      if (!a) return json({ error: 'Unauthorized' }, 401, CORS);
      const r = await env.DB.prepare(
        'SELECT * FROM requests WHERE rid=? AND done=0 ORDER BY id DESC'
      ).bind(a.rid).all();
      return json(r.results, 200, CORS);
    }

    m = path.match(/^\/admin\/requests\/(\d+)$/);
    if (m && method === 'PATCH') {
      const a: any = await getAdmin(request, env);
      if (!a) return json({ error: 'Unauthorized' }, 401, CORS);
      await env.DB.prepare(
        'UPDATE requests SET done=1 WHERE id=? AND rid=?'
      ).bind(m[1], a.rid).run();
      return json({ ok: true }, 200, CORS);
    }

    // ==================== SUPER ADMIN ====================

    if (path === '/super/restaurant' && method === 'POST') {
      if (request.headers.get('X-Super-Key') !== env.SUPER_KEY)
        return json({ error: 'Forbidden' }, 403, CORS);
      const b: any = await request.json();
      if (!b.slug || !b.name || !b.password)
        return json({ error: 'slug, name, password required' }, 400, CORS);

      try {
        const hash = await sha(b.password);
        const r: any = await env.DB.prepare(
          'INSERT INTO restaurants (slug, name, name_urdu, address, phone, google_place_id, table_count, pin_enabled, currency, password_hash, cloud_name, upload_preset) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)'
        ).bind(b.slug, b.name, b.name_urdu || '', b.address || '',
          b.phone || '', b.google_place_id || '', b.table_count || 10,
          1, b.currency || 'Rs', hash, b.cloud_name || '',
          b.upload_preset || '').run();

        const rid = r.meta.last_row_id;
        for (let i = 1; i <= (b.table_count || 10); i++) {
          const pin = String(Math.floor(1000 + Math.random() * 9000));
          await env.DB.prepare(
            'INSERT INTO tables (rid, number, pin, session_count) VALUES (?,?,?,0)'
          ).bind(rid, String(i), pin).run();
        }
        return json({ ok: true, slug: b.slug }, 200, CORS);
      } catch (e: any) {
        if (String(e).includes('UNIQUE'))
          return json({ error: 'Slug already exists' }, 409, CORS);
        return json({ error: 'Create failed: ' + String(e) }, 500, CORS);
      }
    }

    if (path === '/health') return json({ ok: true }, 200, CORS);
    return json({ error: 'Not found', path }, 404, CORS);
  } catch (e: any) {
    return json({ error: String(e?.message || e) }, 500, CORS);
  }
};
