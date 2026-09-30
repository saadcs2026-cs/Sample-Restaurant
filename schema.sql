CREATE TABLE IF NOT EXISTS restaurants (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slug TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  name_urdu TEXT,
  address TEXT,
  phone TEXT,
  google_place_id TEXT,
  table_count INTEGER DEFAULT 10,
  pin_enabled INTEGER DEFAULT 1,
  currency TEXT DEFAULT 'Rs',
  password_hash TEXT NOT NULL,
  cloud_name TEXT,
  upload_preset TEXT
);

CREATE TABLE IF NOT EXISTS menu_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  rid INTEGER NOT NULL,
  name TEXT NOT NULL,
  name_urdu TEXT,
  description TEXT,
  description_urdu TEXT,
  price REAL NOT NULL,
  category TEXT NOT NULL,
  category_urdu TEXT,
  image_url TEXT,
  available INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS tables (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  rid INTEGER NOT NULL,
  number TEXT NOT NULL,
  pin TEXT,
  UNIQUE(rid, number)
);

CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  rid INTEGER NOT NULL,
  table_num TEXT NOT NULL,
  session TEXT,
  status TEXT DEFAULT 'pending',
  total REAL DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS order_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id INTEGER NOT NULL,
  item_id INTEGER NOT NULL,
  qty INTEGER NOT NULL,
  price REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  rid INTEGER NOT NULL,
  table_num TEXT NOT NULL,
  type TEXT NOT NULL,
  done INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
