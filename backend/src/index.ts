import 'dotenv/config';
import express, { Request, Response, NextFunction } from 'express';
import cors, { CorsOptions } from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import multer from 'multer';
import path from 'node:path';
import fs from 'node:fs';
import bcrypt from 'bcrypt';
import { createHmac, timingSafeEqual, randomUUID } from 'node:crypto';
import sharp from 'sharp';

import cloudinary, { type UploadApiResponse } from './cloudinary';
import { prisma } from './db';
import { updateProductSchema } from './validation';

import { createClient } from 'redis';
import RedisStore from 'connect-redis';

/**
 * ============================
 * Express App & Constants
 * ============================
 */
const app = express();
const PORT = Number(process.env.PORT || 3000);
const FRONT_ORIGIN = process.env.FRONT_ORIGIN || 'https://arquiabba-web.vercel.app';
const UPLOAD_DIR = path.join(process.cwd(), 'uploads');
const CSRF_SECRET = process.env.CSRF_SECRET || 'super-secret-key-change-me-in-production';

console.log('--- Iniciando configuración de Redis ---');
console.log('Intentando conectar con la URL de Redis:', process.env.REDIS_URL ? 'URL encontrada' : '¡URL NO ENCONTRADA!');

// Inicializa el cliente de Redis
const redisClient = createClient({
  url: process.env.REDIS_URL, // Usaremos una variable de entorno
});

redisClient.on('error', (err) => console.error('--- ERROR DEL CLIENTE DE REDIS ---', err));
redisClient.on('connect', () => console.log('--- Conectando a Redis... ---'));
redisClient.on('ready', () => console.log('%c--- ¡ÉXITO! Conexión con Redis establecida y lista. ---', 'color: green'));

redisClient.connect().catch(console.error);

const RedisStoreClass = RedisStore(session);

// Inicializa el almacén de sesiones de Redis
const redisStore = new RedisStoreClass({
  client: redisClient,
  prefix: 'myapp:',
});


/**
 * ============================
 * Middlewares Globales
 * ============================
 */
app.set('trust proxy', 1);

const corsOptions: CorsOptions = {
  origin: [FRONT_ORIGIN, 'http://localhost:4200'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
};

app.use(helmet());
app.use(cors(corsOptions));
app.use(rateLimit({ windowMs: 60_000, max: 120 }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(
  session({
    store: redisStore, // Le decimos a express-session que use Redis
    secret: process.env.SESSION_SECRET || 'change-me-to-a-strong-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: true,
      httpOnly: true,
      sameSite: 'none',
      maxAge: 24 * 60 * 60 * 1000, // 1 día
    },
  })
);

app.use('/api/', (_req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});

/**
 * ============================
 * Lógica y Helpers de Seguridad
 * ============================
 */

// --- Lógica CSRF (Stateless) ---
function createCsrfHash(token: string) {
  return createHmac('sha256', CSRF_SECRET).update(token).digest('hex');
}

function requireCsrf(req: Request, res: Response, next: NextFunction) {
  const tokenFromHeader = req.header('x-csrf-token');
  const hashFromCookie = req.cookies['x-csrf-token-hash'];

  if (!tokenFromHeader || !hashFromCookie) {
    return res.status(403).json({ error: 'CSRF token or hash cookie missing' });
  }

  const expectedHash = createCsrfHash(tokenFromHeader);

  try {
    if (!timingSafeEqual(Buffer.from(hashFromCookie), Buffer.from(expectedHash))) {
      return res.status(403).json({ error: 'CSRF token invalid' });
    }
  } catch (e) {
    return res.status(403).json({ error: 'CSRF token invalid' });
  }

  next();
}

// --- Auth Helpers ---
function requireAuth(req: any, res: Response, next: NextFunction) {
  if (req.session?.uid) return next();
  return res.status(401).json({ error: 'Unauthenticated' });
}

function requireRole(role: 'ADMIN' | 'USER') {
  return (req: any, res: Response, next: NextFunction) => {
    if (req.session?.role === role) return next();
    return res.status(403).json({ error: 'Forbidden' });
  };
}

// --- Multer (File Uploads) ---
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
const fileFilter: import('multer').Options['fileFilter'] = (_req, file, cb) => {
  const ok = ['image/png', 'image/jpeg', 'image/webp', 'image/avif'].includes(file.mimetype);
  return ok ? cb(null, true) : cb(new Error('Invalid image type') as any);
};
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter,
});


/**
 * ============================
 * RUTAS DE LA APLICACIÓN
 * ============================
 */

// --- Rutas Públicas y de Autenticación (Exentas de CSRF) ---
app.get('/api/health', (_req: Request, res: Response) => res.json({ ok: true, ts: new Date().toISOString() }));

app.post('/api/auth/login', async (req: any, res) => {
  const { email, password } = req.body ?? {};
  if (!email || !password) return res.status(400).json({ error: 'email and password are required' });

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

  req.session.uid = user.id;
  req.session.role = user.role;

  const csrfToken = randomUUID();
  const csrfHash = createCsrfHash(csrfToken);

  res.cookie('x-csrf-token-hash', csrfHash, {
    secure: true,
    sameSite: 'none',
    path: '/',
    maxAge: 24 * 60 * 60 * 1000,
  });

  res.json({ ok: true, csrfToken: csrfToken });
});

app.post('/api/auth/logout', (req: any, res: Response) => {
  res.clearCookie('x-csrf-token-hash', { path: '/' });
  res.clearCookie('connect.sid');

  if (req.session) {
    req.session.destroy((err: any) => {
      if (err) console.error('Error al destruir la sesión:', err);
      return res.status(204).send();
    });
  } else {
    return res.status(204).send();
  }
});

// --- Rutas Protegidas ---
app.get('/api/auth/me', requireAuth, async (req: any, res) => {
  const me = await prisma.user.findUnique({
    where: { id: req.session.uid },
    select: { id: true, email: true, role: true },
  });
  res.json(me);
});

// --- Rutas de Productos (Públicas y Protegidas) ---
app.get('/api/products', async (_req, res) => {
  const items = await prisma.product.findMany({ orderBy: { createdAt: 'desc' } });
  res.json(items);
});

app.get('/api/products/:id', async (req, res) => {
  const item = await prisma.product.findUnique({ where: { id: req.params.id } });
  if (!item) return res.status(404).json({ error: 'Not found' });
  res.json(item);
});

app.post(
  '/api/products',
  requireAuth,
  requireRole('ADMIN'),
  upload.single('image'),
  requireCsrf,
  async (req: Request, res: Response) => {
    try {
      const { name, description = '', price, imageUrl } = req.body as {
        name?: string; description?: string; price?: string | number; imageUrl?: string;
      };
      if (!name || price === undefined || price === null) {
        return res.status(400).json({ error: 'name and price are required' });
      }

      let url: string | null = null;
      if (req.file) {
        const buf = await sharp(req.file.buffer).rotate().resize({ width: 1200, withoutEnlargement: true }).webp({ quality: 85 }).toBuffer();
        const filename = randomUUID();
        url = await new Promise<string>((resolve, reject) => {
          const stream = cloudinary.uploader.upload_stream(
            { folder: 'products', public_id: filename, overwrite: true, resource_type: 'image' },
            (err, result?: UploadApiResponse) => {
              if (err || !result?.secure_url) return reject(err ?? new Error('Upload failed'));
              resolve(result.secure_url);
            }
          );
          stream.end(buf);
        });
      } else if (imageUrl) {
        url = imageUrl.trim();
      } else {
        return res.status(400).json({ error: 'image is required (file or imageUrl)' });
      }

      const created = await prisma.product.create({
        data: { name, description, price: Number(price), imageUrl: url },
      });
      return res.status(201).json(created);
    } catch (e: any) {
      console.error(e);
      return res.status(400).json({ error: e?.message ?? 'bad request' });
    }
  }
);

app.put(
  '/api/products/:id',
  requireAuth,
  requireRole('ADMIN'),
  upload.single('image'),
  requireCsrf,
  async (req: Request, res: Response) => {
    try {
      const id = req.params.id;
      const parsed = updateProductSchema.safeParse(req.body);
      if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });

      const current = await prisma.product.findUnique({ where: { id } });
      if (!current) return res.status(404).json({ error: 'Not found' });

      let imageUrl = current.imageUrl;
      if (req.file) {
        const buf = await sharp(req.file.buffer).rotate().resize({ width: 1200, withoutEnlargement: true }).webp({ quality: 85 }).toBuffer();
        const filename = randomUUID();
        imageUrl = await new Promise<string>((resolve, reject) => {
          const stream = cloudinary.uploader.upload_stream(
            { folder: 'products', public_id: filename, overwrite: true, resource_type: 'image' },
            (err, result?: UploadApiResponse) => {
              if (err || !result?.secure_url) return reject(err ?? new Error('Upload failed'));
              resolve(result.secure_url);
            }
          );
          stream.end(buf);
        });
      } else if (typeof (req.body as any).imageUrl === 'string' && (req.body as any).imageUrl.trim() !== '') {
        imageUrl = (req.body as any).imageUrl.trim();
      }

      const data: Record<string, any> = {};
      if (parsed.data.name !== undefined) data.name = parsed.data.name;
      if (parsed.data.description !== undefined) data.description = parsed.data.description;
      if (parsed.data.price !== undefined) data.price = parsed.data.price;
      data.imageUrl = imageUrl;
      
      const updated = await prisma.product.update({ where: { id }, data });
      return res.json(updated);
    } catch (e: any) {
      console.error(e);
      return res.status(400).json({ error: e?.message ?? 'bad request' });
    }
  }
);

app.delete(
  '/api/products/:id',
  requireAuth,
  requireRole('ADMIN'),
  requireCsrf,
  async (req, res) => {
    const id = req.params.id;
    const current = await prisma.product.findUnique({ where: { id } });
    if (!current) return res.status(404).json({ error: 'Not found' });

    await prisma.product.delete({ where: { id } });
    if (current.imageUrl?.startsWith('/uploads/')) {
      const p = path.join(UPLOAD_DIR, path.basename(current.imageUrl));
      fs.unlink(p, () => {});
    }
    res.status(204).send();
  }
);


/**
 * ============================
 * Server Start
 * ============================
 */
app.listen(PORT, () => {
  console.log(`API running on http://localhost:${PORT}`);
});