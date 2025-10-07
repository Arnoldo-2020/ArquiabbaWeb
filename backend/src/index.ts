import 'dotenv/config';
import express, { Request, Response, NextFunction } from 'express';
import cors, { CorsOptions } from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';
import cookieSession from 'cookie-session';
import multer from 'multer';
import path from 'node:path';
import fs from 'node:fs';
import bcrypt from 'bcrypt';
import { randomUUID } from 'node:crypto';
import sharp from 'sharp';
import cloudinary, { type UploadApiResponse } from './cloudinary';
import { prisma } from './db';
import { createProductSchema, updateProductSchema } from './validation';

/**
 * ============================
 * Express App & Constants
 * ============================
 */
const app = express();
const PORT = Number(process.env.PORT || 3000);
const UPLOAD_DIR = path.join(process.cwd(), 'uploads');
const CSRF_COOKIE = process.env.CSRF_COOKIE || 'csrfToken';
const FRONT_ORIGIN = process.env.FRONT_ORIGIN || 'https://arquiabba-web.vercel.app';
const CURRENCY = process.env.CURRENCY || 'EUR';

/**
 * ============================
 * PROXY & SECURITY
 * ============================
 */
app.set('trust proxy', 1);

/**
 * ============================
 * Middlewares base (orden)
 * ============================
 */

// 1. Helmet para cabeceras de seguridad
app.use(helmet());

// 2. CORS (configuración robusta y centralizada)
const corsOptions: CorsOptions = {
  origin: ['http://localhost:4200', FRONT_ORIGIN], // Orígenes permitidos
  credentials: true, // Permitir cookies y encabezados de autorización
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
};
app.use(cors(corsOptions));

// 3. Rate Limiter
app.use(rateLimit({ windowMs: 60_000, max: 120, standardHeaders: true, legacyHeaders: false }));

// 4. Parsers (Cookies y JSON)
app.use(cookieParser());
app.use(cookieSession({
  name: 'session',
  secret: process.env.SESSION_SECRET || 'change-me',
  sameSite: 'none',
  secure: true,
  httpOnly: true,
  maxAge: 24 * 60 * 60 * 1000,
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 5. No-cache para respuestas de API
app.use('/api/', (_req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  next();
});

// (Opcional) Logging de peticiones
app.use((req, _res, next) => {
  if (req.path.startsWith('/api/')) {
    console.log(`[req] ${req.method} ${req.path}`);
  }
  next();
});

/**
 * ============================
 * Preparar carpeta local de uploads
 * ============================
 */
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

/**
 * ============================
 * Multer (memoria) + filtro de imagen
 * ============================
 */
const fileFilter: import('multer').Options['fileFilter'] = (_req, file, cb) => {
  const ok = ['image/png', 'image/jpeg', 'image/webp', 'image/avif'].includes(file.mimetype);
  return ok ? cb(null, true) : cb(new Error('Invalid image type') as any);
};
export const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter,
});

/**
 * ============================
 * Health
 * ============================
 */
app.get('/api/health', (_req: Request, res: Response) => {
  res.json({ ok: true, ts: new Date().toISOString() });
});

/**
 * ============================
 * CSRF (doble cookie)
 * ============================
 */
function requireCsrf(req: Request, res: Response, next: NextFunction) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  if (
    req.path === '/api/auth/login' ||
    req.path === '/api/auth/logout' ||
    req.path.startsWith('/api/paypal/')
  ) return next();
    
  const cookie = (req as any).cookies?.[CSRF_COOKIE];
  const header = req.header('x-csrf-token');
    
  if (!cookie || !header || cookie !== header) {
    return res.status(403).json({ error: 'CSRF token invalid' });
  }
  next();
}
app.use(requireCsrf);

/**
 * ============================
 * Auth helpers
 * ============================
 */
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

/**
 * ============================
 * Auth routes
 * ============================
 */
app.post('/api/auth/login', async (req: any, res) => {
  const { email, password } = req.body ?? {};
  if (!email || !password) return res.status(400).json({ error: 'email and password are required' });

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

  req.session = { uid: user.id, role: user.role };

  const csrf = Math.random().toString(36).slice(2);
  res.cookie(CSRF_COOKIE, csrf, {
    sameSite: 'none',
    secure: true,
    httpOnly: false,
    path: '/',
  });

  res.json({ ok: true, csrfToken: csrf });
});

app.post('/api/auth/logout', (req: any, res) => {
  req.session = null;
  res.clearCookie(CSRF_COOKIE, { path: '/' });
  res.status(204).send();
});

app.get('/api/auth/me', requireAuth, async (req: any, res) => {
  const me = await prisma.user.findUnique({
    where: { id: req.session.uid },
    select: { id: true, email: true, role: true },
  });
  res.json(me);
});

/**
 * ============================
 * Productos (públicos)
 * ============================
 */
app.get('/api/products', async (_req, res) => {
  const items = await prisma.product.findMany({ orderBy: { createdAt: 'desc' } });
  res.json(items);
});

app.get('/api/products/:id', async (req, res) => {
  const item = await prisma.product.findUnique({ where: { id: req.params.id } });
  if (!item) return res.status(404).json({ error: 'Not found' });
  res.json(item);
});

/**
 * ============================
 * Rutas de Admin (resto del CRUD)
 * ============================
 */
// ... (el resto de tus rutas de productos y PayPal pueden permanecer sin cambios)
app.post('/api/products', requireAuth, requireRole('ADMIN'), upload.single('image'), async (req: Request, res: Response) => {
  try {
    const { name, description = '', price, imageUrl } = req.body as {
      name?: string; description?: string; price?: string | number; imageUrl?: string;
    };
    if (!name || price === undefined || price === null) {
      return res.status(400).json({ error: 'name and price are required' });
    }

    let url: string | null = null;
    if (req.file) {
      const buf = await sharp(req.file.buffer)
        .rotate()
        .resize({ width: 1200, withoutEnlargement: true })
        .webp({ quality: 85 })
        .toBuffer();

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
});

app.put('/api/products/:id', requireAuth, requireRole('ADMIN'), upload.single('image'), async (req: Request, res: Response) => {
  try {
    const id = req.params.id;
    const parsed = updateProductSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });

    const current = await prisma.product.findUnique({ where: { id } });
    if (!current) return res.status(404).json({ error: 'Not found' });

    let imageUrl = current.imageUrl;
    if (req.file) {
      const buf = await sharp(req.file.buffer)
        .rotate()
        .resize({ width: 1200, withoutEnlargement: true })
        .webp({ quality: 85 })
        .toBuffer();
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
});

app.delete('/api/products/:id', requireAuth, requireRole('ADMIN'), async (req, res) => {
  const id = req.params.id;
  const current = await prisma.product.findUnique({ where: { id } });
  if (!current) return res.status(404).json({ error: 'Not found' });

  await prisma.product.delete({ where: { id } });
  if (current.imageUrl?.startsWith('/uploads/')) {
    const p = path.join(UPLOAD_DIR, path.basename(current.imageUrl));
    fs.unlink(p, () => {});
  }
  res.status(204).send();
});


// Arrancar
app.listen(PORT, () => {
  console.log(`API running on http://localhost:${PORT}`);
});