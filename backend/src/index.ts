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
 *  Express App & Constants
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
 *  PROXY & SECURITY
 * ============================
 * Render/Vercel están detrás de proxy
 * Necesario para que secure cookies funcionen al 100% con HTTPS
 */
app.set('trust proxy', 1);

/**
 * ============================
 *  CORS (con credenciales)
 * ============================
 * Reglas:
 *  - Echo del Origin permitido (no "*") porque usamos cookies (credentials:true)
 *  - Preflight OPTIONS debe devolver 2xx y los headers CORS
 *  - Permitimos front local y el dominio de Vercel
 */
const ALLOWED_ORIGINS = new Set<string>([
  'http://localhost:4200',
  'https://arquibaba-web.vercel.app',
  FRONT_ORIGIN,
]);

function setCorsHeaders(res: import('express').Response, origin: string) {
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Vary', 'Origin'); // para que el CDN no mezcle orígenes
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader(
    'Access-Control-Allow-Methods',
    'GET,POST,PUT,PATCH,DELETE,OPTIONS'
  );
  // reusar lo que pidió el navegador o un set por defecto
  res.setHeader(
    'Access-Control-Allow-Headers',
    (res.req.headers['access-control-request-headers'] as string) ||
      'Content-Type, Authorization, X-CSRF-Token'
  );
}

app.use((req, res, next) => {
  const origin = req.headers.origin as string | undefined;
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    setCorsHeaders(res, origin);
  }

  // Responder TODOS los preflights (OPTIONS) aquí mismo
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  next();
});

// (opcional) logging mínimo para verificar que la petición sí llega a Express
app.use((req, _res, next) => {
  if (req.path.startsWith('/api/')) {
    console.log(`[req] ${req.method} ${req.path}`);
  }
  next();
});

/**
 * ============================
 *  Middlewares base (orden)
 * ============================
 * Importante: CORS antes que cookie-session y parsers.
 */
app.use(helmet());
app.use(rateLimit({ windowMs: 60_000, max: 120 }));
app.use(cookieParser());
app.use(cookieSession({
  name: 'session',
  secret: process.env.SESSION_SECRET || 'change-me',
  sameSite: 'none',   // cookies cross-site
  secure: true,       // obliga HTTPS (Render usa HTTPS)
  httpOnly: true,
  maxAge: 24 * 60 * 60 * 1000,
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// No-cache para respuestas JSON
app.set('etag', false);
app.use((_req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  next();
});

/**
 * ============================
 *  Preparar carpeta local de uploads (solo si existe en este despliegue)
 * ============================
 */
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

/**
 * ============================
 *  Multer (memoria) + filtro de imagen
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
 *  Health
 * ============================
 */
app.get('/api/health', (_req: Request, res: Response) => {
  res.json({ ok: true, ts: new Date().toISOString() });
});

/**
 * ============================
 *  CSRF (doble cookie)
 * ============================
 * Exigimos el header X-CSRF-Token salvo en login/logout y PayPal.
 * Nota: la cookie CSRF debe ser SameSite=None y secure en producción.
 */
function requireCsrf(req: Request, res: Response, next: NextFunction) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  if (
    req.path === '/api/auth/login' ||
    req.path === '/api/auth/logout' ||
    req.path === '/api/paypal/create-order' ||
    req.path === '/api/paypal/capture-order' ||
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
 *  Auth helpers
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
 *  Auth routes
 * ============================
 */
app.post('/api/auth/login', async (req: any, res) => {
  const { email, password } = req.body ?? {};
  if (!email || !password) return res.status(400).json({ error: 'email and password are required' });

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

  // Crear sesión
  req.session = { uid: user.id, role: user.role };

  // Enviar cookie CSRF accesible por JS (para cabecera X-CSRF-Token)
  const csrf = Math.random().toString(36).slice(2);
  res.cookie(CSRF_COOKIE, csrf, {
    sameSite: 'none',
    secure: true,
    httpOnly: false, // debe ser legible por el frontend para enviarla en X-CSRF-Token
    path: '/',
  });

  res.json({ ok: true });
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
 *  Productos (públicos)
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
 *  Crear producto (ADMIN)
 *  - multipart con campo 'image' o campo 'imageUrl'
 *  - sube a Cloudinary con sharp
 * ============================
 */
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

/**
 * ============================
 *  Actualizar producto (ADMIN) - imagen opcional
 * ============================
 */
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

/**
 * ============================
 *  Eliminar producto (ADMIN)
 * ============================
 */
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

/**
 * ============================
 *  PayPal (idéntico a tu versión, omitido por brevedad si no es core del problema de CORS)
 *  -- puedes pegar aquí tus endpoints de PayPal sin cambios si los necesitas --
 * ============================
 */

// Arrancar
app.listen(PORT, () => {
  console.log(`API running on http://localhost:${PORT}`);
});
