import 'dotenv/config';
import express, { Request, Response, NextFunction } from 'express';
import cors, { CorsOptions } from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import { createClient } from 'redis';
import * as connectRedis from 'connect-redis';
import multer from 'multer';
import path from 'node:path';
import fs from 'node:fs';
import bcrypt from 'bcrypt';
import { createHmac, timingSafeEqual, randomUUID } from 'node:crypto';
import sharp from 'sharp';

import cloudinary, { type UploadApiResponse } from './cloudinary';
import { prisma } from './db';
import { updateProductSchema } from './validation';

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


/**
 * ============================
 * Middlewares Globales
 * ============================
 */

app.set('trust proxy', 1);

// --- Configuración de CORS Corregida ---
const corsOptions: CorsOptions = {
  // Orígenes permitidos. El valor de FRONT_ORIGIN se toma de tus variables de entorno.
  origin: [FRONT_ORIGIN, 'http://localhost:4200'],
  
  // Permite que el navegador envíe cookies y cabeceras de autorización.
  credentials: true,
  
  // Cabeceras personalizadas que tu aplicación utiliza y deben ser permitidas.
  allowedHeaders: [
    'Content-Type', 
    'Authorization', 
    'x-csrf-token' // ¡Esta es la cabecera clave que faltaba!
  ],
  
  // Métodos HTTP permitidos por tu API.
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
};

app.use(cors(corsOptions));

// Es buena práctica que las peticiones OPTIONS respondan rápido.
app.options('*', cors(corsOptions)); 

//app.use(helmet());
app.use(rateLimit({ windowMs: 60_000, max: 120 }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

/**
 * ============================
 * Configuración de Sesión con Redis
 * ============================
 */

// 1. Usa la importación por defecto estándar. Es la forma correcta.
import RedisStore from 'connect-redis';

// 2. Crea el cliente de Redis y conéctalo.
const redisClient = createClient({ url: process.env.REDIS_URL });
redisClient.connect().catch(console.error);

// 3. Instancia la tienda directamente.
const redisStore = new RedisStore({
    client: redisClient,
    prefix: 'myapp:',
});

// 4. Usamos la tienda en el middleware de la sesión (sin cambios aquí)
app.use(
  session({
    store: redisStore,
    secret: process.env.SESSION_SECRET || 'change-me-to-a-strong-secret',
    resave: false,
    saveUninitialized: false,
    cookie: { 
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true, 
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 24 * 60 * 60 * 1000 
    },
  })
);


/**
 * ============================
 * Lógica y Helpers de Seguridad
 * ============================
 */
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

// --- Rutas de Productos Públicas ---
app.get('/api/products', async (_req, res) => {
  const items = await prisma.product.findMany({ orderBy: { createdAt: 'desc' } });
  res.json(items);
});

app.get('/api/products/:id', async (req, res) => {
  const item = await prisma.product.findUnique({ where: { id: req.params.id } });
  if (!item) return res.status(404).json({ error: 'Not found' });
  res.json(item);
});

// --- Rutas Protegidas ---
app.get('/api/auth/me', requireAuth, async (req: any, res) => {
  const me = await prisma.user.findUnique({
    where: { id: req.session.uid },
    select: { id: true, email: true, role: true },
  });
  res.json(me);
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
 * Arranque del Servidor Robusto
 * ============================
 */
async function startServer() {
  try {
    redisClient.on('error', (err) => {
      console.error('Error de Conexión con Redis:', err);
    });

    await redisClient.connect();
    console.log('Conexión con Redis establecida.');

    app.listen(PORT, () => {
      console.log(`Servidor escuchando en el puerto ${PORT}`);
    });
  } catch (err) {
    console.error('Fallo al iniciar el servidor:', err);
    process.exit(1);
  }
}

startServer();