import 'dotenv/config';
import express, { Request, Response } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';
import cookieSession from 'cookie-session';
import multer from 'multer';
import path from 'node:path';
import fs from 'node:fs';
import bcrypt from 'bcrypt';
import { v4 as uuid } from 'uuid';


import sharp from 'sharp';
import cloudinary, { type UploadApiResponse } from './cloudinary';
import { randomUUID } from 'node:crypto';

import { prisma } from './db';
import { createProductSchema, updateProductSchema } from './validation';

// ---------- Config ----------
const app = express();

const allowAllOriginsTemporarily = false; // Lo he puesto a false para asegurar que la lista de orígenes funcione.
const ALLOWED_ORIGINS = new Set([
  'http://localhost:4200',
  'https://arquibaba-web.vercel.app', 
  // ¡CORREGIDO! Este es el dominio que estaba dando el error 
  'https://arquiabba-web.vercel.app', // <-- AGREGADO
]);
// La opción cors({ origin: true }) está desactivada, por lo que usamos el middleware manual
app.use((req, res, next) => {
  const origin = (req.headers.origin as string) || '';

  // 1) Decide si permites el origen
  const isAllowed =
    allowAllOriginsTemporarily ||
    !origin ||
    ALLOWED_ORIGINS.has(origin);

  // *IMPORTANTE: La respuesta al preflight (OPTIONS) debe incluir los headers CORS, incluso si es un 204.*
  if (isAllowed) {
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
    res.setHeader(
      'Access-Control-Allow-Headers',
      // reenvía exactamente lo que pide el navegador
      (req.headers['access-control-request-headers'] as string) || 'Content-Type, Authorization'
    );
  }

  // 2) Responder *cualquier* preflight aquí mismo
  if (req.method === 'OPTIONS') {
    // Si isAllowed es true, los headers ya se han establecido arriba
    return res.status(204).end();
  }

  return next();
});

const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;
const UPLOAD_DIR = path.join(process.cwd(), 'uploads');
const CSRF_COOKIE = process.env.CSRF_COOKIE || 'csrfToken';

const PAYPAL_MODE = (process.env.PAYPAL_MODE || 'sandbox').toLowerCase();
const PAYPAL_BASE = PAYPAL_MODE === 'live'
  ?
 'https://api-m.paypal.com'
  : 'https://api-m.sandbox.paypal.com';

const CURRENCY = process.env.CURRENCY || 'EUR';

app.set('trust proxy', 1);
// Desactivar ETag + caché agresiva para respuestas JSON
app.set('etag', false);
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  next();
});
// Consigue un access token OAuth2 de PayPal
async function getPayPalAccessToken() {
  const creds = Buffer.from(`${process.env.PAYPAL_CLIENT_ID}:${process.env.PAYPAL_CLIENT_SECRET}`).toString('base64');
  const resp = await fetch(`${PAYPAL_BASE}/v1/oauth2/token`, {
    method: 'POST',
    headers: {
      'Authorization': `Basic ${creds}`,
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: 'grant_type=client_credentials'
  });
  if (!resp.ok) {
    const txt = await resp.text();
    throw new Error(`PayPal OAuth error: ${resp.status} ${txt}`);
  }

  const data = await resp.json() as { access_token: string };
  return data.access_token;
}

// crea carpeta de uploads si no existe
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

// Se elimina el app.options('*') duplicado ya que el middleware base lo maneja.

// ---------- Middlewares base ----------
//app.use(cors({ origin: true }));
app.use(express.json());
app.use(cookieParser());
app.use(cookieSession({
  name: 'session',
  secret: process.env.SESSION_SECRET!,
  sameSite: 'none', 
  secure: true,  
  httpOnly: true,
  maxAge: 24 * 60 * 60 * 1000,
}));
app.use(helmet());
app.use(rateLimit({ windowMs: 60_000, max: 120 }));



// servir estáticos de imágenes
app.use('/uploads', express.static(UPLOAD_DIR));
// ---------- CSRF (double submit cookie) ----------
function requireCsrf(req: Request, res: Response, next: Function) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  if (req.path === '/api/auth/login' || req.path === '/api/auth/logout' || req.path === '/api/checkout/session' ||
  req.path === '/api/paypal/create-order' ||
  req.path === '/api/paypal/capture-order' || req.path.startsWith('/api/paypal/')) return next();
  const cookie = (req as any).cookies?.[CSRF_COOKIE];
  const header = req.header('x-csrf-token');
  if (!cookie || !header || cookie !== header) {
    return res.status(403).json({ error: 'CSRF token invalid' });
  }
  next();
}
app.use(requireCsrf);

// ---------- Auth helpers ----------
function requireAuth(req: any, res: Response, next: Function) {
  if (req.session?.uid) return next();
  return res.status(401).json({ error: 'Unauthenticated' });
}
function requireRole(role: 'ADMIN' | 'USER') {
  return (req: any, res: Response, next: Function) => {
    if (req.session?.role === role) return next();
    return res.status(403).json({ error: 'Forbidden' });
  };
}

// ---------- Multer (disk storage) ----------
// const storage = multer.diskStorage({
//   destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
//   filename: (_req, file, cb) => {
//     const ext = path.extname(file.originalname) || '';
//     cb(null, `${uuid()}${ext}`);
//   },
// });
// const upload = multer({ storage });

const fileFilter: import('multer').Options['fileFilter'] = (req, file, cb) => {
  const allowed = ['image/png', 'image/jpeg', 'image/webp', 'image/avif'];
  if (allowed.includes(file.mimetype)) {
    return cb(null, true);           
  }

 
  const err = new Error('Invalid image type');
  return cb(err as any);
};

export const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter,
});
// ---------- Health ----------
app.get('/api/health', (_req: Request, res: Response) => {
  res.json({ ok: true, service: 'products-api', ts: new Date().toISOString() });
});
// ---------- Auth routes ----------
app.post('/api/auth/login', async (req: any, res) => {
  const { email, password } = req.body ?? {};
  if (!email || !password) return res.status(400).json({ error: 'email and password are required' });

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

  // crea sesión
  req.session = { uid: user.id, role: user.role };

  // set CSRF cookie (no HttpOnly)
  const csrf = Math.random().toString(36).slice(2);
  res.cookie(CSRF_COOKIE, csrf, {
 
    sameSite: 'lax',
    secure: true, // EN PRODUCCIÓN: Debe ser 'true' si el frontend usa HTTPS.
    httpOnly: false,
    path: '/',
  });

  res.json({ ok: true });
});
app.post('/api/auth/logout', (req: any, res) => {
  req.session = null;
  res.clearCookie(CSRF_COOKIE, { path: '/', sameSite: 'lax' }); // Agregado sameSite para claridad
  res.status(204).send();
});
app.get('/api/auth/me', requireAuth, async (req: any, res) => {
  const me = await prisma.user.findUnique({
    where: { id: req.session.uid },
    select: { id: true, email: true, role: true },
  });
  res.json(me);
});
// ---------- PRODUCTS (GET públicos) ----------
app.get('/api/products', async (_req, res) => {
  const items = await prisma.product.findMany({ orderBy: { createdAt: 'desc' } });
  console.log('LIST COUNT', items.length);
  res.json(items);
});
app.get('/api/products/:id', async (req, res) => {
  const item = await prisma.product.findUnique({ where: { id: req.params.id } });
  if (!item) return res.status(404).json({ error: 'Not found' });
  res.json(item);
});
// ---------- PRODUCTS (mutaciones solo ADMIN) ----------

// Código comentado original de la subida a Cloudinary
// app.post('/api/products', upload.single('image'), async (req: Request, res: Response) => {
//   try {
//     // ... valida req.body con tu zod schema
//     let imageUrl: string | undefined = (req.body.imageUrl as string | undefined)?.trim() || undefined;

//     if (req.file) {
//       // 1) Procesa la imagen en memoria con sharp
//       const buf = await sharp(req.file.buffer)
//         .rotate()
//         .resize({ 
// width: 1600, withoutEnlargement: true })
//         .toFormat('webp', { quality: 82 })
//         .toBuffer();
// //       const filename = randomUUID();
// //       // 2) Sube a Cloudinary usando upload_stream (con tipos correctos)
// //       const url: string = await new Promise<string>((resolve, reject) => {
// //         const stream = cloudinary.uploader.upload_stream(
// //           {
// //             folder: 'products',
// //             public_id: filename,
// //             resource_type: 'image',
// //   
// //           overwrite: true,
// //           },
// //           (err?: Error, result?: UploadApiResponse) => {
// //             if (err) return reject(err);
// //             if (!result || !result.secure_url) {
// //               return reject(new Error('Upload failed'));
// //           
// //   }
// //             resolve(result.secure_url);
// //           }
// //         );
// //         stream.end(buf);
// //       });
// //       imageUrl = url;
// //     }

// //     if (!imageUrl) {
// //       return res.status(400).json({ error: 'Image is required (file or imageUrl)' });
// //     }

//     // ... crea el producto en Prisma con imageUrl
// //     const created = await prisma.product.create({ data: { name: ..., imageUrl, ... } });
// //     console.log('CREATED PRODUCT', created.id);
// //     res.status(201).json(created);
// //     res.status(201).json({ ok: true, imageUrl });
// // <-- temporal, si quieres probar
//   } catch (e: any) {
//     console.error(e);
// //     res.status(400).json({ error: e?.message || 'Bad request' });
//   }
// });
app.post('/api/products', upload.single('image'), async (req: Request, res: Response) => {
  try {
    const { name, description = '', price, imageUrl } = req.body as {
      name?: string; description?: string; price?: string | number; imageUrl?: string;
    };

    if (!name || price === undefined || price === null) {
      return res.status(400).json({ error: 'name and price are required' });
    }

    let url: string | null = null;

    if (req.file) {
      
// 1) Procesa la imagen
      const buf = await sharp(req.file.buffer)
        .rotate()
        .resize({ width: 1200, withoutEnlargement: true })
        .webp({ quality: 85 })
        .toBuffer();
// 2) Sube a Cloudinary
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
      // URL directa opcional
      url = imageUrl;
    } else {
      return res.status(400).json({ error: 'image is required (file or imageUrl)' });
    }

    // 3) Crea en DB
    const created = await prisma.product.create({
      data: {
        name,
        description,
        price: Number(price),
        imageUrl: url,
      },
    });
    console.log('CREATED PRODUCT', created.id);
    return res.status(201).json(created);
  } catch (e: any) {
    console.error(e);
    return res.status(400).json({ error: e?.message ?? 'bad request' });
  }
});

// Código comentado para crear y actualizar que usa disco
// Crear (multipart: campos + image o imageUrl)
// app.post('/api/products', requireAuth, requireRole('ADMIN'), upload.single('image'), async (req, res) => {
//   try {
//     const parsed = createProductSchema.parse(req.body);

//     let imageUrl: string | undefined =
//       (req.body.imageUrl as string | undefined) ?? undefined;
//     if (req.file) imageUrl = `/uploads/${req.file.filename}`;

//     if (!imageUrl) {
//       if (req.file) fs.unlink(path.join(UPLOAD_DIR, req.file.filename), () => {});
//       return res.status(400).json({ error: 'Image 
// is required (image file or imageUrl)' });
//     }

//     const created = await prisma.product.create({
//       data: {
//         name: parsed.name,
//         description: parsed.description,
//         price: parsed.price, // Float en SQLite
//         imageUrl,
//       },
//     });
//     res.status(201).json(created);
//   } catch (err: any) {
//     
// return res.status(400).json({ error: err?.message ?? 'Invalid data' });
//   }
// });
// Actualizar (multipart opcional)
// app.put('/api/products/:id', requireAuth, requireRole('ADMIN'), upload.single('image'), async (req, res) => {
//   try {
//     const parsed = updateProductSchema.parse(req.body);
//     const id = req.params.id;

//     const current = await prisma.product.findUnique({ where: { id } });
//     if (!current) return res.status(404).json({ error: 'Not found' });

//     let imageUrl: string | undefined = current.imageUrl;

//     // prioridad: archivo nuevo > imageUrl texto > conservar actual
//     if (req.file) {
//       imageUrl = `/uploads/${req.file.filename}`;
// 
//       if (current.imageUrl?.startsWith('/uploads/')) {
//         const oldPath = path.join(UPLOAD_DIR, path.basename(current.imageUrl));
//         fs.unlink(oldPath, () => {});
//       }
//     } else if (typeof req.body.imageUrl === 'string' && req.body.imageUrl.trim() !== '') {
//       imageUrl = req.body.imageUrl.trim();
//       if (current.imageUrl?.startsWith('/uploads/')) {
//         const oldPath = path.join(UPLOAD_DIR, path.basename(current.imageUrl));
// //         fs.unlink(oldPath, () => {});
// //       }
//     }

//     const updated = await prisma.product.update({
//       where: { id },
//       data: {
//         name: parsed.name ?? current.name,
//         description: parsed.description ?? current.description,
//         price: parsed.price ?? current.price,
//         imageUrl,
//       },
//     });
// //     res.json(updated);
//   } catch (err: any) {
//     return res.status(400).json({ error: err?.message ?? 'Invalid data' });
// //   }
// });

// Eliminar
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
 * POST /api/paypal/create-order
 * Body: { items: [{ id: string, quantity: number }] }
 * Devuelve { id: orderID }
 */
app.post('/api/paypal/create-order', async (req, res) => {
  try {
    const items = (req.body?.items ?? []) as Array<{ id: string; quantity: number }>;
    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: 'No items' });
    }

    // Verdad desde la DB (no confiar en precios del cliente)
    const ids = items.map(i => i.id);
    const dbItems = 
 await prisma.product.findMany({ where: { id: { in: ids } } });

    let total = 0;
    const paypalItems = items.map(i => {
      const p = dbItems.find(d => d.id === i.id);
      if (!p) throw new Error(`Product not found: ${i.id}`);
      const qty = Math.max(1, Math.min(99, Number(i.quantity) || 1));
      const price = Number(p.price);
      total += price * qty;

      return {
        name: 
 p.name,
        description: p.description?.slice(0, 127),
        unit_amount: { currency_code: CURRENCY, value: price.toFixed(2) },
        quantity: qty.toString(),
        category: 'PHYSICAL_GOODS'
      };
    });

    const accessToken = await getPayPalAccessToken();

    const resp = await fetch(`${PAYPAL_BASE}/v2/checkout/orders`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        intent: 'CAPTURE',
        purchase_units: [{
          amount: {
            currency_code: CURRENCY,
 
            value: total.toFixed(2),
            breakdown: {
              item_total: { currency_code: CURRENCY, value: total.toFixed(2) }
            }
          },
          items: paypalItems
        }],
        application_context: {
     
          brand_name: 'Tu Tienda',
          user_action: 'PAY_NOW',
          landing_page: 'LOGIN'
        }
      })
    });
    if (!resp.ok) {
      const txt = await resp.text();
      throw new Error(`PayPal create error: ${resp.status} ${txt}`);
    }

    const data = await resp.json() as any;
    return res.json({ id: data.id });
// orderID
  } catch (err: any) {
    console.error('PayPal create-order error', err);
    return res.status(400).json({ error: err?.message ?? 'PayPal create error' });
  }
});
/**
 * POST /api/paypal/capture-order
 * Body: { orderID: string }
 * Devuelve { status, captureId, details }
 */
app.post('/api/paypal/capture-order', async (req, res) => {
  try {
    const orderID = req.body?.orderID as string;
    if (!orderID) return res.status(400).json({ error: 'Missing orderID' });

    const accessToken = await getPayPalAccessToken();

    const resp = await fetch(`${PAYPAL_BASE}/v2/checkout/orders/${orderID}/capture`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
     
      }
      // body vacío o {}
    });

    if (!resp.ok) {
      const txt = await resp.text();
      throw new Error(`PayPal capture error: ${resp.status} ${txt}`);
    }

    const data = await resp.json() as any;
    const status = data.status;
    const captureId = data?.purchase_units?.[0]?.payments?.captures?.[0]?.id;

    // TODO: aquí puedes registrar la venta en tu DB
    return res.json({ status, captureId, details: data });
  } catch (err: any) {
    console.error('PayPal capture-order error', err);
    return res.status(400).json({ error: err?.message ?? 'PayPal capture error' });
  }
});
// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`API running on http://localhost:${PORT}`);
});