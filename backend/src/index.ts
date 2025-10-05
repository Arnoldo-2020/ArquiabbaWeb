import express from 'express';
import cors from 'cors';
import path from 'path';
import cookieSession from 'cookie-session';
import { randomUUID } from 'crypto';
import fs from 'fs';
import sharp from 'sharp';
//import { requireAdmin } from './middlewares';
import cloudinary from './cloudinary';
import { updateProductSchema } from './validation';
import { prisma } from './db';

import { Request } from 'express';
import multer from 'multer';

const app = express();

// Confiar en el proxy (Render)
app.set('trust proxy', 1);

// CORS seguro para Render + Vercel
const isAllowedOrigin = (origin?: string) => {
  if (!origin) return true; // permitir health checks sin origin
  const allowedOrigins = [
    'http://localhost:4200',
    'https://arquibabba-web.vercel.app',
  ];
  try {
    const hostname = new URL(origin).hostname;
    if (allowedOrigins.includes(origin) || /\.vercel\.app$/.test(hostname)) {
      return true;
    }
  } catch {
    return false;
  }
  return false;
};

const corsConfig: cors.CorsOptions = {
  origin(origin, cb) {
    if (isAllowedOrigin(origin)) return cb(null, true);
    return cb(new Error('CORS blocked'), false);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};

app.use(cors(corsConfig));
app.options('*', cors(corsConfig));

// Configuración de sesión segura
app.use(cookieSession({
  name: 'session',
  keys: [process.env.SESSION_SECRET || 'dev_key'],
  httpOnly: true,
  secure: true,
  sameSite: 'none',
}));

type ParamsWithId = { id: string };
type MulterReq = Request<{ id: string }> & { file?: File };

// ---- Multer en memoria ----
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
});

function requireAdmin(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) {
  const user = (req as any)?.session?.user;
  if (!user || user.role !== 'ADMIN') {
    return res.status(401).json({ error: 'admin only' });
  }
  return next();
}

// Middlewares comunes
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rutas de ejemplo
app.get('/', (req, res) => {
  res.json({ message: 'Backend is running correctly.' });
});

// Actualización de productos (ejemplo)
app.put<ParamsWithId>(
  '/api/products/:id',
  requireAdmin,
  upload.single('image'),
  async (req, res) => {
    const mreq = req as MulterReq;          // <- para ver mreq.file sin errores
    const id = req.params.id;               // <- ya es string

    const parsed = updateProductSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.flatten() });
    }
    const { name, description, price } = parsed.data;

    let imageUrl: string | undefined;

    if (mreq.file) {
      const temp = path.join(process.cwd(), 'uploads', `${randomUUID()}.webp`);
      await sharp(mreq.file.path).resize(1200).webp({ quality: 86 }).toFile(temp);
      try {
        const result = await cloudinary.uploader.upload(temp, { folder: 'products' });
        imageUrl = result.secure_url;
      } finally {
        try { fs.unlinkSync(temp); } catch {}
      }
    } else if (req.body?.imageUrl) {
      imageUrl = String(req.body.imageUrl);
    }

    // si la imagen NO es obligatoria en update, no valides esto
    // si quieres hacerla obligatoria, descomenta lo de abajo:
    // if (!imageUrl) return res.status(400).json({ error: 'image is required (file or imageUrl)' });

    const product = await prisma.product.update({
      where: { id },
      data: {
        name,
        description,
        price: Number(price),
        ...(imageUrl ? { imageUrl } : {}),   // <- solo si llega
      },
    });

    return res.json({ ok: true, product });
  }
);

// Manejo de errores
app.use((err: any, req: any, res: any, next: any) => {
  console.error(err);
  res.status(500).json({ error: err.message || 'Internal server error' });
});

// Exportar app
export default app;
