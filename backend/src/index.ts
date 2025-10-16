import express, { Request, Response, NextFunction } from 'express';
import session from 'express-session';
import RedisStoreLib from 'connect-redis';
import { createClient } from 'redis';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import cookieParser from 'cookie-parser';
import multer from 'multer';
import jwt from 'jsonwebtoken';
import { v2 as cloudinary } from 'cloudinary';
import { CloudinaryStorage } from 'multer-storage-cloudinary';
import { prisma } from './db';

// =============================
// 🔧 CONFIGURACIÓN BASE
// =============================
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// =============================
// 🔐 REDIS + SESIONES
// =============================
const redisClient = createClient({ url: process.env.REDIS_URL });
redisClient.on('error', (err) => console.error('Redis Client Error:', err));

// @ts-ignore - Se ignora el falso error de tipos de connect-redis
const RedisStore = new (RedisStoreLib as any)({
  client: redisClient,
  prefix: 'session:',
});

// ✅ Tipado de sesión extendido
declare module 'express-session' {
  interface SessionData {
    userId: string;
    role: string;
  }
}

// =============================
// 🌍 CORS
// =============================
app.use(
  cors({
    origin: [
      process.env.FRONT_ORIGIN || 'http://localhost:4200',
      'http://localhost:8100',
    ],
    credentials: true,
  })
);

// =============================
// 📦 SESIÓN
// =============================
app.use(
  session({
    store: RedisStore,
    secret: process.env.SESSION_SECRET || 'super-secret-session',
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 24 * 60 * 60 * 1000,
    },
  })
);

// =============================
// ☁️ SUBIDA DE IMÁGENES A CLOUDINARY
// =============================
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'products', // Nombre de la carpeta en Cloudinary
    allowed_formats: ['jpeg', 'png', 'jpg', 'webp'],
    transformation: [{ width: 800, height: 800, crop: 'limit' }],
  } as any,
});

const upload = multer({ storage });

// =============================
// 🧱 MIDDLEWARE DE AUTENTICACIÓN
// =============================
function requireAuth(req: Request, res: Response, next: NextFunction) {
  // 1️⃣ Sesión activa
  if (req.session?.userId) {
    (req as any).user = { id: req.session.userId, role: req.session.role };
    return next();
  }

  // 2️⃣ Token Bearer
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    try {
      const token = authHeader.substring(7); // eliminar "Bearer "
      const decoded = jwt.verify(
        token,
        process.env.JWT_SECRET || 'supersecret'
      ) as any;

      (req as any).user = { id: decoded.id, role: decoded.role };
      return next();
    } catch (err) {
      console.error('JWT verification failed:', err);
      return res.status(401).json({ error: 'Token inválido o expirado' });
    }
  }

  // 3️⃣ Ninguno
  return res.status(401).json({ error: 'No autorizado' });
}

// =============================
// 🔑 LOGIN ADMIN
// =============================
app.post('/api/auth/login', async (req: Request, res: Response) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'Email y contraseña requeridos' });

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.status(401).json({ error: 'Credenciales inválidas' });

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return res.status(401).json({ error: 'Credenciales inválidas' });

  // Guardar sesión
  req.session.userId = String(user.id);
  req.session.role = user.role ?? 'user';

  // Crear JWT
  const token = jwt.sign(
    { id: user.id, role: user.role },
    process.env.JWT_SECRET || 'supersecret',
    { expiresIn: '2h' }
  );

  res.json({
    message: 'Login exitoso',
    token,
  });
});

// =============================
// 👤 OBTENER USUARIO LOGUEADO
// =============================
app.get('/api/auth/me', requireAuth, async (req: Request, res: Response) => {
  try {
    const userData = (req as any).user;
    if (!userData?.id) {
      return res.status(401).json({ error: 'No autenticado' });
    }

    const user = await prisma.user.findUnique({
      where: { id: userData.id },
      select: { id: true, email: true, role: true },
    });

    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
    res.json(user);
  } catch (err) {
    console.error('Error en /auth/me:', err);
    res.status(500).json({ error: 'Error obteniendo usuario' });
  }
});

// =============================
// 🧾 PRODUCTOS
// =============================
app.get('/api/products', async (_req: Request, res: Response) => {
  const products = await prisma.product.findMany();
  res.json(products);
});

app.post(
  '/api/products',
  requireAuth,
  upload.single('image'),
  async (req: Request, res: Response) => {
    try {
      const { name, price, description } = req.body;

      // La URL ahora viene directamente de Cloudinary
      if (!req.file) {
        return res.status(400).json({ error: 'La imagen es requerida' });
      }
      const imageUrl = req.file.path;

      const product = await prisma.product.create({
        data: {
          name,
          price: Number(price),
          description,
          imageUrl,
        },
      });

      res.status(201).json(product);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Error al crear producto' });
    }
  }
);

// =============================
// 🚀 INICIO DEL SERVIDOR
// =============================
async function startServer() {
  try {
    await redisClient.connect();
    app.listen(PORT, () => {
      console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
    });
  } catch (err) {
    console.error('Error al iniciar servidor:', err);
  }
}

startServer();

// =============================
// 🧹 CIERRE LIMPIO
// =============================
process.on('SIGTERM', async () => {
  console.log('Cerrando servidor...');
  await prisma.$disconnect();
  await redisClient.quit();
  process.exit(0);
});