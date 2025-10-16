import express, { Request, Response, NextFunction } from 'express';
import session from 'express-session';
import RedisStoreLib from 'connect-redis';
import { createClient } from 'redis';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import cookieParser from 'cookie-parser';
import fs from 'fs';
import path from 'path';
import multer from 'multer';
import { randomUUID } from 'crypto';
import jwt from 'jsonwebtoken';
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

// Cliente Redis moderno (v4)
const redisClient = createClient({ url: process.env.REDIS_URL });
redisClient.on('error', (err) => console.error('Redis Client Error:', err));

// Crear instancia de store compatible con v7
const RedisStore = new (RedisStoreLib as any)({
  client: redisClient,
  prefix: 'session:',
});

// ✅ Extender tipos de sesión (sin conflicto de modificadores)
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
// 📁 SUBIDA DE IMÁGENES
// =============================
const UPLOAD_DIR = path.resolve('./uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`),
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
      const token = authHeader.split(' ')[1];
      const decoded = jwt.verify(
        token,
        process.env.JWT_SECRET || 'supersecret'
      ) as any;
      (req as any).user = decoded;
      return next();
    } catch {
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
  req.session.userId = String(user.id); // ✅ asegurar tipo string
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
    // req.user viene del middleware requireAuth (sesión o JWT)
    const userData = (req as any).user;

    if (!userData?.id) {
      return res.status(401).json({ error: 'No autenticado' });
    }

    // Buscar usuario en la base de datos
    const user = await prisma.user.findUnique({
      where: { id: userData.id },
      select: { id: true, email: true, role: true },
    });

    if (!user) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    res.json(user);
  } catch (err) {
    console.error('Error en /auth/me:', err);
    res.status(500).json({ error: 'Error obteniendo usuario' });
  }
});


// =============================
// 🧾 PRODUCTOS
// =============================

// Obtener todos
app.get('/api/products', async (_req: Request, res: Response) => {
  const products = await prisma.product.findMany();
  res.json(products);
});

// Crear producto
app.post(
  '/api/products',
  requireAuth,
  upload.single('image'),
  async (req: Request, res: Response) => {
    try {
      const { name, price, description } = req.body;
      const imageUrl = req.file
        ? `/uploads/${req.file.filename}`
        : '/uploads/default.png';

      const product = await prisma.product.create({
        data: {
          name,
          price: Number(price),
          description,
          imageUrl,
        },
      });

      res.json(product);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Error al crear producto' });
    }
  }
);

// =============================
// 📤 SERVIR ARCHIVOS ESTÁTICOS
// =============================
app.use('/uploads', express.static(UPLOAD_DIR));

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
