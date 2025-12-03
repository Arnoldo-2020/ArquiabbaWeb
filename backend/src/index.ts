import 'dotenv/config';
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

// --- CONFIGURACION BASE ---
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// --- CONFIGURACION REDIS ---
const redisUrl = process.env.REDIS_URL;

console.log('--- DEBUG REDIS ---');
console.log('REDIS_URL detectada:', !!redisUrl);

if (!redisUrl) {
  console.error('Error critico: No se encontro la variable REDIS_URL');
  process.exit(1);
}

const redisClient = createClient({
  url: redisUrl,
  socket: {
    reconnectStrategy: (retries) => Math.min(retries * 50, 500)
  }
});

redisClient.on('error', (err) => console.error('Redis Client Error:', err));
redisClient.on('connect', () => console.log('Conectado a Redis correctamente'));

// @ts-ignore
const RedisStore = new (RedisStoreLib as any)({
  client: redisClient,
  prefix: 'session:',
});

declare module 'express-session' {
  interface SessionData {
    userId: string;
    role: string;
  }
}

// --- CONFIGURACION CORS ---
const allowedOrigins = [
  'http://localhost:4200',
  'http://localhost:8100',
  'https://arquiabba-web.vercel.app',
  'https://arquiabbaweb.vercel.app',
  'https://arquiabbaweb.onrender.com',
  'https://arquiabba-web.onrender.com'
];

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true);

      if (allowedOrigins.indexOf(origin) !== -1 || origin.includes('.vercel.app')) {
        callback(null, true);
      } else {
        console.log('Bloqueado por CORS:', origin);
        callback(new Error('No permitido por CORS'));
      }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
  })
);

// --- SESION ---
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

// --- CLOUDINARY ---
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'products',
    allowed_formats: ['jpeg', 'png', 'jpg', 'webp'],
    transformation: [{ width: 800, height: 800, crop: 'limit' }],
  } as any,
});

const upload = multer({ storage });

// --- MIDDLEWARE AUTH ---
function requireAuth(req: Request, res: Response, next: NextFunction) {
  if (req.session?.userId) {
    (req as any).user = { id: req.session.userId, role: req.session.role };
    return next();
  }

  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    try {
      const token = authHeader.substring(7);
      const decoded = jwt.verify(
        token,
        process.env.JWT_SECRET || 'supersecret'
      ) as any;

      (req as any).user = { id: decoded.id, role: decoded.role };
      return next();
    } catch (err) {
      console.error('JWT verification failed:', err);
      return res.status(401).json({ error: 'Token invalido o expirado' });
    }
  }

  return res.status(401).json({ error: 'No autorizado' });
}

// --- RUTAS AUTH ---
app.post('/api/auth/login', async (req: Request, res: Response) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'Email y contraseña requeridos' });

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.status(401).json({ error: 'Credenciales invalidas' });

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return res.status(401).json({ error: 'Credenciales invalidas' });

  req.session.userId = String(user.id);
  req.session.role = user.role ?? 'user';

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

// --- RUTAS PRODUCTOS ---
app.get('/api/products', async (_req: Request, res: Response) => {
  try {
    const products = await prisma.product.findMany();
    res.json(products);
  } catch (error) {
    console.error("Error fetching products:", error);
    res.status(500).json({ error: "Error al obtener productos" });
  }
});

app.post(
  '/api/products',
  requireAuth,
  upload.single('image'),
  async (req: Request, res: Response) => {
    try {
      const { name, price, description } = req.body;

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

app.delete(
  '/api/products/:id',
  requireAuth,
  async (req: Request, res: Response) => {
    try {
      const { id } = req.params;

      const product = await prisma.product.findUnique({ where: { id } });

      if (!product) {
        return res.status(404).json({ error: 'Producto no encontrado' });
      }

      await prisma.product.delete({ where: { id } });
      
      res.status(204).send();
    } catch (err) {
      console.error('Error al eliminar producto:', err);
      res.status(500).json({ error: 'Error interno del servidor' });
    }
  }
);

app.put(
  '/api/products/:id',
  requireAuth,
  upload.single('image'),
  async (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      const { name, price, description } = req.body;

      const currentProduct = await prisma.product.findUnique({ where: { id } });

      if (!currentProduct) {
        return res.status(404).json({ error: 'Producto no encontrado' });
      }

      const dataToUpdate: any = {
        name,
        price: Number(price),
        description,
      };

      if (req.file) {
        dataToUpdate.imageUrl = req.file.path;
      }

      const updatedProduct = await prisma.product.update({
        where: { id },
        data: dataToUpdate,
      });

      res.json(updatedProduct);
      
    } catch (err) {
      console.error('Error al actualizar producto:', err);
      res.status(500).json({ error: 'Error interno del servidor' });
    }
  }
);

// --- HEALTH CHECK (NECESARIO PARA RENDER) ---
app.get('/api/health', (req, res) => {
  res.status(200).send('OK');
});

// --- CREAR ADMIN ---
app.get('/api/crear-admin', async (req, res) => {
  try {
    const email = 'mayita@tu-dominio.com'; 
    const password = 'password123';        
    
    const passwordHash = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: {
        email: email,
        passwordHash: passwordHash,
        role: 'ADMIN', 
      }
    });
    
    res.json({ message: 'Usuario Admin creado con exito!', user });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al crear usuario', details: error });
  }
});

// --- INICIO SERVIDOR ---
async function startServer() {
  try {
    await redisClient.connect();
    
    app.listen(PORT, () => {
      console.log(`Servidor corriendo en puerto ${PORT}`);
    });
  } catch (err) {
    console.error('Error fatal al iniciar servidor:', err);
    process.exit(1);
  }
}

startServer();

// --- CIERRE ---
process.on('SIGTERM', async () => {
  console.log('Cerrando servidor...');
  await prisma.$disconnect();
  await redisClient.quit();
  process.exit(0);
});