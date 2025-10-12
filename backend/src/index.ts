import 'dotenv/config';
import express, { Request, Response, NextFunction } from 'express';
import cors, { CorsOptions } from 'cors';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import session from 'express-session';
import multer from 'multer';

/**
 * ============================
 * Express App & Constants
 * ============================
 */
const app = express();
const PORT = Number(process.env.PORT || 3000);
const FRONT_ORIGIN = process.env.FRONT_ORIGIN || 'https://arquiabba-web.vercel.app';

/**
 * ============================
 * Middlewares en "Modo Seguro"
 * ============================
 */
app.set('trust proxy', 1);

const corsOptions: CorsOptions = {
  origin: [FRONT_ORIGIN, 'http://localhost:4200'],
  credentials: true,
};

app.use(cors(corsOptions)); // CORS es esencial, se queda.
app.use(express.json());   // Parser de JSON es esencial, se queda.
app.use(cookieParser()); // Parser de cookies es esencial, se queda.

// --- MIDDLEWARES DESACTIVADOS TEMPORALMENTE ---
// app.use(helmet());
// app.use(rateLimit({ windowMs: 60_000, max: 120 }));
// app.use(session({
//   store: redisStore, // Desactivado porque es el principal sospechoso
//   secret: process.env.SESSION_SECRET || 'change-me-to-a-strong-secret',
//   resave: false,
//   saveUninitialized: false,
//   cookie: { secure: true, httpOnly: true, sameSite: 'none', maxAge: 24 * 60 * 60 * 1000 },
// }));

/**
 * ============================
 * Logger Universal (Nuestro "Espía")
 * ============================
 */
app.use((req: Request, res: Response, next: NextFunction) => {
  console.log(`--- PETICIÓN RECIBIDA --- Método: ${req.method}, URL: ${req.originalUrl}`);
  next();
});

/**
 * ============================
 * Ruta de Login de Prueba
 * ============================
 */
app.post('/api/auth/login', (req: Request, res: Response) => {
  console.log('--- ¡ÉXITO! La petición de login llegó al manejador de la ruta. ---');
  // Devolvemos una respuesta falsa pero exitosa para que el frontend no dé error.
  res.status(200).json({ ok: true, csrfToken: 'fake-token-for-testing' });
});

/**
 * ============================
 * Arranque del Servidor
 * ============================
 */
app.listen(PORT, () => {
  console.log(`Servidor en MODO SEGURO escuchando en el puerto ${PORT}`);
});