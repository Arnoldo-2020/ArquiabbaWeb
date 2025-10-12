import express, { Request, Response, NextFunction } from 'express';
import cors, { CorsOptions } from 'cors';
import multer from 'multer';

// --- CONFIGURACIÓN MÍNIMA ---
const app = express();
const PORT = Number(process.env.PORT || 3000);
const FRONT_ORIGIN = process.env.FRONT_ORIGIN || 'https://arquiabba-web.vercel.app';

// --- MIDDLEWARES MÍNIMOS ---
// Solo CORS, para permitir la petición del navegador
const corsOptions: CorsOptions = {
  origin: [FRONT_ORIGIN, 'http://localhost:4200'],
  credentials: true,
};
app.use(cors(corsOptions));

// El middleware de Multer para la subida
const upload = multer({ storage: multer.memoryStorage() });

// --- LOGGER UNIVERSAL (NUESTRO "ESPÍA") ---
// Este es el único logger. Si vemos esto, la petición llegó.
app.use((req: Request, res: Response, next: NextFunction) => {
  console.log(`--- PETICIÓN RECIBIDA --- Método: ${req.method}, URL: ${req.originalUrl}`);
  next();
});


// --- RUTA DE PRUEBA SIMPLIFICADA ---
// Sin Auth, sin CSRF, sin roles. Solo recibe la petición.
app.post('/api/products', upload.single('image'), (req: Request, res: Response) => {
  console.log('--- ¡ÉXITO! La petición POST a /api/products llegó al manejador de la ruta. ---');

  if (req.file) {
    console.log('--- Archivo recibido:', req.file.originalname);
  } else {
    console.log('--- Petición recibida sin archivo. ---');
  }

  // Devolvemos una respuesta exitosa
  res.status(200).json({ message: 'La petición de prueba fue recibida por el servidor mínimo.' });
});


// --- ARRANQUE DEL SERVIDOR ---
app.listen(PORT, () => {
  console.log(`Servidor MÍNIMO de prueba corriendo en el puerto ${PORT}`);
});