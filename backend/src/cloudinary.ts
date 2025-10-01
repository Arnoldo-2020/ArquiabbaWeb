import { v2 as cloudinary } from 'cloudinary';
import 'dotenv/config';

// Validación simple (opcional pero útil)
if (!process.env.CLOUDINARY_CLOUD_NAME ||
    !process.env.CLOUDINARY_API_KEY ||
    !process.env.CLOUDINARY_API_SECRET) {
  console.warn('[cloudinary] Variables .env faltantes');
}

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME!,
  api_key:    process.env.CLOUDINARY_API_KEY!,
  api_secret: process.env.CLOUDINARY_API_SECRET!,
  secure: true,
});

export default cloudinary;              
export type { UploadApiResponse } from 'cloudinary';