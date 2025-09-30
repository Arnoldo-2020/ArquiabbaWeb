import { z } from 'zod';

export const createProductSchema = z.object({
  name: z.string().min(1).max(120),
  description: z.string().min(1).max(1000),
  // Acepta string o number y lo convierte a number
  price: z.union([z.string(), z.number()])
    .transform((v) => Number(v))
    .refine((n) => !Number.isNaN(n) && n >= 0, 'Invalid price'),
  // la imagen llega como archivo (multer) o como imageUrl
});

export const updateProductSchema = z.object({
  name: z.string().min(1).max(120).optional(),
  description: z.string().min(1).max(1000).optional(),
  price: z.union([z.string(), z.number()]).transform((v) => Number(v))
    .refine((n) => !Number.isNaN(n) && n >= 0, 'Invalid price')
    .optional(),
});