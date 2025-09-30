export type Product = {
  id: string;
  name: string;
  price: number;     // en EUR por defecto
  imageUrl: string;  // URL pública a la imagen
  currency?: string; // '€' por defecto
};

export const products: Product[] = [
  {
    id: "p1",
    name: "Café Premium",
    price: 12.99,
    imageUrl: "https://picsum.photos/seed/coffee/800/600",
    currency: "€"
  },
  {
    id: "p2",
    name: "Auriculares Inalámbricos",
    price: 39.9,
    imageUrl: "https://picsum.photos/seed/headphones/800/600",
    currency: "€"
  },
  {
    id: "p3",
    name: "Mochila Urbana",
    price: 24.5,
    imageUrl: "https://picsum.photos/seed/bag/800/600",
    currency: "€"
  }
];