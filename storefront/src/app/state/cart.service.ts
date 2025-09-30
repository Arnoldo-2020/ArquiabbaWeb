import { Injectable, signal, computed } from '@angular/core';
import { Product } from '../models/product';

export type CartItem = { product: Product; quantity: number };

@Injectable({ providedIn: 'root' })
export class CartService {
  // estado interno del carrito
  private itemsSig = signal<CartItem[]>([]);

  // lecturas derivadas
  items = computed(() => this.itemsSig());
  count = computed(() => this.itemsSig().reduce((sum, i) => sum + i.quantity, 0));
  total = computed(() => this.itemsSig().reduce((sum, i) => sum + i.product.price * i.quantity, 0));

  add(product: Product, q = 1) {
    const arr = this.itemsSig().slice();
    const idx = arr.findIndex(i => i.product.id === product.id);
    if (idx >= 0) {
      arr[idx] = { ...arr[idx], quantity: Math.min(99, arr[idx].quantity + q) };
    } else {
      arr.push({ product, quantity: Math.max(1, Math.min(99, q)) });
    }
    this.itemsSig.set(arr);
  }

  update(id: string, q: number) {
    const qty = Math.max(1, Math.min(99, Number(q) || 1));
    this.itemsSig.set(this.itemsSig().map(i => i.product.id === id ? { ...i, quantity: qty } : i));
  }

  remove(id: string) {
    this.itemsSig.set(this.itemsSig().filter(i => i.product.id !== id));
  }

  clear() { this.itemsSig.set([]); }

  // payload para el backend
  toPayload() {
    return this.itemsSig().map(i => ({ id: i.product.id, quantity: i.quantity }));
  }
}
