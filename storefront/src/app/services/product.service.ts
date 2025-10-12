import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { Product } from '../models/product';
import { environment } from 'src/environments/environment';

type CreateOrUpdatePayload = {
  name: string;
  description: string;
  price: number;
  image?: File;
  imageUrl?: string;
};

@Injectable({ providedIn: 'root' })
export class ProductsService {
  private http = inject(HttpClient);
  private base = `${environment.API_URL}/products`;

  // ------- GETS -------
  list(): Observable<Product[]> {
    return this.http.get<Product[]>(this.base);
  }

  get(id: string): Observable<Product> {
    return this.http.get<Product>(`${this.base}/${id}`);
  }

  // ------- CREATE -------
  create(data: CreateOrUpdatePayload): Observable<Product> {
    const body = new FormData();
    body.set('name', data.name);
    body.set('description', data.description);
    body.set('price', String(data.price));
    if (data.image)    body.set('image', data.image);
    if (data.imageUrl) body.set('imageUrl', data.imageUrl);
    return this.http.post<Product>(this.base, body);
  }

  // ------- UPDATE -------
  update(id: string, data: CreateOrUpdatePayload): Observable<Product> {
    const body = new FormData();
    body.set('name', data.name);
    body.set('description', data.description);
    body.set('price', String(data.price));
    if (data.image)    body.set('image', data.image);
    if (data.imageUrl) body.set('imageUrl', data.imageUrl);
    return this.http.put<Product>(`${this.base}/${id}`, body);
  }

  // ------- DELETE -------
  remove(id: string): Observable<void> {
    return this.http.delete<void>(`${this.base}/${id}`);
  }

  // --- MÉTODO DE PRUEBA TEMPORAL ---
  testSimplePost(): Observable<any> {
    const testPayload = { message: 'Hola desde Vercel' };
    return this.http.post(`${environment.API_URL}/test-simple-post`, testPayload);
  }
}
