import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { Product } from '../models/product';

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
  private base = '/api/products';

  // ------- GETS -------
  list(): Observable<Product[]> {
    return this.http.get<Product[]>(this.base);
  }

  get(id: string): Observable<Product> {
    return this.http.get<Product>(`${this.base}/${id}`);
  }

  // ------- CREATE -------
  create(data: CreateOrUpdatePayload): Observable<Object> {
    // const body = new FormData();
    // body.set('name', data.name);
    // body.set('description', data.description);
    // body.set('price', String(data.price));
    // if (data.image)    body.set('image', data.image);
    // if (data.imageUrl) body.set('imageUrl', data.imageUrl);
    // return this.http.post<Product>(this.base, body);
    console.log('Enviando a la ruta de PRUEBA /api/products-test');
    const testPayload = { name: 'Prueba', price: 10 };
    return this.http.post(`${this.base}/products-test`, testPayload);
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
}
