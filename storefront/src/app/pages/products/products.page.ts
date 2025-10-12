import { Component, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import {
  IonContent, IonGrid, IonRow, IonCol,
  IonRefresher, IonRefresherContent, IonSkeletonText, IonHeader, IonToolbar, IonTitle, IonButtons, IonButton
} from '@ionic/angular/standalone';


import { ProductsService } from 'src/app/services/product.service';
import { Product } from 'src/app/models/product';
import { ProductCardComponent } from 'src/app/shared/product-card/product-card.component';

@Component({
  selector: 'app-products-page',
  standalone: true,
  imports: [
    CommonModule, IonContent, IonGrid, IonRow, IonCol,
    IonRefresher, IonRefresherContent, IonSkeletonText,
    ProductCardComponent
  ],
  templateUrl: './products.page.html'
})
export class ProductsPage {
  private api = inject(ProductsService);
  products = signal<Product[]>([]);
  loading = signal(true);
  skeletons = Array.from({ length: 6 });

  constructor() { this.load(); }

  load() {
    this.loading.set(true);
    this.api.list().subscribe({
      next: (data) => { this.products.set(data); this.loading.set(false); },
      error: () => { this.loading.set(false); }
    });
  }

  refresh(ev: CustomEvent) {
    this.api.list().subscribe({
      next: (data) => { this.products.set(data); (ev.target as any).complete(); },
      error: () => { (ev.target as any).complete(); }
    });
  }

}
