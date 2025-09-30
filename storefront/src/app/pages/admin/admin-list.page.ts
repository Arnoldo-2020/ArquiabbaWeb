import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { IonContent, IonList, IonItem, IonLabel, IonButton } from '@ionic/angular/standalone';
import { Router } from '@angular/router';

import { Product } from '../../models/product';
import { AuthService } from '../../state/auth.service';
import { ProductsService } from 'src/app/services/product.service';

@Component({
  standalone: true,
  selector: 'app-admin-list',
  imports: [CommonModule, IonContent, IonList, IonItem, IonLabel, IonButton],
  templateUrl: './admin-list.page.html'
})
export class AdminListPage {
  private api = inject(ProductsService);
  private router = inject(Router);
  private auth = inject(AuthService);
  items: Product[] = [];

  constructor() { this.load(); }
  load() { this.api.list().subscribe(data => this.items = data); }
  new() { this.router.navigate(['/admin/products/new']); }
  edit(id: string) { this.router.navigate(['/admin/products', id]); }
  del(id: string) {
    if (!confirm('Delete this product?')) return;
    this.api.remove(id).subscribe(() => this.load());
  }
  logout() {
    this.auth.logout().subscribe(() => this.router.navigate(['/admin/login']));
  }
}
