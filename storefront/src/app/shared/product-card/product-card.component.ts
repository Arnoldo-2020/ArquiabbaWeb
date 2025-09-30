import { Component, Input, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import {
  IonCard, IonCardHeader, IonCardTitle, IonCardContent,
  IonButton, IonImg
} from '@ionic/angular/standalone';
import { Router } from '@angular/router';

import { Product } from '../../models/product';
import { CartService } from '../../state/cart.service';

@Component({
  selector: 'app-product-card',
  standalone: true,
  imports: [CommonModule, IonCard, IonCardHeader, IonCardTitle, IonCardContent, IonButton, IonImg],
  templateUrl:'./product-card.component.html' ,
  styleUrls: [
    './product-card.component.scss'
  ]
})
export class ProductCardComponent {
  @Input({ required: true }) product!: Product;
  @Input() showCTA = true;

  private cart = inject(CartService);
  private router = inject(Router);

  openDetail() {
    // Si luego haces página de detalle, navega aquí:
    // this.router.navigate(['/product', this.product.id]);
  }

  addToCart(ev: Event) {
    ev.stopPropagation();                // evita que el click burbujee al <ion-card>
    this.cart.add(this.product, 1);      // añade 1 unidad
    this.router.navigateByUrl('/cart');  // lleva al carrito para ver PayPal
  }
}
