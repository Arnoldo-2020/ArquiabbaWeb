import { Component, Input, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import {
  IonCard, IonCardHeader, IonCardTitle, IonCardContent,
  IonButton, IonImg, ModalController
} from '@ionic/angular/standalone';
import { Router } from '@angular/router';

import { Product } from '../../models/product';
import { CartService } from '../../state/cart.service';

import { ProductDetailModalComponent } from '../../components/product-detail-modal/product-detail-modal.component';

@Component({
  selector: 'app-product-card',
  standalone: true,
  imports: [CommonModule, IonCard, IonCardHeader, IonCardTitle, IonCardContent, IonButton, IonImg],
  templateUrl: './product-card.component.html',
  styleUrls: ['./product-card.component.scss']
})
export class ProductCardComponent {
  @Input({ required: true }) product!: Product;
  @Input() showCTA = true;

  private cart = inject(CartService);
  private router = inject(Router);
  private modalCtrl = inject(ModalController);

  // Función para abrir el modal con el detalle
  async openDetail() {
    const modal = await this.modalCtrl.create({
      component: ProductDetailModalComponent,
      componentProps: {
        product: this.product
      },

      breakpoints: [0, 1],
      initialBreakpoint: 1,
    });

    await modal.present();

    // Escuchar cuando se cierra el modal
    const { data } = await modal.onWillDismiss();

    // Si el usuario le dio al botón "Añadir al Carrito" DENTRO del modal
    if (data && data.action === 'add') {
      this.cart.add(this.product, 1);
      this.router.navigateByUrl('/cart');
    }
  }

  // Función para añadir directamente desde la tarjeta (botón pequeño)
  addToCart(ev: Event) {
    ev.stopPropagation();
    this.cart.add(this.product, 1);
    this.router.navigateByUrl('/cart');
  }
}
