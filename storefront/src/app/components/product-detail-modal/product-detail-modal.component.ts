import { Component, Input, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import {
  IonHeader, IonToolbar, IonButtons, IonButton, IonIcon,
  IonContent, IonImg, IonFooter, ModalController
} from '@ionic/angular/standalone';
import { addIcons } from 'ionicons';
import { closeCircle } from 'ionicons/icons';

@Component({
  selector: 'app-product-detail-modal',
  standalone: true,
  imports: [
    CommonModule,
    IonHeader, IonToolbar, IonButtons, IonButton, IonIcon,
    IonContent, IonImg, IonFooter
  ],
  templateUrl: './product-detail-modal.component.html',
  styleUrls: ['./product-detail-modal.component.scss'],
})
export class ProductDetailModalComponent {
  @Input() product: any;

  private modalCtrl = inject(ModalController);

  constructor() {
    addIcons({ closeCircle });
  }

  close() {
    this.modalCtrl.dismiss();
  }

  addToCart() {
    this.modalCtrl.dismiss({ action: 'add', product: this.product });
  }
}
