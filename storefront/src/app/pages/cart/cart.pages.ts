import { Component, inject, AfterViewInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { IonContent, IonList, IonItem, IonLabel, IonInput, IonButton, IonImg } from '@ionic/angular/standalone';
import { HttpClient } from '@angular/common/http';
import { CartService } from '../../state/cart.service';

// Tipos del SDK PayPal para el cliente
import { loadScript, PayPalNamespace, PayPalScriptOptions } from '@paypal/paypal-js';

@Component({
  standalone: true,
  selector: 'app-cart',
  imports: [CommonModule, IonContent, IonList, IonItem, IonLabel, IonInput, IonButton, IonImg],
  templateUrl:'./cart.pages.html'
})
export class CartPage implements AfterViewInit {
  cart = inject(CartService);
  private http = inject(HttpClient);
  private paypal: PayPalNamespace | null = null;

  onQty(id: string, v: any)   { this.cart.update(id, Number(v) || 1); }
  remove(id: string)          { this.cart.remove(id); }

  async ngAfterViewInit() {
    if (this.cart.items().length === 0) return;

    // ---------- FIX #1: opciones del script ----------
    // Si tu TS se queja por claves del objeto, este casting lo hace compatible.
    const opts: PayPalScriptOptions = {
    clientId: 'Af5WYz93i5kbElbWnqRLhurjnkzRp993k_zZcZ4qoTfbdaIYLwXN_eA2iexDmCCkIQMN-UDSBNApmAhH', // ej: AbCdEFG123... (sin << >>)
    currency: 'EUR',
    components: 'buttons',
    };

    this.paypal = await loadScript(opts);
    if (!this.paypal) {
      console.error('PayPal SDK no cargó');
      return;
    }

    // ---------- FIX #2: asegurar no-null ----------
    //const paypal = this.paypal as PayPalNamespace;

    await this.paypal!.Buttons!({
      createOrder: async () => {
        const res = await this.http
          .post<{ id: string }>('/api/paypal/create-order', { items: this.cart.toPayload() })
          .toPromise();
        return res!.id;
      },
      onApprove: async (data) => {
        const capture: any = await this.http
          .post('/api/paypal/capture-order', { orderID: (data as any).orderID })
          .toPromise();

        if (capture?.status === 'COMPLETED') {
          alert('¡Pago completado! Gracias por tu compra.');
          this.cart.clear();
        } else {
          alert('El pago no se completó: ' + (capture?.status || 'desconocido'));
        }
      },
      onError: (err) => {
        console.error('PayPal error', err);
        alert('Hubo un problema con PayPal.');
      },
      style: { layout: 'vertical', color: 'gold', shape: 'rect', label: 'paypal' }
    }).render('#paypal-buttons');
  }
}
