import { Component } from '@angular/core';
import { IonApp, IonRouterOutlet,  IonContent, IonFooter, IonToolbar, IonHeader, IonTitle, IonButton, IonIcon, IonText } from '@ionic/angular/standalone';
import { addIcons } from 'ionicons';
import { logoInstagram } from 'ionicons/icons';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [IonApp, IonRouterOutlet, IonFooter, IonContent, IonHeader, IonTitle, IonToolbar, IonButton, IonIcon, IonText],
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.scss'],
})
export class AppComponent {

  // 🔧 CAMBIA ESTO POR TU USUARIO DE INSTAGRAM (sin @)
  instagramHandle = 'arquiabba';

  constructor() {
    // Registrar el ícono de Instagram
    addIcons({ logoInstagram });
  }

  get instagramUrl(): string {
    // Abre el perfil (sin login requerido)
    return `https://instagram.com/${this.instagramHandle}`;
  }

  openInstagram(): void {
    // En web abre nueva pestaña; en app nativa, Capacitor lo abrirá en el navegador del sistema.
    window.open(this.instagramUrl, '_blank', 'noopener');
  }
}
