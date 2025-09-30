import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ReactiveFormsModule, FormBuilder, Validators } from '@angular/forms';
import { IonContent, IonList, IonItem, IonInput, IonButton } from '@ionic/angular/standalone';
import { AuthService } from '../../state/auth.service';
import { Router } from '@angular/router';

@Component({
  standalone: true,
  selector: 'app-admin-login',
  imports: [CommonModule, ReactiveFormsModule, IonContent, IonList, IonItem, IonInput, IonButton],
  templateUrl: './admin-login.page.html'
})
export class AdminLoginPage {
  private fb = inject(FormBuilder);
  private auth = inject(AuthService);
  private router = inject(Router);
  loading = false;

  form = this.fb.group({ email: ['', [Validators.required, Validators.email]], password: ['', Validators.required] });

  submit() {
    if (this.form.invalid) return;
    this.loading = true;
    this.auth.login(this.form.value.email!, this.form.value.password!).subscribe({
      next: () => { this.router.navigate(['/admin/products']); },
      error: () => { this.loading = false; }
    });
  }
}
