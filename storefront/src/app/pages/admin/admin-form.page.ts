import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import {
  IonContent, IonList, IonItem, IonInput, IonTextarea, IonButton, IonImg
} from '@ionic/angular/standalone';


import { Product } from '../../models/product';
import { ProductsService } from 'src/app/services/product.service';

@Component({
  standalone: true,
  selector: 'app-admin-form',
  imports: [
    CommonModule, ReactiveFormsModule,
    IonContent, IonList, IonItem, IonInput, IonTextarea, IonButton, IonImg
  ],
  templateUrl:'./admin-form.page.html'
})
export class AdminFormPage {
  private fb = inject(FormBuilder);
  private route = inject(ActivatedRoute);
  private router = inject(Router);
  private api = inject(ProductsService);

  loading = false;
  isEdit = false;
  id: string | null = null;
  file: File | null = null;
  preview: string | null = null;

  form = this.fb.group({
    name: ['', Validators.required],
    description: ['', Validators.required],
    price: [0, [Validators.required, Validators.min(0)]],
    imageUrl: ['']
  });

  constructor() {
    this.id = this.route.snapshot.paramMap.get('id');
    this.isEdit = !!this.id;

    if (this.isEdit) {
      this.api.get(this.id!).subscribe((p: Product) => {
        this.form.patchValue({
          name: p.name,
          description: p.description,
          price: p.price,
          imageUrl: p.imageUrl?.startsWith('/uploads/') ? '' : p.imageUrl
        });
        this.preview = p.imageUrl;
      });
    }
  }

  onFile(ev: Event) {
    const input = ev.target as HTMLInputElement;
    this.file = input.files?.[0] ?? null;
    if (this.file) {
      const r = new FileReader();
      r.onload = () => this.preview = String(r.result);
      r.readAsDataURL(this.file);
    }
  }

  submit() {
    if (this.form.invalid) return;
    this.loading = true;

    const { name, description, price, imageUrl } = this.form.value as any;
    const done = () => this.router.navigate(['/admin/products']);

    if (this.isEdit) {
      this.api.update(this.id!, {
        name, description, price: Number(price),
        image: this.file ?? undefined,
        imageUrl: imageUrl || undefined
      }).subscribe({ next: done, error: () => this.loading = false });
    } else {
      this.api.create({
        name, description, price: Number(price),
        image: this.file ?? undefined,
        imageUrl: imageUrl || undefined
      }).subscribe({ next: done, error: () => this.loading = false });
    }
  }
}
