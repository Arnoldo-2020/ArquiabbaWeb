import { Routes } from '@angular/router';
import { ProductsPage } from './pages/products/products.page';

import { adminGuard } from './shared/admin.guard';
import { AdminLoginPage } from './pages/admin/admin-login.page';
import { AdminListPage } from './pages/admin/admin-list.page';
import { AdminFormPage } from './pages/admin/admin-form.page';

import { CartPage } from './pages/cart/cart.pages';

export const routes: Routes = [
  { path: '', component: ProductsPage },

  { path: 'admin/login', component: AdminLoginPage },
  { path: 'admin/products', canActivate: [adminGuard], component: AdminListPage },
  { path: 'admin/products/new', canActivate: [adminGuard], component: AdminFormPage },
  { path: 'cart', loadComponent: () => import('./pages/cart/cart.pages').then(m => m.CartPage) },
  { path: 'admin/products/:id', canActivate: [adminGuard], component: AdminFormPage },

  { path: '**', redirectTo: '' },
];
