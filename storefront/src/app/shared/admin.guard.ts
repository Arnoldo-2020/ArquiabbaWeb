import { Injectable, inject } from '@angular/core';
import { CanActivate, Router } from '@angular/router';
import { map, catchError } from 'rxjs/operators';
import { of } from 'rxjs';
import { AuthService, UserMe } from '../state/auth.service';

@Injectable({ providedIn: 'root' })
export class AdminGuard implements CanActivate {
  private auth = inject(AuthService);
  private router = inject(Router);

  canActivate() {
    return this.auth.me().pipe(
      map((me: UserMe) => me.role === 'ADMIN'),
      catchError(() => {
        this.router.navigateByUrl('/admin/login');
        return of(false);
      })
    );
  }
}
