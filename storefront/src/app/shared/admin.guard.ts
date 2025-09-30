import { CanActivateFn, Router } from '@angular/router';
import { inject } from '@angular/core';
import { AuthService } from '../state/auth.service';
import { firstValueFrom } from 'rxjs';

export const adminGuard: CanActivateFn = async () => {
  const auth = inject(AuthService);
  const router = inject(Router);
  try {
    const me = await firstValueFrom(auth.me());
    if (me.role === 'ADMIN') return true;
  } catch {}
  router.navigate(['/admin/login']);
  return false;
};
