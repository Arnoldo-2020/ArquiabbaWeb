// En src/app/shared/auth-csrf.interceptor.ts

import { inject } from '@angular/core';
import { HttpInterceptorFn, HttpRequest, HttpHandlerFn } from '@angular/common/http';
import { AuthService } from '../state/auth.service';

export const authCsrfInterceptor: HttpInterceptorFn = (req: HttpRequest<unknown>, next: HttpHandlerFn) => {
  // Inyectamos el AuthService para acceder al token
  const authService = inject(AuthService);
  console.log(`Interceptor usando AuthService con ID: ${authService.instanceId}`);

  if (!['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
    return next(req);
  }

  // Obtenemos el token directamente del servicio
  const csrfToken = authService.getCsrfToken();

  if (!csrfToken) {
    console.warn('Interceptor CSRF: No se encontró token en AuthService. La petición será rechazada.');
    return next(req);
  }

  const clonedReq = req.clone({
    headers: req.headers.set('X-CSRF-Token', csrfToken),
  });
  console.log('Interceptor CSRF: Token del servicio añadido a la cabecera.');
  return next(clonedReq);
};
