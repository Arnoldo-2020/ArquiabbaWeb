// En src/app/shared/auth-csrf.interceptor.ts

import { inject } from '@angular/core';
import { HttpInterceptorFn, HttpRequest, HttpHandlerFn } from '@angular/common/http';
import { AuthService } from '../state/auth.service';

export const authCsrfInterceptor: HttpInterceptorFn = (req: HttpRequest<unknown>, next: HttpHandlerFn) => {
  const authService = inject(AuthService);
  console.log(`[Interceptor] Interceptando petición: ${req.method} ${req.url}`);

  if (!['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
    return next(req);
  }

  // Obtenemos el token directamente del servicio
  const csrfToken = authService.getCsrfToken();

  if (!csrfToken) {
    console.warn(`[Interceptor] Token NO encontrado para ${req.url}. Enviando sin cabecera.`);
    return next(req);
  }

  const clonedReq = req.clone({
    headers: req.headers.set('X-CSRF-Token', csrfToken),
  });
  console.log(`%c[Interceptor] Token encontrado y AÑADIDO a la cabecera para ${req.url}.`, 'color: green; font-weight: bold;');
  return next(clonedReq);
};
