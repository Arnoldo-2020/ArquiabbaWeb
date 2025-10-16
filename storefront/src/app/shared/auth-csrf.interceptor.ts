import { inject } from '@angular/core';
import {
  HttpInterceptorFn,
  HttpRequest,
  HttpHandlerFn,
  HttpEvent,
} from '@angular/common/http';
import { AuthService } from '../state/auth.service';
import { Observable } from 'rxjs';

export const authCsrfInterceptor: HttpInterceptorFn = (
  req: HttpRequest<unknown>,
  next: HttpHandlerFn
): Observable<HttpEvent<unknown>> => {
  const authService = inject(AuthService);

  console.log(`[Interceptor] Interceptando petición: ${req.method} ${req.url}`);

  // --- 1️⃣ Si la ruta es de login o registro, no agregamos token ---
  if (req.url.includes('/auth/login') || req.url.includes('/auth/register')) {
    console.warn(`[Interceptor] Petición de autenticación detectada. Enviando sin token.`);
    return next(req);
  }

  // --- 2️⃣ Clonamos la solicitud para añadir tokens si existen ---
  let clonedReq = req;

  // Token CSRF (si lo usas para sesiones basadas en cookies)
  const csrfToken = authService.getCsrfToken();
  if (csrfToken) {
    clonedReq = clonedReq.clone({
      setHeaders: { 'X-CSRF-Token': csrfToken },
    });
  }

  // Token JWT (usado por tu backend actual)
  const jwtToken = authService.getToken(); // asegúrate que AuthService tenga este método
  if (jwtToken) {
    clonedReq = clonedReq.clone({
      setHeaders: {
        Authorization: `Bearer ${jwtToken}`,
        ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
      },
    });
    console.log(
      `%c[Interceptor] JWT encontrado y añadido a ${req.url}`,
      'color: green; font-weight: bold;'
    );
  } else {
    console.warn(`[Interceptor] JWT no encontrado para ${req.url}`);
  }

  return next(clonedReq);
};
