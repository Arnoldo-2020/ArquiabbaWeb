import { HttpInterceptorFn, HttpRequest, HttpHandlerFn } from '@angular/common/http';

function getCookie(name: string): string | null {
  const nameLenPlus = name.length + 1;
  return document.cookie
    .split(';')
    .map(c => c.trim())
    .filter(cookie => cookie.substring(0, nameLenPlus) === `${name}=`)
    .map(cookie => decodeURIComponent(cookie.substring(nameLenPlus)))[0] || null;
}

export const authCsrfInterceptor: HttpInterceptorFn = (req: HttpRequest<unknown>, next: HttpHandlerFn) => {
  // Primero, verifica si el método NO necesita el token y sal de inmediato
  if (!['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
    return next(req);
  }

  // Si el método SÍ necesita el token, búscalo
  const csrfToken = getCookie('csrfToken');

  // Si no se encuentra el token, envía la petición original (el backend la rechazará)
  // y muestra una advertencia en la consola para facilitar la depuración.
  if (!csrfToken) {
    console.warn('Interceptor CSRF: No se encontró la cookie csrfToken. La petición será rechazada por el backend.');
    return next(req);
  }

  // Si se encontró el token, clona la petición, añade la cabecera y envía la nueva petición.
  const clonedReq = req.clone({
    headers: req.headers.set('X-CSRF-Token', csrfToken),
  });

  return next(clonedReq);
};
