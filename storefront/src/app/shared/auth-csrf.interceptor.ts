import { HttpInterceptorFn } from '@angular/common/http';

function readCookie(name: string) {
  const m = document.cookie.match(new RegExp('(^|; )' + name + '=([^;]*)'));
  return m ? decodeURIComponent(m[2]) : null;
}

export const authCsrfInterceptor: HttpInterceptorFn = (req, next) => {
  if (['POST','PUT','DELETE','PATCH'].includes(req.method)) {
    const csrf = readCookie('csrfToken'); // debe coincidir con .env
    if (csrf) req = req.clone({ setHeaders: { 'x-csrf-token': csrf } });
  }
  return next(req);
};
