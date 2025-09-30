import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { ToastController } from '@ionic/angular';
import { catchError } from 'rxjs/operators';
import { throwError } from 'rxjs';

/**
 * Interceptor que muestra un Toast cuando ocurre un error HTTP.
 * - No bloquea el flujo: lanza de nuevo el error tras mostrar el toast.
 * - Usa DI funcional: inject(ToastController).
 */
export const errorToastInterceptor: HttpInterceptorFn = (req, next) => {
  const toastCtrl = inject(ToastController);

  return next(req).pipe(
    catchError((err: unknown) => {
      const msg =
        (err as HttpErrorResponse)?.error?.error ??
        (err as any)?.message ??
        'Network error';

      // Mostramos el toast (no esperamos; evitamos romper el tipo de retorno)
      toastCtrl
        .create({
          message: String(msg),
          duration: 2500,
          position: 'bottom',
        })
        .then((t) => t.present());

      // Reemitimos el error para que el caller lo maneje si quiere
      return throwError(() => err);
    })
  );
};
