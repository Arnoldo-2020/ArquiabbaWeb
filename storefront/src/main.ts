import { bootstrapApplication } from '@angular/platform-browser';
import { provideRouter } from '@angular/router';
import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { provideIonicAngular } from '@ionic/angular/standalone';

import { routes } from './app/app.routes';
import { AppComponent } from './app/app.component';
import { authCsrfInterceptor } from './app/shared/auth-csrf.interceptor';
import { errorToastInterceptor } from './app/shared/error-toast.interceptor';


bootstrapApplication(AppComponent, {
  providers: [
    provideIonicAngular(),
    provideRouter(routes),
    provideHttpClient(withInterceptors([
      authCsrfInterceptor,
      errorToastInterceptor
    ])),
  ],
});
