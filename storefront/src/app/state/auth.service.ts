import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { environment } from 'src/environments/environment';
import { Observable, of, tap } from 'rxjs';
import { catchError, switchMap } from 'rxjs/operators';

export type UserMe = {
  id: string;
  email: string;
  role: 'ADMIN' | 'USER';
};

@Injectable({ providedIn: 'root' })
export class AuthService {
  private http = inject(HttpClient);
  private base = environment.API_URL;
  private csrfToken: string | null = null;

  getCsrfToken(): string | null {
    return this.csrfToken;
  }


  private warmUp(): Observable<unknown> {
    return this.http.get(`${this.base}/health`, {
      withCredentials: true,
    }).pipe(
      catchError(() => of(null))
    );
  }


  login(email: string, password: string): Observable<{ ok: boolean, csrfToken: string }> {
    return this.warmUp().pipe(
      switchMap(() =>
        this.http.post<{ ok: boolean, csrfToken: string }>(
          `${this.base}/auth/login`,
          { email, password },
          { withCredentials: true }
        )
      ),
    tap(response => {
        this.csrfToken = response.csrfToken;
        console.log('AuthService: Token CSRF guardado:', this.csrfToken);
      })
    );
  }


  logout(): Observable<unknown> {
    return this.http.post(
      `${this.base}/auth/logout`,
      {},
      { withCredentials: true }
    );
  }

  /**
   * Get current authenticated user from session.
   */
  me(): Observable<UserMe> {
    return this.http.get<UserMe>(
      `${this.base}/auth/me`,
      { withCredentials: true }
    );
  }
}
