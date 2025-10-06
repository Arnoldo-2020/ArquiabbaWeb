import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { environment } from 'src/environments/environment';
import { Observable, of } from 'rxjs';
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


  private warmUp(): Observable<unknown> {
    return this.http.get(`${this.base}/health`, {
      withCredentials: true,
    }).pipe(
      catchError(() => of(null))
    );
  }


  login(email: string, password: string): Observable<unknown> {
    return this.warmUp().pipe(
      switchMap(() =>
        this.http.post(
          `${this.base}/auth/login`,
          { email, password },
          { withCredentials: true }
        )
      )
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
