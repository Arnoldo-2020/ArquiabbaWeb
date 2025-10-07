// En src/app/shared/auth.service.ts (o la ruta que corresponda)

import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { environment } from 'src/environments/environment';
import { Observable, of, tap } from 'rxjs';
import { catchError, switchMap } from 'rxjs/operators';


function getCookie(name: string): string | null {
  const nameLenPlus = name.length + 1;
  return document.cookie
    .split(';')
    .map(c => c.trim())
    .filter(cookie => cookie.substring(0, nameLenPlus) === `${name}=`)
    .map(cookie => decodeURIComponent(cookie.substring(nameLenPlus)))[0] || null;
}

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

  constructor() {
    this.loadTokenFromCookie();
  }

  private loadTokenFromCookie() {
    this.csrfToken = getCookie('csrfToken');
    console.log('AuthService inicializado. Token CSRF cargado desde cookie:', this.csrfToken);
  }

  getCsrfToken(): string | null {
    return this.csrfToken;
  }

  login(email: string, password: string): Observable<{ ok: boolean, csrfToken: string }> {
    return this.http.post<{ ok: boolean, csrfToken: string }>(
      `${this.base}/auth/login`,
      { email, password },
      { withCredentials: true }
    ).pipe(
      tap(response => {
        this.csrfToken = response.csrfToken;
        console.log('AuthService: Token CSRF guardado desde respuesta de login:', this.csrfToken);
      })
    );
  }

  logout(): Observable<unknown> {
    this.csrfToken = null;
    return this.http.post(`${this.base}/auth/logout`, {}, { withCredentials: true });
  }

  me(): Observable<UserMe> {
    return this.http.get<UserMe>(`${this.base}/auth/me`, { withCredentials: true });
  }
}
