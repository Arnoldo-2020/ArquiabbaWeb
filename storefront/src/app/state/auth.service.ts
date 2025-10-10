import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { environment } from 'src/environments/environment';
import { Observable, tap } from 'rxjs';

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
  public instanceId: number;

  constructor() {
    this.instanceId = Math.random();
    console.log(`%cAuthService CREADO con ID: ${this.instanceId}`, 'color: blue; font-weight: bold;');
  }

  getCsrfToken(): string | null {
    console.log(`[AuthService - ID: ${this.instanceId}] Interceptor pide el token. Valor actual:`, this.csrfToken);
    return this.csrfToken;
  }

  login(email: string, password: string): Observable<{ ok: boolean, csrfToken: string }> {
    console.log(`[AuthService - ID: ${this.instanceId}] Iniciando petición de login...`);
    return this.http.post<{ ok: boolean, csrfToken: string }>(
      `${this.base}/auth/login`,
      { email, password },
      { withCredentials: true }
    ).pipe(
      tap(response => {
        this.csrfToken = response.csrfToken;
        console.log(`%c[AuthService - ID: ${this.instanceId}] Petición de login COMPLETADA. Guardando token:`, 'color: green; font-weight: bold;', this.csrfToken);
      })
    );
  }

  logout(): Observable<unknown> {
    console.log(`[AuthService - ID: ${this.instanceId}] Limpiando token por logout.`);
    this.csrfToken = null; // Limpia el token al hacer logout
    return this.http.post(`${this.base}/auth/logout`, {}, { withCredentials: true });
  }

  me(): Observable<UserMe> {
    return this.http.get<UserMe>(`${this.base}/auth/me`, { withCredentials: true });
  }
}
