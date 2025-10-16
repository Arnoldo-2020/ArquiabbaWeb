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

  // ================================================================
  // ✅ TOKENS ======================================================
  // ================================================================

  /** Devuelve el JWT almacenado en localStorage */
  getToken(): string | null {
    const token = localStorage.getItem('token');
    console.log(`[AuthService - ID: ${this.instanceId}] getToken() →`, token);
    return token;
  }

  /** Guarda el JWT en localStorage */
  setToken(token: string): void {
    localStorage.setItem('token', token);
    console.log(`[AuthService - ID: ${this.instanceId}] Token guardado en localStorage.`);
  }

  /** Limpia el JWT */
  clearToken(): void {
    localStorage.removeItem('token');
    this.csrfToken = null;
  }

  /** Si aún usas CSRF */
  getCsrfToken(): string | null {
    console.log(`[AuthService - ID: ${this.instanceId}] getCsrfToken() →`, this.csrfToken);
    return this.csrfToken;
  }

  // ================================================================
  // ✅ AUTENTICACIÓN ===============================================
  // ================================================================

  /**
   * Inicia sesión. Espera que el backend devuelva un JWT.
   * Ejemplo de respuesta esperada:
   *   { token: "<JWT>", user: {...} }
   */
  login(email: string, password: string): Observable<{ token: string }> {
    console.log(`[AuthService - ID: ${this.instanceId}] Iniciando petición de login...`);
    return this.http
      .post<{ token: string }>(
        `${this.base}/auth/login`,
        { email, password },
        { withCredentials: true }
      )
      .pipe(
        tap((response) => {
          if (response && response.token) {
            this.setToken(response.token);
            console.log(
              `%c[AuthService - ID: ${this.instanceId}] Petición de login COMPLETADA. Guardando token.`,
              'color: green; font-weight: bold;'
            );
          } else {
            console.warn(`[AuthService] No se recibió un token JWT en la respuesta.`);
          }
        })
      );
  }

  /** Cierra sesión */
  logout(): Observable<unknown> {
    console.log(`[AuthService - ID: ${this.instanceId}] Logout iniciado.`);
    this.clearToken();
    return this.http.post(`${this.base}/auth/logout`, {}, { withCredentials: true });
  }

  /** Obtiene los datos del usuario autenticado */
  me(): Observable<UserMe> {
    return this.http.get<UserMe>(`${this.base}/auth/me`, { withCredentials: true });
  }
}
