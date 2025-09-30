import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';

@Injectable({ providedIn: 'root' })
export class AuthService {
  private http = inject(HttpClient);

  login(email: string, password: string) {
    return this.http.post('/api/auth/login', { email, password });
  }
  logout() {
    return this.http.post('/api/auth/logout', {});
  }
  me() {
    return this.http.get<{ id:string; email:string; role:'ADMIN'|'USER' }>('/api/auth/me');
  }
}
