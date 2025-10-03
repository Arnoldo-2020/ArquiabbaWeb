import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { environment } from 'src/environments/environment.prod';

export type UserMe = {
  id: string;
  email: string;
  role: 'ADMIN' | 'USER';
};

@Injectable({ providedIn: 'root' })
export class AuthService {
  private http = inject(HttpClient);
  private base = environment.API_URL;

  login(email: string, password: string) {
    return this.http.post(
      `${this.base}/auth/login`,
      { email, password },
      { withCredentials: true }
    );
  }

  logout() {
    return this.http.post(
      `${this.base}/auth/logout`,
      {},
      { withCredentials: true }
    );
  }

  me() {
    return this.http.get<UserMe>(`${this.base}/auth/me`, { withCredentials: true });
  }

}
