import 'express-session';

declare module 'express-session' {
  interface SessionData {
    uid: string;
    role: 'ADMIN' | 'USER';
    csrfToken: string;
  }
}