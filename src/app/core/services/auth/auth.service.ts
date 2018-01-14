/*
 * MIT License
 *
 * Copyright (c) 2017-2018 Stefano Cappa
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';

import { Observable } from 'rxjs/Observable';
import { tap } from 'rxjs/operators';

import { isLoggedIn as isLoggedInUtil, removeToken as removeTokenUtil, setToken as setTokenUtil, TOKEN_NAME } from './auth.util';

export interface User {
  username: string;
  password: string;
}

export interface AuthResponse {
  message?: string;
  token?: string;
}

@Injectable()
export class AuthService {

  constructor(private http: HttpClient) {
  }

  isLoggedIn(tokenName: string = TOKEN_NAME): boolean {
    return isLoggedInUtil(tokenName);
  }

  login(user: User): Observable<AuthResponse> {
    return this.http.post<AuthResponse>('/api/login', user).pipe(
      tap((resp: AuthResponse) => {
        // login successful if there's a jwt token in the response
        const token = resp.token;
        if (token) {
          // store token in local storage to keep user logged in
          setTokenUtil(token);
        }
      })
    );
  }

  logout(): Observable<AuthResponse> {
    return this.http.get<AuthResponse>('/api/logout').pipe(tap(() => removeTokenUtil()));
  }
}
