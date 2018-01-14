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

import { Component, OnDestroy, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { Subscription } from 'rxjs/Subscription';

import { AuthResponse, AuthService } from '../../core/services/auth/auth.service';
import { ToastrService } from 'ngx-toastr';
import { HttpErrorResponse } from '@angular/common/http';

/**
 * Component to login
 */
@Component({
  selector: 'app-home-page',
  styleUrls: ['home.scss'],
  templateUrl: 'home.html'
})
export class HomeComponent implements OnInit, OnDestroy {
  formModel: FormGroup;

  isLoggingIn = false;
  signInBtnText = 'Sign in!';

  private loginSubscription: Subscription;

  constructor(private authService: AuthService, private router: Router, private toastr: ToastrService) {
    const fb = new FormBuilder();
    this.formModel = fb.group({
      username: [null, Validators.required],
      password: [null, Validators.required]
    });
  }

  ngOnInit() {
    if (this.authService.isLoggedIn()) {
      // if already logged in, redicert to the profile page
      this.router.navigate(['/profile']);
    }
  }

  onLogin() {
    if (!this.formModel.valid) {
      this.toastr.error('Both username and password are mandatory!', 'Login failed!', { closeButton: true });
      return;
    }

    this.isLoggingIn = true;
    this.signInBtnText = 'Signing in...';

    this.loginSubscription = this.authService
      .login({
        username: this.formModel.value.username,
        password: this.formModel.value.password
      })
      .subscribe(
        (resp: AuthResponse) => {
          this.isLoggingIn = false;
          this.signInBtnText = 'Sign in!';
          this.toastr.success('Welcome!', 'Login successful!', { closeButton: true });
          this.router.navigate(['/profile']);
        },
        (err: HttpErrorResponse) => {
          this.isLoggingIn = false;
          this.signInBtnText = 'Sign in!';

          if (err.status === 429) {
            // too many requests
            this.toastr.error('Too many requests!', 'Login error!', { closeButton: true });
          } else {
            this.toastr.error('Username or password not valid!', 'Login error!', { closeButton: true });
          }
        }
      );
  }

  ngOnDestroy() {
    // unsubscribe to all Subscriptions to prevent memory leaks and wrong behaviour
    if (this.loginSubscription) {
      this.loginSubscription.unsubscribe();
    }
  }
}
