import { Injectable } from '@angular/core';
import { HttpEvent, HttpHandler, HttpInterceptor, HttpRequest } from '@angular/common/http';

import { Observable } from 'rxjs/Observable';

import { EXTERNAL_URLS } from './auth.util';

@Injectable()
export class TokenInterceptor implements HttpInterceptor {
  constructor() {
  }

  intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {

    // fon some urls I shouldn't add my Authentication header (valid only for my server),
    // in particular for external urls, like Github, Google and so on...
    if (!!EXTERNAL_URLS.find((url: string) => request.url.startsWith(url))) {
      return next.handle(request);
    }

    // I'm using clone, because the original request is immutable
    request = request.clone({
      setHeaders: {
        Authorization: `Bearer ${localStorage.getItem('token')}`
      }
    });
    return next.handle(request);
  }
}
