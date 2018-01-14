// token name used in local storage
export const TOKEN_NAME = 'token';

// all external urls to bypass the auth.interceptor preventing wrong Authorization headers
export const EXTERNAL_URLS: string[] = [
  'https://api.github.com'
];

// these should be in auth.service, but there is a bug in Angular and I cannot inject auth.service into interceptors without throwing expection,
// so at the moment I found this solution.

export function isLoggedIn(tokenName: string = TOKEN_NAME): boolean {
  return !!localStorage.getItem(tokenName);
}

export function getToken(tokenName: string = TOKEN_NAME): string | null {
  return localStorage.getItem(tokenName);
}

export function setToken(token: string, tokenName: string = TOKEN_NAME) {
  localStorage.setItem(tokenName, token);
}

export function removeToken(tokenName: string = TOKEN_NAME) {
  localStorage.removeItem(tokenName);
}
