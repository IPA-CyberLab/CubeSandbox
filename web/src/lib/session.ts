// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Tencent. All rights reserved.

// Lightweight WebUI session storage. The token is sent as `X-Session-Token`
// (see lib/api.ts) and validated by CubeAPI's /auth/session endpoint.

const TOKEN_KEY = 'cube.session';
const USER_KEY = 'cube.sessionUser';

export function getSessionToken(): string {
  return localStorage.getItem(TOKEN_KEY) ?? '';
}

export function getSessionUser(): string {
  return localStorage.getItem(USER_KEY) ?? '';
}

export function setSession(token: string, username: string): void {
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(USER_KEY, username);
}

export function clearSession(): void {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}
