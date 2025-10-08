/*!
 * Copyright (c) 2021-2025 Digital Bazaar, Inc. All rights reserved.
 */
export function base64Decode(str) {
  if(Uint8Array.fromBase64) {
    return Uint8Array.fromBase64(str);
  }
  return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

export function base64urlDecode(str) {
  if(Uint8Array.fromBase64) {
    return Uint8Array.fromBase64(str, {alphabet: 'base64url'});
  }
  return base64Decode(str.replace(/-/g, '+').replace(/_/g, '/'));
}
