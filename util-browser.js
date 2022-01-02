/*!
 * Copyright (c) 2021-2022 Digital Bazaar, Inc. All rights reserved.
 */

/* eslint-env browser */
export function base64Decode(str) {
  return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}
