/*!
 * Copyright (c) 2021-2022 Digital Bazaar, Inc. All rights reserved.
 */
export function base64Decode(str) {
  return Buffer.from(str, 'base64');
}
