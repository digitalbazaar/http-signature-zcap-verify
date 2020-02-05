// browser TextDecoder/TextEncoder
/* eslint-env browser */
const TextDecoder = self.TextDecoder;
const TextEncoder = self.TextEncoder;
export {TextDecoder, TextEncoder};

// TODO: replace these with faster base64 implementation

export function base64Encode(data) {
  return btoa(String.fromCharCode.apply(null, data));
}

export function base64Decode(str) {
  return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}
