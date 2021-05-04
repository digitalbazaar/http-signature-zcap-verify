/*!
 * Copyright (c) 2020-2021 Digital Bazaar, Inc. All rights reserved.
 */
import {securityLoader} from '@digitalbazaar/security-document-loader';
import aesContext from 'aes-key-wrapping-2019-context';
import hmacContext from 'sha256-hmac-key-2019-context';
import secCtx from '@digitalbazaar/security-context';
import zcapCtx from 'zcap-context';

const loader = securityLoader();
loader.addStatic(zcapCtx.CONTEXT_URL, zcapCtx.CONTEXT);
loader.addStatic(
  aesContext.constants.CONTEXT_URL, aesContext.contexts);
loader.addStatic(
  hmacContext.constants.CONTEXT_URL, hmacContext.contexts);
loader.addStatic(
  secCtx.SECURITY_CONTEXT_V2_URL,
  secCtx.contexts.get(secCtx.SECURITY_CONTEXT_V2_URL)
);
loader.addStatic(
  secCtx.SECURITY_CONTEXT_V1_URL,
  secCtx.contexts.get(secCtx.SECURITY_CONTEXT_V1_URL)
);

export const securityDocumentLoader = loader.build();
