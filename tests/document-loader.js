/*!
 * Copyright (c) 2020-2025 Digital Bazaar, Inc. All rights reserved.
 */
import secCtx from '@digitalbazaar/security-context';
import {securityLoader} from '@digitalbazaar/security-document-loader';
import zcapCtx from 'zcap-context';

const loader = securityLoader();
loader.addStatic(zcapCtx.CONTEXT_URL, zcapCtx.CONTEXT);
loader.addStatic(
  secCtx.SECURITY_CONTEXT_V2_URL,
  secCtx.contexts.get(secCtx.SECURITY_CONTEXT_V2_URL)
);
loader.addStatic(
  secCtx.SECURITY_CONTEXT_V1_URL,
  secCtx.contexts.get(secCtx.SECURITY_CONTEXT_V1_URL)
);

export const securityDocumentLoader = loader.build();
