// SPDX-License-Identifier: Apache-2.0
// The product name lives here only, so a rename touches one line (and index.html's <title>).
export const BRAND = {
  name: "FortProof",
  tagline: "Evidence-driven application security assurance",
  docs: "https://fortproof.dev/",
} as const;

/** A page of the documentation site, e.g. docs("guide/connect-your-organization/#4-github-app"). */
export const docs = (path = ""): string => `${BRAND.docs}${path}`;
