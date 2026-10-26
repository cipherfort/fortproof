// SPDX-License-Identifier: Apache-2.0
import { setPersona } from "./api";

// Demo personas (seeded by `aap demo seed`). Development sign-in only: in production people sign in through your OIDC
// identity provider and see what their role allows, exactly as these personas do.
export const PERSONAS = [
  { login: "ajones", name: "Amira Jones", role: "Security champion, Claims team" },
  { login: "ekim", name: "Eun Kim", role: "Engineer, Payments team" },
  { login: "gokafor", name: "Grace Okafor", role: "Engineer, People Systems team" },
  { login: "nhaddad", name: "Noor Haddad", role: "Engineer, not in a team yet (sees nothing until added)" },
  { login: "dlee", name: "Dana Lee", role: "Security lead, Benefits business unit" },
  { login: "cpatel", name: "Chandra Patel", role: "AppSec engineer (organisation-wide)" },
  { login: "fwong", name: "Farah Wong", role: "Executive (aggregates only)" },
  { login: "padmin", name: "Pat Admin", role: "Platform administrator (structure and access, no application data)" },
] as const;

// `?as=<login>` selects a demo persona (for links and screenshots). Only known personas are accepted.
const asParam = new URLSearchParams(window.location.search).get("as");
if (asParam && PERSONAS.some((p) => p.login === asParam)) setPersona(asParam);
