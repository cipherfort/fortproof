// SPDX-License-Identifier: Apache-2.0
import { useQuery } from "@tanstack/react-query";
import { Check } from "lucide-react";
import type { ReactNode } from "react";
import { Link } from "react-router";
import { api } from "../../api";
import { ButtonLink } from "../ui/Button";
import { Card } from "../ui/Card";

interface Item { title: string; body: ReactNode; done: boolean | null; action?: ReactNode; unknown?: string }

/** First-run checklist. A step is ticked only when the platform can see it is done; a step it cannot check
 *  (publishing the pipelines happens in your source control) is never ticked for you. */
export function GettingStarted({ perms, apps }: { perms: Set<string>; apps: number | null }) {
  const canIntegrations = perms.has("integration.read");
  const integrations = useQuery({ queryKey: ["integrations"], queryFn: api.integrations, enabled: canIntegrations });
  const on = (...keys: string[]) => (integrations.data ? integrations.data.items.some((i) => keys.includes(i.key) && i.configured) : null);
  const items: Item[] = [
    {
      title: "Connect sign-in",
      body: "People sign in through your identity provider (OIDC). Until then the platform only runs in development mode.",
      done: on("oidc"),
      action: canIntegrations && <Link to="/integrations/oidc">Set up sign-in</Link>,
    },
    {
      title: "Connect source control",
      body: "The GitHub App or GitLab integration reads repository settings and receives evidence from pipelines.",
      done: on("github", "gitlab"),
      action: canIntegrations && <Link to="/integrations/github">Set up GitHub</Link>,
    },
    {
      title: "Publish the security pipelines",
      body: <>Copy the shared workflows into your organisation (<code>pipelines/</code>) and call them from each repository. Only evidence from approved workflows counts.</>,
      done: null,
      unknown: "done in your source control",
    },
    {
      title: "Register your first application",
      body: "Add .security/application.yaml to the repository and register it; its risk tier decides which controls apply.",
      done: apps === null ? null : apps > 0,
      unknown: "done by an application team",
      action: perms.has("application.register") && <ButtonLink to="/register" variant="primary" size="sm">Register an application</ButtonLink>,
    },
  ];
  const known = items.filter((i) => i.done !== null);
  const doneCount = known.filter((i) => i.done).length;
  return (
    <Card title="Get started" description={`${doneCount} of ${items.length} steps done. Controls are evaluated as soon as evidence arrives; until then they show No evidence, never a pass.`}>
      <ol className="plain m-0 p-0" aria-label="Getting started steps">
        {items.map((it, n) => (
          <li key={it.title} className="flex gap-3 border-b border-line py-3 first:pt-0 last:border-b-0 last:pb-0">
            <span className={`mt-0.5 flex size-6 shrink-0 items-center justify-center rounded-full border text-xs font-semibold ${it.done ? "border-good/50 text-good" : "border-line-strong text-ink-2"}`}>
              {it.done ? <Check className="size-3.5" aria-label="done" /> : n + 1}
            </span>
            <div className="min-w-0 flex-1">
              <div className="text-[13px] font-semibold text-ink">{it.title}{it.done === null && it.unknown && <span className="ml-2 text-xs font-normal text-muted">{it.unknown}</span>}</div>
              <p className="m-0 mt-0.5 text-[13px] text-ink-2">{it.body}</p>
              {!it.done && it.action && <div className="mt-2 text-[13px]">{it.action}</div>}
            </div>
          </li>
        ))}
      </ol>
    </Card>
  );
}
