// SPDX-License-Identifier: Apache-2.0
import * as Tooltip from "@radix-ui/react-tooltip";
import { BookOpen, PanelLeftClose, PanelLeftOpen } from "lucide-react";
import { useState } from "react";
import { Link, useLocation } from "react-router";
import type { Me } from "../../api";
import { BRAND } from "../../brand";
import { Logo, LogoMark } from "./Logo";
import { isActive, NAV, visible } from "./nav";

const DOCS_URL = "https://fortproof.dev/";

function readCollapsed(): boolean {
  try {
    return window.localStorage.getItem("sidebar") === "collapsed";
  } catch {
    return false;
  }
}

export function Sidebar({ me }: { me: Me | undefined }) {
  const { pathname } = useLocation();
  const [collapsed, setCollapsed] = useState(readCollapsed);
  const toggle = () => {
    setCollapsed((c) => {
      try {
        window.localStorage.setItem("sidebar", c ? "expanded" : "collapsed");
      } catch {
        /* per-page only */
      }
      return !c;
    });
  };
  const item = (to: string, label: string, Icon: typeof BookOpen, active: boolean, external = false) => {
    const cls = `group relative flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-[13px] font-medium transition-colors ${
      active ? "bg-accent-soft text-ink" : "text-ink-2 hover:bg-surface-2 hover:text-ink"
    } ${collapsed ? "justify-center px-0" : ""}`;
    const body = (
      <>
        {active && <span aria-hidden="true" className="absolute inset-y-1 left-0 w-0.5 rounded-full bg-accent" />}
        <Icon aria-hidden="true" className="size-4 shrink-0" strokeWidth={1.75} />
        <span className={collapsed ? "sr-only" : ""}>{label}</span>
      </>
    );
    const link = external ? (
      <a href={to} target="_blank" rel="noreferrer" className={cls}>{body}</a>
    ) : (
      <Link to={to} aria-current={active ? "page" : undefined} className={cls}>{body}</Link>
    );
    if (!collapsed) return link;
    return (
      <Tooltip.Root>
        <Tooltip.Trigger asChild>{link}</Tooltip.Trigger>
        <Tooltip.Portal>
          <Tooltip.Content side="right" sideOffset={8} className="rounded-md border border-line bg-surface-3 px-2 py-1 text-xs text-ink shadow-card">
            {label}
          </Tooltip.Content>
        </Tooltip.Portal>
      </Tooltip.Root>
    );
  };
  return (
    <aside
      className={`print:hidden sticky top-0 flex h-screen shrink-0 flex-col border-r border-line bg-sidebar transition-[width] ${collapsed ? "w-16" : "w-60"}`}
    >
      <div className={`flex h-12 items-center border-b border-line ${collapsed ? "justify-center" : "px-4"}`}>
        <Link to="/" className="text-ink hover:no-underline" aria-label={`${BRAND.name} home`}>
          {collapsed ? <LogoMark /> : <Logo />}
        </Link>
      </div>
      <nav aria-label="Main navigation" className="flex-1 overflow-y-auto px-2 py-3">
        {NAV.map((group) => {
          const items = visible(group.items, me?.permissions);
          if (!items.length) return null;
          return (
            <div key={group.label} className="mb-4">
              <div className={`mb-1 px-2.5 text-[11px] font-semibold uppercase tracking-wider text-muted ${collapsed ? "sr-only" : ""}`}>
                {group.label}
              </div>
              <ul className="plain space-y-0.5">
                {items.map((i) => (
                  <li key={i.to}>{item(i.to, i.label, i.icon, isActive(i, pathname))}</li>
                ))}
              </ul>
            </div>
          );
        })}
      </nav>
      <div className="border-t border-line px-2 py-2">
        {item(DOCS_URL, "Documentation", BookOpen, false, true)}
        <button
          type="button"
          onClick={toggle}
          aria-label={collapsed ? "Expand the sidebar" : "Collapse the sidebar"}
          className={`mt-0.5 flex w-full items-center gap-2.5 rounded-md bg-transparent px-2.5 py-1.5 text-[13px] font-medium text-muted hover:bg-surface-2 hover:text-ink ${collapsed ? "justify-center px-0" : ""}`}
        >
          {collapsed ? <PanelLeftOpen className="size-4" strokeWidth={1.75} /> : <PanelLeftClose className="size-4" strokeWidth={1.75} />}
          <span className={collapsed ? "sr-only" : ""}>Collapse</span>
        </button>
      </div>
    </aside>
  );
}
