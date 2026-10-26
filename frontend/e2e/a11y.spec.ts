// SPDX-License-Identifier: Apache-2.0
import AxeBuilder from "@axe-core/playwright";
import { expect, test, visit } from "./fixtures";

// WCAG 2.2 AA on every page, in both themes; the administrator pages as the platform administrator.
const PAGES = ["/", "nhaddad:/", "/apps", "/apps/APP-00001", "/apps/APP-00001/controls", "/apps/APP-00001/evidence", "/evidence", "/evidence/view/rejected", "/findings",
  "/controls", "/controls/ASC-BLD-02", "/maturity", "/supply-chain", "/apps/APP-00001/supply-chain", "/cve/CVE-2021-44228",
  "/exceptions", "/exceptions/EX-000002", "/exceptions/new", "/assessments", "/assessments/new", "/leadership", "/integrations", "/register",
  "padmin:/", "padmin:/admin", "padmin:/admin/roles", "padmin:/integrations/github"];

for (const theme of ["dark", "light"] as const) {
  for (const entry of PAGES) {
    const [who, path] = entry.includes(":") ? (entry.split(":") as [string, string]) : ["cpatel", entry];
    test(`${entry} meets WCAG 2.2 AA (${theme})`, async ({ page, problems }) => {
      void problems;
      await page.addInitScript((t) => window.localStorage.setItem("theme", t), theme);
      await visit(page, path, who);
      await expect(page.locator("main h1")).toBeVisible();
      await page.waitForLoadState("networkidle");
      const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]).analyze();
      const summary = results.violations.map((v) => `${v.id} (${v.impact}): ${v.nodes.length} × ${v.nodes[0]?.target.join(" ")}`);
      expect(summary).toEqual([]);
    });
  }
}
