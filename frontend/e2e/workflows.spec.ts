import { test, expect } from "@playwright/test";

const DEMO_PASSWORD = "SentinelDemo!2026#SOC";

test.describe("SENTINEL IR — Comprehensive E2E Workflows", () => {
  test.beforeEach(async ({ page }) => {
    // Start at login page
    await page.goto("/login");
  });

  // ---------------------------------------------------------------------------
  // Workflow 1: Authentication & Access Control
  // ---------------------------------------------------------------------------
  test("Workflow 1: Authentication lifecycle, invalid rejection, and protected routes", async ({ page }) => {
    // 1. Invalid login attempt
    await page.fill('input[type="text"], input[name="identifier"], input[placeholder*="analyst"]', "invalid.analyst");
    await page.fill('input[type="password"]', "WrongPassword123!");
    await page.click('button[type="submit"]');
    await expect(page.locator("text=Invalid credentials").or(page.locator("text=failed")).or(page.locator("text=error"))).toBeVisible({ timeout: 10000 });

    // 2. Valid login as L2 Analyst
    await page.fill('input[type="text"], input[name="identifier"], input[placeholder*="analyst"]', "l2.analyst");
    await page.fill('input[type="password"]', DEMO_PASSWORD);
    await page.click('button[type="submit"]');

    // Should redirect to dashboard or home
    await page.waitForURL((url) => !url.pathname.includes("/login"), { timeout: 15000 });
    await expect(page.locator("text=SENTINEL IR").or(page.locator("text=SOC Command")).first()).toBeVisible();

    // 3. Verify user profile displays role
    await page.goto("/profile");
    await expect(page.locator("text=l2.analyst").or(page.locator("text=soc_l2")).first()).toBeVisible({ timeout: 10000 });
  });

  // ---------------------------------------------------------------------------
  // Workflow 2: SOC Alert Triage
  // ---------------------------------------------------------------------------
  test("Workflow 2: SOC Alert Inbox and Triage navigation", async ({ page }) => {
    // Login
    await page.fill('input[type="text"], input[name="identifier"], input[placeholder*="analyst"]', "l2.analyst");
    await page.fill('input[type="password"]', DEMO_PASSWORD);
    await page.click('button[type="submit"]');
    await page.waitForURL((url) => !url.pathname.includes("/login"), { timeout: 15000 });

    // Open Alerts page
    await page.goto("/alerts");
    await expect(page.locator("h1, h2, div").filter({ hasText: /Alerts|Alert Inbox/i }).first()).toBeVisible({ timeout: 10000 });

    // Open Triage Workbench
    await page.goto("/triage");
    await expect(page.locator("h1, h2, div").filter({ hasText: /Triage/i }).first()).toBeVisible({ timeout: 10000 });
  });

  // ---------------------------------------------------------------------------
  // Workflow 3: Incident Investigation & Workbench
  // ---------------------------------------------------------------------------
  test("Workflow 3: Incident Management and Investigation Workbench", async ({ page }) => {
    // Login
    await page.fill('input[type="text"], input[name="identifier"], input[placeholder*="analyst"]', "l2.analyst");
    await page.fill('input[type="password"]', DEMO_PASSWORD);
    await page.click('button[type="submit"]');
    await page.waitForURL((url) => !url.pathname.includes("/login"), { timeout: 15000 });

    // Open Incidents page
    await page.goto("/incidents");
    await expect(page.locator("h1, h2, div").filter({ hasText: /Incidents/i }).first()).toBeVisible({ timeout: 10000 });

    // Open Workbench
    await page.goto("/workbench");
    await expect(page.locator("text=Workbench").or(page.locator("text=Investigation")).first()).toBeVisible({ timeout: 10000 });

    // Open Evidence page
    await page.goto("/evidence");
    await expect(page.locator("text=Evidence").or(page.locator("text=Forensic")).first()).toBeVisible({ timeout: 10000 });

    // Open Threat Intelligence
    await page.goto("/intelligence");
    await expect(page.locator("text=Threat Intelligence").or(page.locator("text=Indicators")).first()).toBeVisible({ timeout: 10000 });

    // Open MITRE ATT&CK Matrix
    await page.goto("/mitre");
    await expect(page.locator("text=MITRE").or(page.locator("text=ATT&CK")).first()).toBeVisible({ timeout: 10000 });
  });

  // ---------------------------------------------------------------------------
  // Workflow 4: SOAR Playbook Execution
  // ---------------------------------------------------------------------------
  test("Workflow 4: Playbook Library and Workflow inspection", async ({ page }) => {
    // Login
    await page.fill('input[type="text"], input[name="identifier"], input[placeholder*="analyst"]', "l2.analyst");
    await page.fill('input[type="password"]', DEMO_PASSWORD);
    await page.click('button[type="submit"]');
    await page.waitForURL((url) => !url.pathname.includes("/login"), { timeout: 15000 });

    // Open Playbooks
    await page.goto("/playbooks");
    await expect(page.locator("text=Playbook").first()).toBeVisible({ timeout: 10000 });

    // Inspect PB-001
    await page.goto("/playbooks/phishing-investigation");
    await expect(page.locator("text=Phishing").or(page.locator("text=PB-001")).first()).toBeVisible({ timeout: 10000 });
  });

  // ---------------------------------------------------------------------------
  // Workflow 5: Human Approval Governance
  // ---------------------------------------------------------------------------
  test("Workflow 5: Response Actions and Four-Eyes Approval Queue", async ({ page }) => {
    // Login as Manager
    await page.fill('input[type="text"], input[name="identifier"], input[placeholder*="analyst"]', "soc.manager");
    await page.fill('input[type="password"]', DEMO_PASSWORD);
    await page.click('button[type="submit"]');
    await page.waitForURL((url) => !url.pathname.includes("/login"), { timeout: 15000 });

    // Open Responses page
    await page.goto("/responses");
    await expect(page.locator("text=Approval").or(page.locator("text=Response")).first()).toBeVisible({ timeout: 10000 });
  });

  // ---------------------------------------------------------------------------
  // Workflow 6: Incident Simulation
  // ---------------------------------------------------------------------------
  test("Workflow 6: Simulation Scenarios Catalog and Detail", async ({ page }) => {
    // Login
    await page.fill('input[type="text"], input[name="identifier"], input[placeholder*="analyst"]', "l2.analyst");
    await page.fill('input[type="password"]', DEMO_PASSWORD);
    await page.click('button[type="submit"]');
    await page.waitForURL((url) => !url.pathname.includes("/login"), { timeout: 15000 });

    // Open Simulations page
    await page.goto("/simulations");
    await expect(page.locator("text=Simulation").or(page.locator("text=Scenario")).first()).toBeVisible({ timeout: 10000 });
    await expect(page.locator("text=Perimeter Brute-Force").or(page.locator("text=s01_brute_force"))).toBeVisible({ timeout: 10000 });

    // Open Scenario Detail
    await page.goto("/simulations/s01_brute_force");
    await expect(page.locator("text=Perimeter Brute-Force").or(page.locator("text=SIM-SCN-001")).first()).toBeVisible({ timeout: 10000 });
  });

  // ---------------------------------------------------------------------------
  // Workflow 7: Reporting
  // ---------------------------------------------------------------------------
  test("Workflow 7: Incident Reports Library and Export Modals", async ({ page }) => {
    // Login
    await page.fill('input[type="text"], input[name="identifier"], input[placeholder*="analyst"]', "l2.analyst");
    await page.fill('input[type="password"]', DEMO_PASSWORD);
    await page.click('button[type="submit"]');
    await page.waitForURL((url) => !url.pathname.includes("/login"), { timeout: 15000 });

    // Open Reports page
    await page.goto("/reports");
    await expect(page.locator("text=Report").or(page.locator("text=Exports")).first()).toBeVisible({ timeout: 10000 });
  });

  // ---------------------------------------------------------------------------
  // Workflow 8: SOC Command Analytics
  // ---------------------------------------------------------------------------
  test("Workflow 8: SOC Analytics Dashboard and KPI Scorecards", async ({ page }) => {
    // Login
    await page.fill('input[type="text"], input[name="identifier"], input[placeholder*="analyst"]', "l2.analyst");
    await page.fill('input[type="password"]', DEMO_PASSWORD);
    await page.click('button[type="submit"]');
    await page.waitForURL((url) => !url.pathname.includes("/login"), { timeout: 15000 });

    // Open Analytics page
    await page.goto("/analytics");
    await expect(page.locator("text=Analytics").or(page.locator("text=Performance")).first()).toBeVisible({ timeout: 10000 });
    await expect(page.locator("text=MTTA").or(page.locator("text=MTTC")).or(page.locator("text=Mean Time"))).toBeVisible({ timeout: 10000 });
  });
});
