import React from "react";
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import {
  AlertTriageBadge,
  IncidentStatusBadge,
  MockIntelBadge,
  RoleBadge,
  SeverityBadge,
  SimulatedBadge,
  SlaBadge,
} from "@/components/ui/badges";
import { OPENAPI_PATHS, SentinelApiError } from "@/lib/api/generated";

describe("M1 Vertical Slice UI & OpenAPI Client Contract", () => {
  it("renders operational severity, lifecycle, SLA, role, and safety badges accurately", () => {
    render(
      <div>
        <SeverityBadge severity="critical" />
        <IncidentStatusBadge status="CONTAINMENT" />
        <AlertTriageBadge status="incident_created" />
        <SlaBadge status="at_risk" />
        <SimulatedBadge />
        <MockIntelBadge />
        <RoleBadge role="soc_l2" />
      </div>
    );

    expect(screen.getByText("critical")).toBeTruthy();
    expect(screen.getByText("CONTAINMENT")).toBeTruthy();
    expect(screen.getByText("CASE LINKED")).toBeTruthy();
    expect(screen.getByText("SLA AT RISK (>75%)")).toBeTruthy();
    expect(screen.getByText("SIMULATED")).toBeTruthy();
    expect(screen.getByText("MOCK / SIMULATED")).toBeTruthy();
    expect(screen.getByText("SOC L2")).toBeTruthy();
  });

  it("exposes generated OpenAPI v1 routes and structured SentinelApiError", () => {
    expect(OPENAPI_PATHS["/api/v1/auth/login"]).toContain("POST");
    expect(OPENAPI_PATHS["/api/v1/ingest/wazuh"]).toContain("POST");
    expect(OPENAPI_PATHS["/api/v1/incidents"]).toContain("POST");
    expect(OPENAPI_PATHS["/api/v1/audit/verify"]).toContain("GET");

    const err = new SentinelApiError(
      403,
      "INSUFFICIENT_PERMISSIONS",
      "Forbidden",
      "corr-123"
    );
    expect(err.status).toBe(403);
    expect(err.code).toBe("INSUFFICIENT_PERMISSIONS");
    expect(err.correlationId).toBe("corr-123");
  });
});
