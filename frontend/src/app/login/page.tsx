"use client";

import React, { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { KeyRound, Lock, ShieldAlert } from "lucide-react";
import { useAuth } from "@/components/providers";
import { SentinelApiError } from "@/lib/api/generated";

const loginSchema = z.object({
  identifier: z.string().min(2, "Enter your SOC username or email"),
  password: z.string().min(1, "Password is required"),
  totpCode: z.string().optional(),
});

type LoginFormValues = z.infer<typeof loginSchema>;

const DEV_DEMO_ACCOUNTS = [
  { role: "SOC L1", username: "l1.analyst" },
  { role: "SOC L2", username: "l2.analyst" },
  { role: "SOC Manager", username: "soc.manager" },
  { role: "Admin", username: "admin" },
];

export default function LoginPage() {
  const { login } = useAuth();
  const [serverError, setServerError] = useState<string | null>(null);
  const [mfaPrompted, setMfaPrompted] = useState(false);

  const {
    register,
    handleSubmit,
    setValue,
    formState: { errors, isSubmitting },
  } = useForm<LoginFormValues>({
    resolver: zodResolver(loginSchema),
    defaultValues: { identifier: "", password: "", totpCode: "" },
  });

  const onSubmit = async (values: LoginFormValues) => {
    setServerError(null);
    try {
      await login(values.identifier, values.password, values.totpCode);
    } catch (err) {
      if (err instanceof SentinelApiError) {
        if (err.code === "MFA_REQUIRED") {
          setMfaPrompted(true);
          setServerError("Enter your 6-digit TOTP authenticator code to complete sign-in.");
          return;
        }
        setServerError(err.message);
      } else {
        setServerError("Unable to reach SENTINEL IR authentication service.");
      }
    }
  };

  const fillDemoAccount = (username: string) => {
    setValue("identifier", username, { shouldValidate: true });
    setValue("password", "SentinelDemo!2026#SOC", { shouldValidate: true });
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-soc-bg px-4 py-12">
      <div className="w-full max-w-md space-y-6">
        <div className="rounded-lg border border-soc-border bg-soc-surface p-8 shadow-2xl">
          <div className="flex items-center gap-3 mb-6">
            <div className="p-2.5 rounded-md bg-sky-500/15 border border-sky-500/30 text-sky-400">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-lg font-semibold tracking-tight text-soc-text">SENTINEL IR</h1>
              <p className="text-[11px] font-mono uppercase tracking-wider text-soc-muted">
                Security Incident Response &amp; SOAR
              </p>
            </div>
          </div>

          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4" noValidate>
            <div>
              <label
                htmlFor="identifier"
                className="block text-xs font-medium text-soc-muted mb-1.5"
              >
                Analyst Username or Email
              </label>
              <input
                id="identifier"
                type="text"
                autoComplete="username"
                {...register("identifier")}
                placeholder="l2.analyst"
                className="w-full rounded-md border border-soc-border bg-soc-bg px-3 py-2 text-sm text-soc-text placeholder:text-soc-muted/60 focus:outline-none focus:border-sky-500"
              />
              {errors.identifier && (
                <p className="text-xs text-red-400 mt-1">{errors.identifier.message}</p>
              )}
            </div>

            <div>
              <label
                htmlFor="password"
                className="block text-xs font-medium text-soc-muted mb-1.5"
              >
                Password
              </label>
              <input
                id="password"
                type="password"
                autoComplete="current-password"
                {...register("password")}
                placeholder="••••••••••••"
                className="w-full rounded-md border border-soc-border bg-soc-bg px-3 py-2 text-sm text-soc-text placeholder:text-soc-muted/60 focus:outline-none focus:border-sky-500"
              />
              {errors.password && (
                <p className="text-xs text-red-400 mt-1">{errors.password.message}</p>
              )}
            </div>

            {mfaPrompted && (
              <div>
                <label
                  htmlFor="totpCode"
                  className="block text-xs font-medium text-soc-muted mb-1.5"
                >
                  TOTP Authenticator Code
                </label>
                <input
                  id="totpCode"
                  type="text"
                  inputMode="numeric"
                  {...register("totpCode")}
                  placeholder="123456"
                  className="w-full rounded-md border border-soc-border bg-soc-bg px-3 py-2 text-sm font-mono text-soc-text focus:outline-none focus:border-sky-500"
                />
              </div>
            )}

            {serverError && (
              <div
                role="alert"
                className="rounded-md border border-red-500/35 bg-red-500/10 px-3 py-2.5 text-xs text-red-300"
              >
                {serverError}
              </div>
            )}

            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full inline-flex items-center justify-center gap-2 rounded-md bg-sky-600 hover:bg-sky-500 disabled:opacity-50 px-4 py-2.5 text-sm font-medium text-white transition-colors"
            >
              <Lock className="w-4 h-4" />
              {isSubmitting ? "Authenticating..." : "Authenticate to SOC"}
            </button>
          </form>

          {/* Local Demo Role Selector (Development Only — Seeded Accounts Refused in Prod) */}
          <div className="mt-6 pt-5 border-t border-soc-border">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[11px] font-mono uppercase tracking-wider text-amber-300 flex items-center gap-1.5">
                <KeyRound className="w-3.5 h-3.5" />
                Dev Lab Quick-Fill (Disabled in Prod)
              </span>
            </div>
            <div className="grid grid-cols-2 gap-2">
              {DEV_DEMO_ACCOUNTS.map((acct) => (
                <button
                  key={acct.username}
                  type="button"
                  onClick={() => fillDemoAccount(acct.username)}
                  className="rounded border border-soc-border bg-soc-bg hover:bg-soc-elevated px-2.5 py-1.5 text-left transition-colors"
                >
                  <span className="block text-xs font-medium text-soc-text">{acct.role}</span>
                  <span className="block text-[10px] font-mono text-soc-muted">
                    {acct.username}
                  </span>
                </button>
              ))}
            </div>
          </div>
        </div>

        <p className="text-center text-[11px] text-soc-muted">
          Authorized Security Operations Personnel Only. All authentication events and actions are
          recorded in a cryptographically hash-chained audit trail.
        </p>
      </div>
    </div>
  );
}

