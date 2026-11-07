"use client";

import React, { useState } from "react";
import { useRouter } from "next/navigation";
import {
  AlertTriangle,
  CheckCircle2,
  KeyRound,
  Lock,
  ShieldCheck,
  Smartphone,
  UserCheck,
} from "lucide-react";
import {
  SentinelApiError,
  TotpSetupResponse,
  apiRequest,
} from "@/lib/api/generated";
import { useAuth, useToast } from "@/components/providers";
import { RoleBadge } from "@/components/ui/badges";
import { formatDateTime } from "@/lib/format";

export default function ProfileSecurityPage() {
  const { user, permissions, refreshProfile } = useAuth();
  const { pushToast } = useToast();
  const router = useRouter();

  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [changingPw, setChangingPw] = useState(false);

  const [totpSetup, setTotpSetup] = useState<TotpSetupResponse | null>(null);
  const [totpCode, setTotpCode] = useState("");
  const [mfaLoading, setMfaLoading] = useState(false);

  if (!user) return null;

  const handlePasswordChange = async (e: React.FormEvent) => {
    e.preventDefault();
    if (newPassword !== confirmPassword) {
      pushToast({
        title: "Passwords Do Not Match",
        description: "New password and confirmation must match.",
        variant: "error",
      });
      return;
    }
    setChangingPw(true);
    try {
      await apiRequest("/api/v1/auth/change-password", {
        method: "POST",
        body: {
          current_password: currentPassword,
          new_password: newPassword,
        },
      });
      pushToast({
        title: "Password Rotated — Please Sign In Again",
        description: "All active refresh-token families were revoked for session safety.",
        variant: "success",
      });
      router.replace("/login");
    } catch (err) {
      const msg = err instanceof SentinelApiError ? err.message : "Password change failed";
      pushToast({ title: "Password Rotation Failed", description: msg, variant: "error" });
    } finally {
      setChangingPw(false);
    }
  };

  const handleInitMfa = async () => {
    setMfaLoading(true);
    try {
      const res = await apiRequest<TotpSetupResponse>("/api/v1/auth/mfa/setup", {
        method: "POST",
      });
      setTotpSetup(res);
      pushToast({
        title: "TOTP Secret Generated",
        description: "Add the Base32 secret to your authenticator app and enter a 6-digit code.",
        variant: "info",
      });
    } catch (err) {
      const msg = err instanceof SentinelApiError ? err.message : "MFA setup failed";
      pushToast({ title: "MFA Setup Error", description: msg, variant: "error" });
    } finally {
      setMfaLoading(false);
    }
  };

  const handleEnableMfa = async (e: React.FormEvent) => {
    e.preventDefault();
    setMfaLoading(true);
    try {
      await apiRequest("/api/v1/auth/mfa/enable", {
        method: "POST",
        body: { code: totpCode },
      });
      setTotpSetup(null);
      setTotpCode("");
      await refreshProfile();
      pushToast({
        title: "Multi-Factor Authentication Enabled",
        description: "TOTP verification is now enforced on future sign-ins.",
        variant: "success",
      });
    } catch (err) {
      const msg = err instanceof SentinelApiError ? err.message : "Invalid TOTP code";
      pushToast({ title: "MFA Verification Failed", description: msg, variant: "error" });
    } finally {
      setMfaLoading(false);
    }
  };

  return (
    <div className="max-w-4xl space-y-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight flex items-center gap-2">
          <KeyRound className="w-5 h-5 text-sky-400" />
          Analyst Profile & Session Security
        </h1>
        <p className="text-xs text-soc-muted mt-1">
          Manage your Argon2id credentials, TOTP multi-factor enrollment, and inspect granted RBAC capabilities.
        </p>
      </div>

      {user.must_change_password && (
        <div className="rounded-lg border border-amber-500/40 bg-amber-500/15 p-4 text-xs text-amber-200 flex items-start gap-3">
          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          <div>
            <p className="font-semibold">Mandatory Password Rotation Required</p>
            <p className="mt-0.5 opacity-90">
              Your account is flagged with <code className="font-mono">must_change_password</code>. Rotate your password below to clear this notice.
            </p>
          </div>
        </div>
      )}

      {/* Identity Card */}
      <div className="rounded-lg border border-soc-border bg-soc-surface p-5">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-soc-border pb-4 mb-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-sky-500/15 border border-sky-500/30 text-sky-400">
              <UserCheck className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-semibold text-soc-text">{user.full_name}</h2>
              <p className="text-xs font-mono text-soc-muted">
                @{user.username} · {user.email}
              </p>
            </div>
          </div>
          <RoleBadge role={user.role} />
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs mb-4">
          <div>
            <span className="text-soc-muted block">Account Created</span>
            <span className="font-mono">{formatDateTime(user.created_at)}</span>
          </div>
          <div>
            <span className="text-soc-muted block">Last Authenticated</span>
            <span className="font-mono">{formatDateTime(user.last_login_at)}</span>
          </div>
          <div>
            <span className="text-soc-muted block">TOTP MFA Status</span>
            <span className="font-mono">
              {user.totp_enabled ? "Enrolled & Active" : "Not Enabled"}
            </span>
          </div>
        </div>

        <div>
          <span className="text-xs text-soc-muted block mb-2">
            Granted Session Permissions ({permissions.size})
          </span>
          <div className="flex flex-wrap gap-1.5">
            {Array.from(permissions)
              .sort()
              .map((perm) => (
                <span
                  key={perm}
                  className="px-2 py-0.5 rounded bg-soc-bg border border-soc-border font-mono text-[11px] text-soc-text"
                >
                  {perm}
                </span>
              ))}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Password Rotation */}
        <div className="rounded-lg border border-soc-border bg-soc-surface p-5">
          <h2 className="text-sm font-semibold flex items-center gap-2 mb-1">
            <Lock className="w-4 h-4 text-sky-400" />
            Rotate Password
          </h2>
          <p className="text-xs text-soc-muted mb-4">
            Minimum 12 characters including uppercase, lowercase, numeric, and special character. Rotating revokes all active refresh tokens.
          </p>

          <form onSubmit={handlePasswordChange} className="space-y-3 text-xs">
            <div>
              <label className="block text-soc-muted mb-1">Current Password</label>
              <input
                required
                type="password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                className="w-full rounded border border-soc-border bg-soc-bg px-3 py-2 font-mono text-soc-text"
              />
            </div>
            <div>
              <label className="block text-soc-muted mb-1">New Password</label>
              <input
                required
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="w-full rounded border border-soc-border bg-soc-bg px-3 py-2 font-mono text-soc-text"
              />
            </div>
            <div>
              <label className="block text-soc-muted mb-1">Confirm New Password</label>
              <input
                required
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className="w-full rounded border border-soc-border bg-soc-bg px-3 py-2 font-mono text-soc-text"
              />
            </div>
            <button
              type="submit"
              disabled={changingPw}
              className="w-full rounded bg-sky-500 py-2 font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-50"
            >
              {changingPw ? "Rotating Credentials..." : "Update Password"}
            </button>
          </form>
        </div>

        {/* TOTP MFA */}
        <div className="rounded-lg border border-soc-border bg-soc-surface p-5">
          <h2 className="text-sm font-semibold flex items-center gap-2 mb-1">
            <Smartphone className="w-4 h-4 text-sky-400" />
            TOTP Multi-Factor Authentication
          </h2>
          <p className="text-xs text-soc-muted mb-4">
            RFC 6238 time-based one-time passwords encrypted at rest with Fernet AES-128-CBC + HMAC.
          </p>

          {user.totp_enabled ? (
            <div className="rounded-md border border-emerald-500/35 bg-emerald-500/10 p-4 text-xs text-emerald-200 flex items-start gap-2.5">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold">TOTP Hardware/App Authenticator Active</p>
                <p className="mt-1 opacity-85">
                  Your account requires a 6-digit TOTP verification token during interactive sign-in.
                </p>
              </div>
            </div>
          ) : !totpSetup ? (
            <div className="space-y-3 text-xs">
              <div className="rounded-md border border-soc-border bg-soc-bg p-3 text-soc-muted">
                Enroll an authenticator app (1Password, Authy, Google Authenticator, or YubiKey Authenticator) for stronger SOC operator assurance.
              </div>
              <button
                type="button"
                disabled={mfaLoading}
                onClick={() => void handleInitMfa()}
                className="inline-flex items-center gap-1.5 rounded border border-sky-500/40 bg-sky-500/15 px-3.5 py-2 font-medium text-sky-300 hover:bg-sky-500/25 disabled:opacity-50"
              >
                <ShieldCheck className="w-4 h-4" />
                {mfaLoading ? "Generating Secret..." : "Begin TOTP Enrollment"}
              </button>
            </div>
          ) : (
            <form onSubmit={handleEnableMfa} className="space-y-3 text-xs">
              <div className="rounded-md border border-soc-border bg-soc-bg p-3 space-y-2">
                <div>
                  <span className="text-soc-muted block">Base32 Secret Key</span>
                  <code className="font-mono text-emerald-300 break-all select-all">
                    {totpSetup.secret}
                  </code>
                </div>
                <div>
                  <span className="text-soc-muted block">Provisioning URI</span>
                  <code className="font-mono text-[10px] text-soc-muted break-all">
                    {totpSetup.provisioning_uri}
                  </code>
                </div>
              </div>
              <div>
                <label className="block text-soc-muted mb-1">6-Digit Authenticator Code</label>
                <input
                  required
                  pattern="[0-9]{6}"
                  maxLength={6}
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value)}
                  placeholder="123456"
                  className="w-full rounded border border-soc-border bg-soc-bg px-3 py-2 font-mono tracking-widest text-soc-text"
                />
              </div>
              <button
                type="submit"
                disabled={mfaLoading}
                className="w-full rounded bg-emerald-500 py-2 font-semibold text-slate-950 hover:bg-emerald-400 disabled:opacity-50"
              >
                {mfaLoading ? "Verifying..." : "Verify & Enable TOTP"}
              </button>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}

