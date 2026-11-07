"use client";

import React, { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Check,
  Edit3,
  KeyRound,
  Plus,
  Shield,
  ShieldAlert,
  Unlock,
  Users,
  X,
} from "lucide-react";
import {
  CreateUserRequest,
  RoleMatrixEntryOut,
  SentinelApiError,
  UpdateUserRequest,
  UserSummaryOut,
  apiRequest,
} from "@/lib/api/generated";
import { useAuth, useToast } from "@/components/providers";
import { RoleBadge } from "@/components/ui/badges";
import { Modal } from "@/components/ui/modal";
import { formatDateTime } from "@/lib/format";

export default function AnalystManagementPage() {
  const { hasPermission, user: currentUser } = useAuth();
  const { pushToast } = useToast();
  const queryClient = useQueryClient();

  const canRead = hasPermission("users:read");
  const canManage = hasPermission("users:manage");

  const [createOpen, setCreateOpen] = useState(false);
  const [editingUser, setEditingUser] = useState<UserSummaryOut | null>(null);

  const [newUsername, setNewUsername] = useState("");
  const [newEmail, setNewEmail] = useState("");
  const [newFullName, setNewFullName] = useState("");
  const [newRole, setNewRole] = useState<CreateUserRequest["role"]>("soc_l1");
  const [newPassword, setNewPassword] = useState("");
  const [newMustChange, setNewMustChange] = useState(true);

  const [editFullName, setEditFullName] = useState("");
  const [editRole, setEditRole] = useState<NonNullable<UpdateUserRequest["role"]>>("soc_l1");
  const [editActive, setEditActive] = useState(true);
  const [editUnlock, setEditUnlock] = useState(false);

  const usersQuery = useQuery({
    queryKey: ["users-roster"],
    enabled: canRead,
    queryFn: () => apiRequest<UserSummaryOut[]>("/api/v1/users"),
  });

  const matrixQuery = useQuery({
    queryKey: ["role-matrix"],
    enabled: canRead,
    queryFn: () => apiRequest<RoleMatrixEntryOut[]>("/api/v1/users/roles/matrix"),
  });

  const allPermissions = useMemo(() => {
    const perms = new Set<string>();
    for (const entry of matrixQuery.data || []) {
      for (const p of entry.permissions) {
        perms.add(p);
      }
    }
    return Array.from(perms).sort();
  }, [matrixQuery.data]);

  const createMutation = useMutation({
    mutationFn: (payload: CreateUserRequest) =>
      apiRequest<UserSummaryOut>("/api/v1/users", {
        method: "POST",
        body: payload,
      }),
    onSuccess: (created) => {
      pushToast({
        title: "Analyst Provisioned",
        description: `Created @${created.username} (${created.role}).`,
        variant: "success",
      });
      setCreateOpen(false);
      setNewUsername("");
      setNewEmail("");
      setNewFullName("");
      setNewPassword("");
      void queryClient.invalidateQueries({ queryKey: ["users-roster"] });
    },
    onError: (err) => {
      const msg = err instanceof SentinelApiError ? err.message : "Failed to create analyst";
      pushToast({ title: "Provisioning Failed", description: msg, variant: "error" });
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ userId, payload }: { userId: string; payload: UpdateUserRequest }) =>
      apiRequest<UserSummaryOut>(`/api/v1/users/${userId}`, {
        method: "PATCH",
        body: payload,
      }),
    onSuccess: (updated) => {
      pushToast({
        title: "Analyst Account Updated",
        description: `Saved changes for @${updated.username}.`,
        variant: "success",
      });
      setEditingUser(null);
      void queryClient.invalidateQueries({ queryKey: ["users-roster"] });
    },
    onError: (err) => {
      const msg = err instanceof SentinelApiError ? err.message : "Failed to update user";
      pushToast({ title: "Update Failed", description: msg, variant: "error" });
    },
  });

  const openEditModal = (target: UserSummaryOut) => {
    setEditingUser(target);
    setEditFullName(target.full_name);
    setEditRole((target.role as NonNullable<UpdateUserRequest["role"]>) || "soc_l1");
    setEditActive(target.is_active);
    setEditUnlock(false);
  };

  if (!canRead) {
    return (
      <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-6 text-sm text-red-200">
        <div className="flex items-center gap-2 font-semibold text-red-300 mb-1">
          <ShieldAlert className="w-4 h-4" />
          Restricted Access
        </div>
        You do not have permission (<code className="font-mono">users:read</code>) to view the SOC
        analyst roster.
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight flex items-center gap-2">
            <Users className="w-5 h-5 text-sky-400" />
            SOC Analyst Roster & RBAC Matrix
          </h1>
          <p className="text-xs text-soc-muted mt-1">
            Role-based access control across L1 Triage, L2 Investigation, SOC Management, and Platform Administration.
          </p>
        </div>

        {canManage && (
          <button
            type="button"
            onClick={() => setCreateOpen(true)}
            className="inline-flex items-center gap-1.5 rounded-md bg-sky-500 px-3.5 py-2 text-xs font-semibold text-slate-950 hover:bg-sky-400 transition-colors"
          >
            <Plus className="w-4 h-4" />
            Provision Analyst
          </button>
        )}
      </div>

      {/* Analyst Roster Table */}
      <div className="rounded-lg border border-soc-border bg-soc-surface overflow-hidden">
        <div className="border-b border-soc-border px-4 py-3 flex items-center justify-between">
          <h2 className="text-sm font-semibold">Active & Provisioned SOC Personnel</h2>
          <span className="text-xs font-mono text-soc-muted">
            {usersQuery.data?.length ?? 0} accounts
          </span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-soc-border bg-soc-elevated/60 text-[11px] uppercase tracking-wider text-soc-muted">
              <tr>
                <th className="px-4 py-3 font-semibold">Analyst</th>
                <th className="px-4 py-3 font-semibold">Role</th>
                <th className="px-4 py-3 font-semibold">Status</th>
                <th className="px-4 py-3 font-semibold">MFA (TOTP)</th>
                <th className="px-4 py-3 font-semibold">Last Login</th>
                {canManage && <th className="px-4 py-3 font-semibold text-right">Manage</th>}
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-border">
              {usersQuery.isLoading ? (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-soc-muted">
                    Loading SOC analyst roster...
                  </td>
                </tr>
              ) : (
                usersQuery.data?.map((u) => (
                  <tr key={u.id} className="hover:bg-soc-elevated/40 transition-colors">
                    <td className="px-4 py-3">
                      <div className="font-medium text-soc-text flex items-center gap-2">
                        <span>{u.full_name}</span>
                        {u.is_demo_user && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-amber-500/15 text-amber-300 border border-amber-500/30">
                            DEMO
                          </span>
                        )}
                      </div>
                      <div className="text-[11px] font-mono text-soc-muted">
                        @{u.username} · {u.email}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <RoleBadge role={u.role} />
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`inline-flex px-2 py-0.5 rounded text-[10px] font-mono uppercase border ${
                          u.is_active
                            ? "bg-emerald-500/15 text-emerald-300 border-emerald-500/30"
                            : "bg-slate-500/20 text-slate-400 border-slate-500/30"
                        }`}
                      >
                        {u.is_active ? "Active" : "Suspended"}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`inline-flex items-center gap-1 text-[11px] font-mono ${
                          u.totp_enabled ? "text-emerald-400" : "text-soc-muted"
                        }`}
                      >
                        <KeyRound className="w-3 h-3" />
                        {u.totp_enabled ? "Enabled" : "Not enrolled"}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-soc-muted">
                      {formatDateTime(u.last_login_at)}
                    </td>
                    {canManage && (
                      <td className="px-4 py-3 text-right">
                        <button
                          type="button"
                          onClick={() => openEditModal(u)}
                          className="inline-flex items-center gap-1 rounded border border-soc-border bg-soc-bg px-2.5 py-1 text-[11px] text-soc-text hover:border-sky-500/40"
                        >
                          <Edit3 className="w-3 h-3 text-sky-400" />
                          Configure
                        </button>
                      </td>
                    )}
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* RBAC Matrix */}
      <div className="rounded-lg border border-soc-border bg-soc-surface overflow-hidden">
        <div className="border-b border-soc-border px-4 py-3 flex items-center gap-2">
          <Shield className="w-4 h-4 text-sky-400" />
          <div>
            <h2 className="text-sm font-semibold">Centralized Role Permission Matrix</h2>
            <p className="text-[11px] text-soc-muted">
              Enforced server-side on every API route via <code className="font-mono">require_permission()</code>.
            </p>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-soc-border bg-soc-elevated/60 text-[11px] uppercase tracking-wider text-soc-muted">
              <tr>
                <th className="px-4 py-2.5 font-semibold">Permission Code</th>
                {matrixQuery.data?.map((r) => (
                  <th key={r.role} className="px-4 py-2.5 font-semibold text-center">
                    {r.display_name}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-border">
              {allPermissions.map((perm) => (
                <tr key={perm} className="hover:bg-soc-elevated/30">
                  <td className="px-4 py-2 font-mono text-[11px] text-soc-text">{perm}</td>
                  {matrixQuery.data?.map((r) => {
                    const granted = r.permissions.includes(perm);
                    return (
                      <td key={`${r.role}-${perm}`} className="px-4 py-2 text-center">
                        {granted ? (
                          <Check className="w-4 h-4 text-emerald-400 inline-block" aria-label="Granted" />
                        ) : (
                          <X className="w-3.5 h-3.5 text-soc-muted/40 inline-block" aria-label="Denied" />
                        )}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Create Analyst Modal */}
      <Modal
        open={createOpen}
        title="Provision New SOC Analyst"
        description="Accounts use Argon2id password hashing and enforce complexity checks."
        onClose={() => setCreateOpen(false)}
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            createMutation.mutate({
              username: newUsername,
              email: newEmail,
              full_name: newFullName,
              role: newRole,
              password: newPassword,
              must_change_password: newMustChange,
            });
          }}
          className="space-y-3.5 text-xs"
        >
          <div>
            <label className="block text-soc-muted mb-1">Full Name</label>
            <input
              required
              value={newFullName}
              onChange={(e) => setNewFullName(e.target.value)}
              placeholder="Elena Rostova"
              className="w-full rounded border border-soc-border bg-soc-bg px-3 py-2 text-soc-text"
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-soc-muted mb-1">Username</label>
              <input
                required
                value={newUsername}
                onChange={(e) => setNewUsername(e.target.value)}
                placeholder="elena.l2"
                className="w-full rounded border border-soc-border bg-soc-bg px-3 py-2 font-mono text-soc-text"
              />
            </div>
            <div>
              <label className="block text-soc-muted mb-1">SOC Role</label>
              <select
                value={newRole}
                onChange={(e) => setNewRole(e.target.value as CreateUserRequest["role"])}
                className="w-full rounded border border-soc-border bg-soc-bg px-3 py-2 text-soc-text"
              >
                <option value="soc_l1">SOC Analyst L1</option>
                <option value="soc_l2">SOC Analyst L2</option>
                <option value="soc_manager">SOC Manager</option>
                <option value="admin">Platform Administrator</option>
              </select>
            </div>
          </div>
          <div>
            <label className="block text-soc-muted mb-1">Enterprise Email</label>
            <input
              required
              type="email"
              value={newEmail}
              onChange={(e) => setNewEmail(e.target.value)}
              placeholder="elena.rostova@sentinel.example"
              className="w-full rounded border border-soc-border bg-soc-bg px-3 py-2 text-soc-text"
            />
          </div>
          <div>
            <label className="block text-soc-muted mb-1">Initial Temporary Password</label>
            <input
              required
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="Min 12 chars, upper, lower, digit, symbol"
              className="w-full rounded border border-soc-border bg-soc-bg px-3 py-2 font-mono text-soc-text"
            />
          </div>
          <label className="flex items-center gap-2 text-soc-muted cursor-pointer">
            <input
              type="checkbox"
              checked={newMustChange}
              onChange={(e) => setNewMustChange(e.target.checked)}
            />
            Require password rotation on first login
          </label>
          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={() => setCreateOpen(false)}
              className="rounded border border-soc-border px-3 py-1.5 text-soc-muted hover:text-soc-text"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={createMutation.isPending}
              className="rounded bg-sky-500 px-4 py-1.5 font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-50"
            >
              {createMutation.isPending ? "Provisioning..." : "Create Account"}
            </button>
          </div>
        </form>
      </Modal>

      {/* Edit Analyst Modal */}
      <Modal
        open={Boolean(editingUser)}
        title={editingUser ? `Configure @${editingUser.username}` : "Configure Analyst"}
        description="Role assignments and lockouts take effect immediately and are recorded in audit_logs."
        onClose={() => setEditingUser(null)}
      >
        {editingUser && (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              updateMutation.mutate({
                userId: editingUser.id,
                payload: {
                  full_name: editFullName,
                  role: editRole,
                  is_active: editActive,
                  unlock_account: editUnlock,
                },
              });
            }}
            className="space-y-3.5 text-xs"
          >
            <div>
              <label className="block text-soc-muted mb-1">Full Name</label>
              <input
                required
                value={editFullName}
                onChange={(e) => setEditFullName(e.target.value)}
                className="w-full rounded border border-soc-border bg-soc-bg px-3 py-2 text-soc-text"
              />
            </div>
            <div>
              <label className="block text-soc-muted mb-1">Assigned Role</label>
              <select
                value={editRole}
                disabled={editingUser.id === currentUser?.id}
                onChange={(e) =>
                  setEditRole(e.target.value as NonNullable<UpdateUserRequest["role"]>)
                }
                className="w-full rounded border border-soc-border bg-soc-bg px-3 py-2 text-soc-text disabled:opacity-50"
              >
                <option value="soc_l1">SOC Analyst L1</option>
                <option value="soc_l2">SOC Analyst L2</option>
                <option value="soc_manager">SOC Manager</option>
                <option value="admin">Platform Administrator</option>
              </select>
            </div>
            <label className="flex items-center gap-2 text-soc-text cursor-pointer">
              <input
                type="checkbox"
                checked={editActive}
                disabled={editingUser.id === currentUser?.id}
                onChange={(e) => setEditActive(e.target.checked)}
              />
              Account Active (allow login and token refresh)
            </label>
            <label className="flex items-center gap-2 text-amber-300 cursor-pointer">
              <input
                type="checkbox"
                checked={editUnlock}
                onChange={(e) => setEditUnlock(e.target.checked)}
              />
              <Unlock className="w-3.5 h-3.5" />
              Reset failed login counter and clear any active lockout window
            </label>
            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setEditingUser(null)}
                className="rounded border border-soc-border px-3 py-1.5 text-soc-muted hover:text-soc-text"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={updateMutation.isPending}
                className="rounded bg-sky-500 px-4 py-1.5 font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-50"
              >
                {updateMutation.isPending ? "Saving..." : "Save Changes"}
              </button>
            </div>
          </form>
        )}
      </Modal>
    </div>
  );
}

