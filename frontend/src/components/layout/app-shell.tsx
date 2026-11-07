"use client";

import React, { useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Bell,
  BookOpen,
  CheckCheck,
  CheckSquare,
  FileArchive,
  FileSearch,
  FileText,
  FolderKanban,
  Globe,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Menu,
  Moon,
  Network,
  ScrollText,
  Search,
  ShieldAlert,
  Sun,
  Users,
  Wifi,
  X,
  Zap,
} from "lucide-react";
import { NotificationListOut, apiRequest } from "@/lib/api/generated";
import { useAuth } from "@/components/providers";
import { RoleBadge } from "@/components/ui/badges";
import { formatRelativeTime } from "@/lib/format";

interface NavItem {
  href: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  permission?: string;
}

interface NavGroup {
  section: string;
  items: NavItem[];
}

export const NAV_GROUPS: NavGroup[] = [
  {
    section: "SOC Operations",
    items: [
      { href: "/", label: "SOC Command Centre", icon: LayoutDashboard, permission: "dashboard:view" },
      { href: "/alerts", label: "Alert Inbox", icon: AlertTriangle, permission: "alerts:view" },
      { href: "/triage", label: "Triage Workbench", icon: FileSearch, permission: "alerts:view" },
      { href: "/incidents", label: "Incident Management", icon: FolderKanban, permission: "incidents:view" },
    ],
  },
  {
    section: "Investigation & Forensics",
    items: [
      { href: "/workbench", label: "Investigation Workbench", icon: Network, permission: "incidents:view" },
      { href: "/evidence", label: "Evidence Repository", icon: FileArchive, permission: "evidence:read" },
    ],
  },
  {
    section: "Threat Intel & MITRE",
    items: [
      { href: "/intelligence", label: "Threat Intelligence", icon: Globe, permission: "enrichment:read" },
      { href: "/mitre", label: "MITRE ATT&CK Matrix", icon: ShieldAlert, permission: "mitre:read" },
    ],
  },
  {
    section: "Orchestration & SOAR",
    items: [
      { href: "/playbooks", label: "Playbook Engine", icon: BookOpen, permission: "playbooks:view" },
      { href: "/responses", label: "Approval Queue", icon: CheckSquare, permission: "incidents:view" },
      { href: "/simulations", label: "Simulation Launcher", icon: Zap, permission: "simulation:run" },
    ],
  },
  {
    section: "Reporting & Analytics",
    items: [
      { href: "/analytics", label: "SOC Analytics", icon: BarChart3, permission: "dashboard:view" },
      { href: "/reports", label: "Incident Reports", icon: FileText, permission: "reports:view" },
    ],
  },
  {
    section: "Governance & Access",
    items: [
      { href: "/audit", label: "Audit & Compliance", icon: ScrollText, permission: "audit:read" },
      { href: "/analysts", label: "Analyst Management", icon: Users, permission: "users:read" },
      { href: "/profile", label: "Profile & Security", icon: KeyRound },
    ],
  },
];

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const queryClient = useQueryClient();
  const { user, loading, hasPermission, logout, sseStatus, theme, toggleTheme, appEnv } =
    useAuth();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [notifOpen, setNotifOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");

  const notifQuery = useQuery({
    queryKey: ["notifications"],
    enabled: Boolean(user) && pathname !== "/login",
    refetchInterval: sseStatus === "connected" ? false : 20_000,
    queryFn: () => apiRequest<NotificationListOut>("/api/v1/notifications"),
  });

  const markAllReadMutation = useMutation({
    mutationFn: () => apiRequest("/api/v1/notifications/read-all", { method: "POST" }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["notifications"] });
    },
  });

  if (pathname === "/login") {
    return <>{children}</>;
  }

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-soc-bg text-soc-muted text-sm">
        <Activity className="w-4 h-4 mr-2 animate-spin text-sky-400" />
        Initializing SENTINEL IR workspace...
      </div>
    );
  }

  if (!user) {
    return null;
  }

  const handleGlobalSearch = (e: React.FormEvent) => {
    e.preventDefault();
    const q = searchQuery.trim();
    if (!q) return;
    if (q.toUpperCase().startsWith("INC-")) {
      router.push(`/incidents/${encodeURIComponent(q.toUpperCase())}`);
    } else {
      router.push(`/alerts?search=${encodeURIComponent(q)}`);
    }
  };

  const unreadCount = notifQuery.data?.unread_count ?? 0;
  const segments = pathname.split("/").filter(Boolean);

  return (
    <div className="min-h-screen flex bg-soc-bg text-soc-text">
      {/* Sidebar */}
      <aside
        className={`fixed inset-y-0 left-0 z-40 w-64 border-r border-soc-border bg-soc-surface flex flex-col transition-transform lg:static lg:translate-x-0 ${
          mobileOpen ? "translate-x-0" : "-translate-x-full"
        }`}
      >
        <div className="h-14 px-4 border-b border-soc-border flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2.5">
            <div className="p-1.5 rounded bg-sky-500/15 border border-sky-500/30 text-sky-400">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <span className="font-semibold tracking-tight text-sm block leading-none">
                SENTINEL IR
              </span>
              <span className="text-[10px] font-mono uppercase tracking-widest text-soc-muted">
                Enterprise SOAR
              </span>
            </div>
          </Link>
          <button
            type="button"
            aria-label="Close navigation"
            onClick={() => setMobileOpen(false)}
            className="lg:hidden text-soc-muted hover:text-soc-text"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-6" aria-label="Main Navigation">
          {NAV_GROUPS.map((group) => {
            const visibleItems = group.items.filter(
              (item) => !item.permission || hasPermission(item.permission)
            );
            if (visibleItems.length === 0) return null;
            return (
              <div key={group.section}>
                <p className="px-2.5 mb-2 text-[10px] font-semibold uppercase tracking-wider text-soc-muted">
                  {group.section}
                </p>
                <ul className="space-y-1">
                  {visibleItems.map((item) => {
                    const Icon = item.icon;
                    const active =
                      item.href === "/"
                        ? pathname === "/"
                        : pathname === item.href || pathname.startsWith(`${item.href}/`);
                    return (
                      <li key={item.href}>
                        <Link
                          href={item.href}
                          onClick={() => setMobileOpen(false)}
                          className={`flex items-center gap-2.5 px-2.5 py-2 rounded-md text-sm font-medium transition-colors ${
                            active
                              ? "bg-soc-accent-muted text-sky-400 border border-sky-500/25"
                              : "text-soc-muted hover:text-soc-text hover:bg-soc-elevated"
                          }`}
                        >
                          <Icon className="w-4 h-4 shrink-0" />
                          <span>{item.label}</span>
                        </Link>
                      </li>
                    );
                  })}
                </ul>
              </div>
            );
          })}
        </nav>

        <div className="p-3 border-t border-soc-border bg-soc-elevated/40">
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-xs font-medium truncate">{user.full_name}</span>
            <RoleBadge role={user.role} />
          </div>
          <div className="flex items-center justify-between text-[11px] text-soc-muted">
            <span className="font-mono truncate">@{user.username}</span>
            <button
              type="button"
              onClick={() => void logout()}
              className="inline-flex items-center gap-1 text-soc-muted hover:text-red-400 transition-colors"
            >
              <LogOut className="w-3.5 h-3.5" />
              Sign out
            </button>
          </div>
        </div>
      </aside>

      {/* Main Column */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top Bar */}
        <header className="h-14 border-b border-soc-border bg-soc-surface px-4 lg:px-6 flex items-center justify-between gap-4 sticky top-0 z-30">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              aria-label="Open navigation"
              onClick={() => setMobileOpen(true)}
              className="lg:hidden p-1.5 rounded border border-soc-border text-soc-muted hover:text-soc-text"
            >
              <Menu className="w-4 h-4" />
            </button>
            <nav aria-label="Breadcrumb" className="flex items-center gap-1.5 text-xs text-soc-muted truncate">
              <Link href="/" className="hover:text-soc-text">
                SOC
              </Link>
              {segments.map((seg, idx) => {
                const href = "/" + segments.slice(0, idx + 1).join("/");
                return (
                  <React.Fragment key={href}>
                    <span>/</span>
                    <Link
                      href={href}
                      className={
                        idx === segments.length - 1
                          ? "text-soc-text font-medium truncate max-w-[200px]"
                          : "hover:text-soc-text"
                      }
                    >
                      {decodeURIComponent(seg)}
                    </Link>
                  </React.Fragment>
                );
              })}
            </nav>
          </div>

          <div className="flex items-center gap-2.5">
            <form onSubmit={handleGlobalSearch} className="hidden md:flex items-center relative">
              <Search className="w-3.5 h-3.5 text-soc-muted absolute left-2.5 pointer-events-none" />
              <input
                type="search"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Jump INC-2026-0001, IP, host, user..."
                aria-label="Global SOC search"
                className="w-60 rounded-md border border-soc-border bg-soc-bg pl-8 pr-3 py-1.5 text-xs text-soc-text placeholder:text-soc-muted focus:outline-none focus:border-sky-500"
              />
            </form>

            {/* Telemetry / Stream Status Indicator */}
            <div
              title={`Telemetry transport: ${sseStatus.toUpperCase()}`}
              className="hidden sm:inline-flex items-center gap-1.5 px-2.5 py-1 rounded border border-soc-border bg-soc-bg text-[11px] font-mono text-soc-muted"
            >
              <Wifi
                className={`w-3.5 h-3.5 ${
                  sseStatus === "connected"
                    ? "text-emerald-400"
                    : sseStatus === "reconnecting"
                    ? "text-amber-400"
                    : "text-sky-400"
                }`}
              />
              <span>
                {sseStatus === "connected"
                  ? "LIVE SSE"
                  : sseStatus === "reconnecting"
                  ? "RECONNECTING"
                  : "SYNC ACTIVE"}
              </span>
            </div>

            {/* Notification Centre */}
            <div className="relative">
              <button
                type="button"
                aria-label="Open notifications"
                onClick={() => setNotifOpen((prev) => !prev)}
                className="relative p-1.5 rounded border border-soc-border bg-soc-bg text-soc-muted hover:text-soc-text"
              >
                <Bell className="w-4 h-4" />
                {unreadCount > 0 && (
                  <span className="absolute -top-1 -right-1 min-w-[16px] h-4 px-1 rounded-full bg-red-500 text-[10px] font-bold text-white flex items-center justify-center">
                    {unreadCount > 9 ? "9+" : unreadCount}
                  </span>
                )}
              </button>

              {notifOpen && (
                <div className="absolute right-0 mt-2 w-80 rounded-lg border border-soc-border bg-soc-surface shadow-2xl z-50 overflow-hidden text-xs">
                  <div className="flex items-center justify-between border-b border-soc-border px-3.5 py-2.5 bg-soc-elevated/60">
                    <span className="font-semibold">SOC Notifications</span>
                    {unreadCount > 0 && (
                      <button
                        type="button"
                        onClick={() => markAllReadMutation.mutate()}
                        className="inline-flex items-center gap-1 text-[11px] text-sky-400 hover:text-sky-300"
                      >
                        <CheckCheck className="w-3.5 h-3.5" />
                        Mark all read
                      </button>
                    )}
                  </div>
                  <div className="max-h-80 overflow-y-auto divide-y divide-soc-border">
                    {(notifQuery.data?.items ?? []).length === 0 ? (
                      <div className="p-4 text-center text-soc-muted">
                        No operational notifications yet.
                      </div>
                    ) : (
                      notifQuery.data?.items.map((n) => (
                        <div
                          key={n.id}
                          onClick={() => {
                            setNotifOpen(false);
                            if (n.link_url) router.push(n.link_url);
                          }}
                          className={`p-3 cursor-pointer hover:bg-soc-elevated/50 transition-colors ${
                            !n.is_read ? "bg-sky-500/5" : ""
                          }`}
                        >
                          <div className="flex items-center justify-between gap-2 mb-0.5">
                            <span className="font-medium text-soc-text truncate">{n.title}</span>
                            <span className="text-[10px] text-soc-muted shrink-0">
                              {formatRelativeTime(n.created_at)}
                            </span>
                          </div>
                          {n.body && <p className="text-[11px] text-soc-muted line-clamp-2">{n.body}</p>}
                        </div>
                      ))
                    )}
                  </div>
                </div>
              )}
            </div>

            {appEnv !== "production" && (
              <span className="hidden xl:inline-flex px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-amber-500/10 text-amber-300 border border-amber-500/30">
                {appEnv}
              </span>
            )}

            <button
              type="button"
              aria-label="Toggle color theme"
              onClick={toggleTheme}
              className="p-1.5 rounded border border-soc-border bg-soc-bg text-soc-muted hover:text-soc-text"
            >
              {theme === "dark" ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
            </button>
          </div>
        </header>

        <main className="flex-1 p-4 lg:p-6 overflow-x-hidden">{children}</main>
      </div>
    </div>
  );
}
