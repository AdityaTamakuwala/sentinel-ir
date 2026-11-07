"use client";

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { usePathname, useRouter } from "next/navigation";
import {
  AuthSessionResponse,
  SentinelApiError,
  UserSummaryOut,
  apiRequest,
} from "@/lib/api/generated";
import { AlertCircle, CheckCircle2, Info, X } from "lucide-react";

interface ToastItem {
  id: string;
  title: string;
  description?: string;
  variant: "success" | "error" | "info";
}

interface ToastContextValue {
  pushToast: (toast: Omit<ToastItem, "id">) => void;
}

const ToastContext = createContext<ToastContextValue>({
  pushToast: () => undefined,
});

export function useToast() {
  return useContext(ToastContext);
}

interface AuthContextValue {
  user: UserSummaryOut | null;
  permissions: Set<string>;
  appEnv: string;
  loading: boolean;
  sseStatus: "connected" | "reconnecting" | "polling";
  setSseStatus: (status: "connected" | "reconnecting" | "polling") => void;
  hasPermission: (perm: string) => boolean;
  login: (identifier: string, password: string, totpCode?: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshProfile: () => Promise<void>;
  theme: "dark" | "light";
  toggleTheme: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used inside Providers");
  }
  return ctx;
}

const SSE_DOMAIN_EVENTS = [
  "alert.created",
  "alert.deduplicated",
  "alert.triaged",
  "incident.created",
  "incident.status_changed",
  "incident.assigned",
  "incident.timeline_updated",
  "evidence.uploaded",
  "enrichment.completed",
  "playbook.execution_updated",
  "response.status_changed",
] as const;

export function Providers({ children }: { children: React.ReactNode }) {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            staleTime: 10_000,
            retry: 1,
            refetchOnWindowFocus: false,
          },
        },
      })
  );

  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const pushToast = useCallback((toast: Omit<ToastItem, "id">) => {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    setToasts((prev) => [...prev, { ...toast, id }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 4500);
  }, []);

  const [user, setUser] = useState<UserSummaryOut | null>(null);
  const [permissions, setPermissions] = useState<Set<string>>(new Set());
  const [appEnv, setAppEnv] = useState<string>("development");
  const [loading, setLoading] = useState<boolean>(true);
  const [sseStatus, setSseStatus] = useState<"connected" | "reconnecting" | "polling">(
    "polling"
  );
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const lastEventIdRef = useRef<string | null>(null);

  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    const saved =
      typeof window !== "undefined" ? window.localStorage.getItem("sentinel_theme") : null;
    if (saved === "light" || saved === "dark") {
      setTheme(saved);
      document.documentElement.classList.toggle("light", saved === "light");
      document.documentElement.classList.toggle("dark", saved === "dark");
    }
  }, []);

  const toggleTheme = useCallback(() => {
    setTheme((prev) => {
      const next = prev === "dark" ? "light" : "dark";
      if (typeof window !== "undefined") {
        window.localStorage.setItem("sentinel_theme", next);
      }
      document.documentElement.classList.toggle("light", next === "light");
      document.documentElement.classList.toggle("dark", next === "dark");
      return next;
    });
  }, []);

  const applySession = useCallback((session: AuthSessionResponse) => {
    setUser(session.user);
    setPermissions(new Set(session.permissions));
    setAppEnv(session.app_env);
  }, []);

  const refreshProfile = useCallback(async () => {
    try {
      const session = await apiRequest<AuthSessionResponse>("/api/v1/auth/me");
      applySession(session);
    } catch {
      setUser(null);
      setPermissions(new Set());
    } finally {
      setLoading(false);
    }
  }, [applySession]);

  useEffect(() => {
    void refreshProfile();
  }, [refreshProfile]);

  useEffect(() => {
    if (!loading && !user && pathname !== "/login") {
      router.replace("/login");
    }
  }, [loading, user, pathname, router]);

  // Authenticated Server-Sent Events (SSE) stream with automatic backoff & Last-Event-ID replay
  useEffect(() => {
    if (typeof window === "undefined" || typeof EventSource === "undefined") {
      return;
    }
    if (!user || pathname === "/login") {
      setSseStatus("polling");
      return;
    }

    let es: EventSource | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let disposed = false;
    let retryAttempt = 0;

    const handleDomainEvent = (evt: MessageEvent) => {
      if (evt.lastEventId) {
        lastEventIdRef.current = evt.lastEventId;
      }
      const evType = evt.type;
      if (evType.startsWith("alert.")) {
        void queryClient.invalidateQueries({ queryKey: ["alerts"] });
        void queryClient.invalidateQueries({ queryKey: ["command-center"] });
      }
      if (evType.startsWith("incident.")) {
        void queryClient.invalidateQueries({ queryKey: ["incidents"] });
        void queryClient.invalidateQueries({ queryKey: ["incident"] });
        void queryClient.invalidateQueries({ queryKey: ["command-center"] });
        void queryClient.invalidateQueries({ queryKey: ["notifications"] });
      }
      if (evType.startsWith("evidence.")) {
        void queryClient.invalidateQueries({ queryKey: ["evidence"] });
        void queryClient.invalidateQueries({ queryKey: ["incident"] });
      }
      if (evType.startsWith("enrichment.")) {
        void queryClient.invalidateQueries({ queryKey: ["enrichment"] });
        void queryClient.invalidateQueries({ queryKey: ["incident"] });
      }
      if (evType.startsWith("playbook.") || evType.startsWith("response.")) {
        void queryClient.invalidateQueries({ queryKey: ["playbooks"] });
        void queryClient.invalidateQueries({ queryKey: ["approvals"] });
        void queryClient.invalidateQueries({ queryKey: ["incident"] });
        void queryClient.invalidateQueries({ queryKey: ["notifications"] });
      }
    };

    const connect = () => {
      if (disposed) return;
      const qs = lastEventIdRef.current
        ? `?last_event_id=${encodeURIComponent(lastEventIdRef.current)}`
        : "";
      es = new EventSource(`/api/v1/events/stream${qs}`, { withCredentials: true });

      es.addEventListener("connected", () => {
        retryAttempt = 0;
        setSseStatus("connected");
      });

      for (const evName of SSE_DOMAIN_EVENTS) {
        es.addEventListener(evName, handleDomainEvent as EventListener);
      }

      es.onerror = () => {
        es?.close();
        es = null;
        if (disposed) return;
        retryAttempt += 1;
        setSseStatus(retryAttempt >= 3 ? "polling" : "reconnecting");
        const delayMs = Math.min(20_000, 1500 * Math.pow(2, retryAttempt - 1));
        reconnectTimer = setTimeout(connect, delayMs);
      };
    };

    connect();

    return () => {
      disposed = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (es) es.close();
    };
  }, [user, pathname, queryClient]);

  const login = useCallback(
    async (identifier: string, password: string, totpCode?: string) => {
      const session = await apiRequest<AuthSessionResponse>("/api/v1/auth/login", {
        method: "POST",
        body: {
          identifier,
          password,
          totp_code: totpCode || null,
        },
        skipAuthRefresh: true,
      });
      applySession(session);
      queryClient.clear();
      router.replace(session.user.must_change_password ? "/profile" : "/");
    },
    [applySession, queryClient, router]
  );

  const logout = useCallback(async () => {
    try {
      await apiRequest("/api/v1/auth/logout", { method: "POST", skipAuthRefresh: true });
    } catch (err) {
      if (!(err instanceof SentinelApiError)) {
        // ignore network hiccup on logout
      }
    } finally {
      setUser(null);
      setPermissions(new Set());
      queryClient.clear();
      router.replace("/login");
    }
  }, [queryClient, router]);

  const hasPermission = useCallback(
    (perm: string) => permissions.has(perm),
    [permissions]
  );

  const authValue = useMemo<AuthContextValue>(
    () => ({
      user,
      permissions,
      appEnv,
      loading,
      sseStatus,
      setSseStatus,
      hasPermission,
      login,
      logout,
      refreshProfile,
      theme,
      toggleTheme,
    }),
    [
      user,
      permissions,
      appEnv,
      loading,
      sseStatus,
      hasPermission,
      login,
      logout,
      refreshProfile,
      theme,
      toggleTheme,
    ]
  );

  return (
    <QueryClientProvider client={queryClient}>
      <ToastContext.Provider value={{ pushToast }}>
        <AuthContext.Provider value={authValue}>
          {children}
          {/* Operational Toast Stack */}
          <div
            aria-live="polite"
            className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 w-full max-w-sm pointer-events-none"
          >
            {toasts.map((t) => (
              <div
                key={t.id}
                className="pointer-events-auto flex items-start gap-3 rounded-md border border-soc-border bg-soc-elevated px-4 py-3 shadow-xl text-sm"
              >
                {t.variant === "success" && (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                )}
                {t.variant === "error" && (
                  <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                )}
                {t.variant === "info" && (
                  <Info className="w-4 h-4 text-sky-400 shrink-0 mt-0.5" />
                )}
                <div className="flex-1 min-w-0">
                  <p className="font-medium text-soc-text">{t.title}</p>
                  {t.description && (
                    <p className="text-xs text-soc-muted mt-0.5 break-words">{t.description}</p>
                  )}
                </div>
                <button
                  type="button"
                  aria-label="Dismiss notification"
                  onClick={() => setToasts((prev) => prev.filter((item) => item.id !== t.id))}
                  className="text-soc-muted hover:text-soc-text"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            ))}
          </div>
        </AuthContext.Provider>
      </ToastContext.Provider>
    </QueryClientProvider>
  );
}
