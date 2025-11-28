import { useEffect, useState } from "react";
import { auth } from "@/lib/firebase";
import { Clock, Loader2 } from "lucide-react";
import { dsClasses } from "@/lib/design-system";

interface AdminLog {
  id: string;
  action: string;
  adminUid: string;
  data?: Record<string, any>;
  timestamp: Date;
  severity: "info" | "warning" | "success" | "error";
}

function getSeverityColor(severity: "info" | "warning" | "success" | "error") {
  switch (severity) {
    case "success":
      return "bg-emerald-500/10 border-emerald-500/30 text-emerald-300";
    case "warning":
      return "bg-amber-500/10 border-amber-500/30 text-amber-300";
    case "error":
      return "bg-red-500/10 border-red-500/30 text-red-300";
    case "info":
    default:
      return "bg-blue-500/10 border-blue-500/30 text-blue-300";
  }
}

function formatTime(date: Date): string {
  const now = new Date();
  const diff = (now.getTime() - date.getTime()) / 1000;

  if (diff < 60) return "À l'instant";
  if (diff < 3600) return `Il y a ${Math.floor(diff / 60)}m`;
  if (diff < 86400) return `Il y a ${Math.floor(diff / 3600)}h`;
  if (diff < 604800) return `Il y a ${Math.floor(diff / 86400)}j`;

  return date.toLocaleDateString("fr-FR", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function getActionLabel(action: string, data?: Record<string, any>): string {
  const actions: Record<string, string> = {
    BAN_USER: "Bannissement utilisateur",
    UNBAN_USER: "Débannissement utilisateur",
    PROMOTE_USER: "Promotion en admin",
    DEMOTE_USER: "Rétrogradation admin",
    UPDATE_USER_PLAN: "Modification du plan",
    RESET_USER_MESSAGES: "Réinitialisation des messages",
    DELETE_USER: "Suppression utilisateur",
    CREATE_LICENSE: "Création de licence",
    INVALIDATE_LICENSE: "Invalidation de licence",
    DELETE_LICENSE: "Suppression de licence",
    UPDATE_AI_CONFIG: "Mise à jour config IA",
    ENABLE_GLOBAL_MAINTENANCE: "Maintenance globale activée",
    DISABLE_GLOBAL_MAINTENANCE: "Maintenance globale désactivée",
    ENABLE_PARTIAL_MAINTENANCE: "Maintenance partielle activée",
    DISABLE_PARTIAL_MAINTENANCE: "Maintenance partielle désactivée",
    ENABLE_IA_MAINTENANCE: "Maintenance IA activée",
    DISABLE_IA_MAINTENANCE: "Maintenance IA désactivée",
    ENABLE_LICENSE_MAINTENANCE: "Maintenance licences activée",
    DISABLE_LICENSE_MAINTENANCE: "Maintenance licences désactivée",
  };

  return actions[action] || action;
}

export default function AdminLogs() {
  const [logs, setLogs] = useState<AdminLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let isMounted = true;

    const fetchLogs = async () => {
      try {
        setLoading(true);
        setError(null);
        const currentUser = auth.currentUser;
        if (!currentUser) throw new Error("Non authentifié");

        const idToken = await currentUser.getIdToken();
        const response = await fetch("/api/admin/logs", {
          headers: { Authorization: `Bearer ${idToken}` },
        });

        if (!response.ok) {
          const errorData = await response.json().catch(() => ({}));
          throw new Error(errorData.message || `Erreur serveur: ${response.status}`);
        }

        const data = await response.json();
        if (!isMounted) return;

        if (data.success && Array.isArray(data.logs)) {
          const formattedLogs: AdminLog[] = data.logs
            .slice(0, 10)
            .map((log: any) => ({
              id: log.id || Math.random().toString(),
              action: log.action,
              adminUid: log.adminUid,
              data: log.data,
              timestamp: log.timestamp?.toDate?.() || new Date(log.timestamp),
              severity: getSeverityFromAction(log.action),
            }));
          setLogs(formattedLogs);
        } else {
          setError("Format de réponse invalide");
        }
      } catch (error) {
        if (!isMounted) return;
        const errorMsg = error instanceof Error ? error.message : "Erreur lors du chargement";
        console.error("Erreur lors du chargement des logs:", error);
        setError(errorMsg);
        setLogs([]);
      } finally {
        if (!isMounted) return;
        setLoading(false);
      }
    };

    fetchLogs();
    const interval = setInterval(fetchLogs, 120000); // Refresh toutes les 2 minutes
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  const getSeverityFromAction = (
    action: string,
  ): "info" | "warning" | "success" | "error" => {
    if (action.includes("DELETE") || action.includes("BAN")) return "error";
    if (
      action.includes("PROMOTE") ||
      action.includes("CREATE") ||
      action.includes("ENABLE")
    )
      return "success";
    if (action.includes("DISABLE") || action.includes("UPDATE"))
      return "warning";
    return "info";
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-8">
        <Loader2 size={16} className="animate-spin text-white/60" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="space-y-2">
        <h3 className="text-18px font-semibold text-white">Activité récente</h3>
        <p className="text-13px text-white/60">Dernières actions du système</p>
      </div>

      {/* Logs list */}
      <div className="space-y-2">
        {logs.length === 0 ? (
          <div
            className={`${dsClasses.card} p-4 text-center text-white/60 text-13px`}
          >
            Aucune activité récente
          </div>
        ) : (
          logs.map((log, index) => (
            <div
              key={log.id}
              className={`${dsClasses.card} p-4 flex items-start justify-between gap-3 group hover:border-white/10 transition-all duration-150 animate-slideUp`}
              style={{ animationDelay: `${index * 50}ms` }}
            >
              <div className="flex items-start gap-3 flex-1 min-w-0">
                {/* Severity indicator */}
                <div
                  className={`w-2 h-10 rounded-full flex-shrink-0 mt-1 ${
                    log.severity === "success"
                      ? "bg-emerald-500/50"
                      : log.severity === "warning"
                        ? "bg-amber-500/50"
                        : log.severity === "error"
                          ? "bg-red-500/50"
                          : "bg-blue-500/50"
                  }`}
                />

                {/* Content */}
                <div className="flex-1 min-w-0">
                  {/* Action title */}
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-14px font-semibold text-white">
                      {getActionLabel(log.action, log.data)}
                    </span>
                  </div>

                  {/* Details */}
                  {log.data && (
                    <p className="text-13px text-white/70 mt-1">
                      {log.data.reason ||
                        log.data.message ||
                        log.data.targetUser ||
                        ""}
                    </p>
                  )}

                  {/* Meta */}
                  <div className="flex items-center gap-3 mt-2 text-11px text-white/50 flex-wrap">
                    <div className="flex items-center gap-1">
                      <Clock size={11} />
                      <span>{formatTime(log.timestamp)}</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Footer */}
      <button className="w-full py-3 text-13px font-medium text-white/60 hover:text-white/80 transition-colors">
        Voir tous les logs
      </button>
    </div>
  );
}
