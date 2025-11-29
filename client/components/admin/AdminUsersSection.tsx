import { useState, useEffect, useRef } from "react";
import { auth } from "@/lib/firebase";
import { UserData } from "@/contexts/AuthContext";
import { toast } from "sonner";
import {
  Loader2,
  Shield,
  User,
  Ban,
  RotateCcw,
  Trash2,
  ChevronDown,
  AlertCircle,
  MoreVertical,
  Mail,
  Calendar,
  MessageSquare,
} from "lucide-react";
import ActionConfirmModal from "./ActionConfirmModal";
import { dsClasses } from "@/lib/design-system";

interface UserRow extends UserData {
  isExpanded?: boolean;
}

export default function AdminUsersSection() {
  const [users, setUsers] = useState<UserRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [confirmAction, setConfirmAction] = useState<{
    type: "promote" | "demote" | "ban" | "unban" | "reset" | "delete" | "plan";
    userId: string;
    email: string;
    plan?: "Free" | "Classic" | "Pro";
  } | null>(null);
  const [expandedUserId, setExpandedUserId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const abortControllerRef = useRef<AbortController | null>(null);
  const isLoadingRef = useRef(false);

  useEffect(() => {
    if (isLoadingRef.current) return;

    const controller = new AbortController();
    abortControllerRef.current = controller;
    isLoadingRef.current = true;

    loadUsers(controller.signal).finally(() => {
      isLoadingRef.current = false;
    });

    return () => {
      controller.abort();
      isLoadingRef.current = false;
    };
  }, []);

  const loadUsers = async (signal?: AbortSignal) => {
    try {
      setLoading(true);
      setError(null);
      const currentUser = auth.currentUser;
      if (!currentUser) throw new Error("Non authentifié");

      const idToken = await currentUser.getIdToken();
      const response = await fetch("/api/admin/users", {
        headers: { Authorization: `Bearer ${idToken}` },
        signal,
      });

      if (!response.ok) {
        let errorMessage = "Erreur serveur";
        try {
          const errorData = await response.json();
          errorMessage = errorData.message || errorData.error || errorMessage;
        } catch {
          errorMessage = response.statusText || errorMessage;
        }
        throw new Error(errorMessage);
      }

      let data;
      try {
        data = await response.json();
      } catch (parseError) {
        throw new Error("Impossible de traiter la réponse du serveur");
      }

      if (!data.success || !data.users) {
        throw new Error("Format de réponse invalide");
      }

      setUsers(data.users || []);
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") {
        return;
      }

      const errorMsg =
        error instanceof Error ? error.message : "Erreur lors du chargement";
      setError(errorMsg);
    } finally {
      setLoading(false);
    }
  };

  const handleAction = async (
    type: "promote" | "demote" | "ban" | "unban" | "reset" | "delete" | "plan",
    userId: string,
    email: string,
    plan?: "Free" | "Classic" | "Pro",
  ) => {
    setConfirmAction({ type, userId, email, plan });
  };

  const executeAction = async () => {
    if (!confirmAction) return;

    try {
      setActionLoading(`${confirmAction.type}-${confirmAction.userId}`);
      const currentUser = auth.currentUser;
      if (!currentUser) throw new Error("Non authentifié");

      const idToken = await currentUser.getIdToken();
      let endpoint = "";
      let body: any = { userId: confirmAction.userId };

      switch (confirmAction.type) {
        case "promote":
          endpoint = "/api/admin/promote-user";
          break;
        case "demote":
          endpoint = "/api/admin/demote-user";
          break;
        case "ban":
          endpoint = "/api/admin/ban-user";
          body.reason = "Violation des conditions d'utilisation";
          break;
        case "unban":
          endpoint = "/api/admin/unban-user";
          break;
        case "reset":
          endpoint = "/api/admin/reset-messages";
          break;
        case "delete":
          endpoint = "/api/admin/delete-user";
          break;
        case "plan":
          endpoint = "/api/admin/update-user-plan";
          body.plan = confirmAction.plan;
          break;
      }

      const response = await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${idToken}`,
        },
        body: JSON.stringify(body),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.message || data.error || "Erreur lors de l'opération",
        );
      }

      toast.success(`Action complétée: ${confirmAction.type}`);
      loadUsers();
    } catch (error) {
      const errorMsg =
        error instanceof Error ? error.message : "Erreur lors de l'opération";
      toast.error(errorMsg);
    } finally {
      setActionLoading(null);
      setConfirmAction(null);
    }
  };

  const filteredUsers = users.filter(
    (user) =>
      user.email?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      user.displayName?.toLowerCase().includes(searchTerm.toLowerCase()),
  );

  const stats = {
    total: users.length,
    admins: users.filter((u) => u.isAdmin).length,
    pro: users.filter((u) => u.plan === "Pro").length,
    banned: users.filter((u) => u.isBanned).length,
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-8 h-8 animate-spin text-white/60" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="space-y-4">
        <div>
          <h2 className="text-20px font-semibold text-white">
            Gestion des utilisateurs
          </h2>
          <p className="text-13px text-white/60 mt-1">
            Découvrir et gérer {stats.total} utilisateurs actifs
          </p>
        </div>

        {/* Search */}
        <input
          type="text"
          placeholder="Rechercher par email ou nom..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className={dsClasses.input}
        />
      </div>

      {/* Error State */}
      {error && (
        <div
          className={`${dsClasses.card} border-red-500/30 bg-red-500/10 p-4 flex items-start gap-3`}
        >
          <AlertCircle
            size={18}
            className="text-red-400 mt-0.5 flex-shrink-0"
          />
          <div>
            <p className="text-sm font-medium text-red-300">{error}</p>
            <button
              onClick={() => loadUsers()}
              disabled={loading}
              className="text-xs text-red-300/70 hover:text-red-300 mt-2 underline"
            >
              Réessayer
            </button>
          </div>
        </div>
      )}

      {/* Users List */}
      <div className="space-y-3">
        {filteredUsers.length === 0 ? (
          <div className={`${dsClasses.card} p-8 text-center`}>
            <User size={32} className="mx-auto text-white/30 mb-3" />
            <p className="text-14px text-white/60">Aucun utilisateur trouvé</p>
          </div>
        ) : (
          filteredUsers.map((user, index) => (
            <div
              key={user.uid}
              className={`${dsClasses.card} p-4 animate-slideUp hover:border-white/10 transition-all duration-200`}
              style={{ animationDelay: `${index * 30}ms` }}
            >
              <div className="flex items-center justify-between gap-4">
                {/* User Info */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-3">
                    {/* Avatar */}
                    <div className="w-10 h-10 rounded-full bg-gradient-to-br from-blue-600 to-blue-700 flex items-center justify-center flex-shrink-0">
                      <User size={18} className="text-white/80" />
                    </div>

                    {/* Email & Name */}
                    <div className="flex-1 min-w-0">
                      <p className="text-14px font-medium text-white truncate">
                        {user.displayName || "Sans nom"}
                      </p>
                      <div className="flex items-center gap-2 text-12px text-white/60 mt-0.5">
                        <Mail size={11} />
                        <span className="truncate">{user.email}</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Badges */}
                <div className="flex items-center gap-2 flex-wrap justify-end">
                  {user.isAdmin && (
                    <div
                      className={`${dsClasses.badge} ${dsClasses.badgeInfo}`}
                    >
                      <Shield size={11} />
                      Admin
                    </div>
                  )}
                  {user.isBanned && (
                    <div
                      className={`${dsClasses.badge} ${dsClasses.badgeError}`}
                    >
                      <Ban size={11} />
                      Banni
                    </div>
                  )}
                  {user.plan && (
                    <div
                      className={`${dsClasses.badge} ${
                        user.plan === "Pro"
                          ? dsClasses.badgeSuccess
                          : user.plan === "Classic"
                            ? dsClasses.badgeWarning
                            : dsClasses.badgeInfo
                      }`}
                    >
                      {user.plan}
                    </div>
                  )}
                </div>

                {/* Actions Menu */}
                <button
                  onClick={() =>
                    setExpandedUserId(
                      expandedUserId === user.uid ? null : user.uid,
                    )
                  }
                  className="p-1.5 text-white/40 hover:text-white/70 hover:bg-white/5 rounded-md transition-all"
                >
                  <ChevronDown
                    size={16}
                    className={`transition-transform ${
                      expandedUserId === user.uid ? "rotate-180" : ""
                    }`}
                  />
                </button>
              </div>

              {/* Expanded Actions */}
              {expandedUserId === user.uid && (
                <div className="mt-4 pt-4 border-t border-white/5 space-y-3 animate-slideUp">
                  {/* Stats */}
                  <div className="grid grid-cols-3 gap-3">
                    <div className="text-center">
                      <p className="text-11px text-white/50 uppercase font-medium">
                        Créé
                      </p>
                      <p className="text-12px text-white mt-1">
                        {user.createdAt?.toLocaleDateString?.("fr-FR") || "-"}
                      </p>
                    </div>
                    <div className="text-center">
                      <p className="text-11px text-white/50 uppercase font-medium">
                        Messages
                      </p>
                      <p className="text-12px text-white mt-1">
                        {user.messagesUsed} / {user.messagesLimit}
                      </p>
                    </div>
                    <div className="text-center">
                      <p className="text-11px text-white/50 uppercase font-medium">
                        Statut
                      </p>
                      <p className="text-12px text-white mt-1">
                        {user.isBanned ? "Banni" : "Actif"}
                      </p>
                    </div>
                  </div>

                  {/* Action Buttons */}
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                    {!user.isAdmin && (
                      <button
                        onClick={() =>
                          handleAction("promote", user.uid, user.email)
                        }
                        disabled={actionLoading !== null}
                        className={`${dsClasses.buttonBase} text-12px px-3 py-1.5 rounded-md bg-blue-600/20 hover:bg-blue-600/30 text-blue-300 border border-blue-500/30`}
                      >
                        Promouvoir
                      </button>
                    )}
                    {user.isAdmin && (
                      <button
                        onClick={() =>
                          handleAction("demote", user.uid, user.email)
                        }
                        disabled={actionLoading !== null}
                        className={`${dsClasses.buttonBase} text-12px px-3 py-1.5 rounded-md bg-amber-600/20 hover:bg-amber-600/30 text-amber-300 border border-amber-500/30`}
                      >
                        Rétrograder
                      </button>
                    )}
                    {!user.isBanned && (
                      <button
                        onClick={() =>
                          handleAction("ban", user.uid, user.email)
                        }
                        disabled={actionLoading !== null}
                        className={`${dsClasses.buttonBase} text-12px px-3 py-1.5 rounded-md bg-red-600/20 hover:bg-red-600/30 text-red-300 border border-red-500/30`}
                      >
                        <Ban size={11} /> Bannir
                      </button>
                    )}
                    {user.isBanned && (
                      <button
                        onClick={() =>
                          handleAction("unban", user.uid, user.email)
                        }
                        disabled={actionLoading !== null}
                        className={`${dsClasses.buttonBase} text-12px px-3 py-1.5 rounded-md bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/30`}
                      >
                        Débannir
                      </button>
                    )}
                    <button
                      onClick={() =>
                        handleAction("reset", user.uid, user.email)
                      }
                      disabled={actionLoading !== null}
                      className={`${dsClasses.buttonBase} text-12px px-3 py-1.5 rounded-md bg-white/10 hover:bg-white/15 text-white`}
                    >
                      <RotateCcw size={11} /> Reset
                    </button>
                    <button
                      onClick={() =>
                        handleAction("delete", user.uid, user.email)
                      }
                      disabled={actionLoading !== null}
                      className={`${dsClasses.buttonBase} text-12px px-3 py-1.5 rounded-md bg-red-600/20 hover:bg-red-600/30 text-red-300 border border-red-500/30`}
                    >
                      <Trash2 size={11} /> Supprimer
                    </button>
                  </div>
                </div>
              )}
            </div>
          ))
        )}
      </div>

      {/* Confirmation Modal */}
      {confirmAction && (
        <ActionConfirmModal
          type={confirmAction.type}
          email={confirmAction.email}
          plan={confirmAction.plan}
          onConfirm={executeAction}
          onCancel={() => setConfirmAction(null)}
          isLoading={actionLoading !== null}
        />
      )}
    </div>
  );
}
