import { useEffect, useState } from "react";
import { auth } from "@/lib/firebase";
import { Loader2 } from "lucide-react";
import { dsClasses } from "@/lib/design-system";

interface SystemStats {
  totalUsers: number;
  totalAdmins: number;
  bannedUsers: number;
  activeLicenses: number;
  systemHealth: string;
  uptime: number;
  avgLatency: number;
  storage: {
    used: number;
    total: number;
  };
}

interface StatCardProps {
  title: string;
  value: string | number;
  change?: string;
  trend?: "up" | "down" | "neutral";
  lastUpdated?: string;
}

function StatCard({ title, value, change, trend, lastUpdated }: StatCardProps) {
  return (
    <div
      className={`${dsClasses.card} p-6 flex flex-col gap-3 group hover:border-white/10 transition-all duration-200`}
    >
      <div className="flex items-center justify-between">
        <p className="text-white/70 text-13px font-medium uppercase tracking-wide">
          {title}
        </p>
      </div>

      <div className="flex items-end gap-2">
        <span className="text-3xl font-bold text-white">{value}</span>
        {change && (
          <div
            className={`text-12px font-medium px-2 py-1 rounded-md ${
              trend === "up"
                ? "bg-emerald-500/15 text-emerald-400"
                : trend === "down"
                  ? "bg-red-500/15 text-red-400"
                  : "bg-gray-500/15 text-gray-400"
            }`}
          >
            {change}
          </div>
        )}
      </div>

      {lastUpdated && (
        <p className="text-11px text-white/40 mt-auto">{lastUpdated}</p>
      )}
    </div>
  );
}

export default function AdminStats() {
  const [stats, setStats] = useState<SystemStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let isMounted = true;

    const fetchStats = async () => {
      try {
        setLoading(true);
        setError(null);
        const currentUser = auth.currentUser;
        if (!currentUser) throw new Error("Non authentifié");

        const idToken = await currentUser.getIdToken();
        const response = await fetch("/api/admin/system-stats", {
          headers: { Authorization: `Bearer ${idToken}` },
        });

        if (!response.ok) {
          const errorData = await response.json().catch(() => ({}));
          throw new Error(
            errorData.message || `Erreur serveur: ${response.status}`,
          );
        }

        const data = await response.json();
        if (!isMounted) return;

        if (data.success && data.stats) {
          setStats(data.stats);
        } else {
          setError("Format de réponse invalide");
        }
      } catch (error) {
        if (!isMounted) return;
        const errorMsg =
          error instanceof Error ? error.message : "Erreur lors du chargement";
        console.error("Erreur lors du chargement des stats:", error);
        setError(errorMsg);
        setStats(null);
      } finally {
        if (!isMounted) return;
        setLoading(false);
      }
    };

    fetchStats();
    const interval = setInterval(fetchStats, 60000); // Refresh toutes les minutes
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-8">
        <Loader2 size={20} className="animate-spin text-white/60" />
      </div>
    );
  }

  if (error || !stats) {
    return (
      <div className={`${dsClasses.card} p-6 bg-red-500/10 border-red-500/20`}>
        <p className="text-red-300 text-14px font-medium mb-2">
          Impossible de charger les statistiques
        </p>
        {error && <p className="text-red-300/70 text-13px">{error}</p>}
      </div>
    );
  }

  const storagePercent = Math.round(
    (stats.storage.used / stats.storage.total) * 100,
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="space-y-2">
        <h2 className="text-2xl font-bold text-white">Tableau de bord</h2>
        <p className="text-white/60 text-14px">
          Aperçu en temps réel de l'activité du système
        </p>
      </div>

      {/* Main stats grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Utilisateurs totaux"
          value={stats.totalUsers}
          lastUpdated="Mise à jour en temps réel"
        />
        <StatCard
          title="Administrateurs"
          value={stats.totalAdmins}
          lastUpdated="Mise à jour en temps réel"
        />
        <StatCard
          title="Licences actives"
          value={stats.activeLicenses}
          lastUpdated="Mise à jour en temps réel"
        />
        <StatCard
          title="Utilisateurs bannis"
          value={stats.bannedUsers}
          lastUpdated="Mise à jour en temps réel"
        />
      </div>

      {/* Secondary metrics */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className={`${dsClasses.card} p-4 space-y-3`}>
          <div className="flex items-center justify-between">
            <span className="text-white/70 text-12px font-medium uppercase">
              Santé système
            </span>
            <span
              className={`text-12px font-semibold ${stats.systemHealth === "Optimal" ? "text-emerald-400" : "text-amber-400"}`}
            >
              {stats.systemHealth}
            </span>
          </div>
          <p className="text-12px text-white/70">
            Uptime: {stats.uptime.toFixed(2)}% • Latence: {stats.avgLatency}ms
          </p>
          <p className="text-11px text-white/40">Statut optimal</p>
        </div>

        <div className={`${dsClasses.card} p-4 space-y-3`}>
          <div className="flex items-center justify-between">
            <span className="text-white/70 text-12px font-medium uppercase">
              Requêtes API
            </span>
            <span className="text-emerald-400 text-12px font-semibold">
              Actif
            </span>
          </div>
          <p className="text-12px text-white/70">Performance: Normal</p>
          <p className="text-11px text-white/40">Aucune alerte</p>
        </div>

        <div className={`${dsClasses.card} p-4 space-y-3`}>
          <div className="flex items-center justify-between">
            <span className="text-white/70 text-12px font-medium uppercase">
              Stockage
            </span>
            <span
              className={`text-12px font-semibold ${storagePercent > 80 ? "text-amber-400" : "text-emerald-400"}`}
            >
              {storagePercent}%
            </span>
          </div>
          <div className="w-full bg-white/5 rounded-full h-2 overflow-hidden">
            <div
              className={`h-full transition-all duration-300 ${
                storagePercent > 80
                  ? "bg-gradient-to-r from-amber-500/60 to-amber-400/40"
                  : "bg-gradient-to-r from-emerald-500/60 to-emerald-400/40"
              }`}
              style={{ width: `${storagePercent}%` }}
            />
          </div>
          <p className="text-11px text-white/40">
            {stats.storage.used} GB / {stats.storage.total} GB
          </p>
        </div>
      </div>
    </div>
  );
}
