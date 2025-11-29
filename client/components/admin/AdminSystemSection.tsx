import { useEffect, useState } from "react";
import { auth } from "@/lib/firebase";
import {
  Loader2,
  Users,
  Zap,
  FileText,
  Activity,
  AlertCircle,
} from "lucide-react";
import { toast } from "sonner";
import {
  LineChart,
  Line,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from "recharts";

interface SystemStats {
  totalUsers: number;
  adminUsers: number;
  bannedUsers: number;
  freeUsers: number;
  proUsers: number;
  totalMessages: number;
  avgMessagesPerUser: number;
  totalLicenses: number;
  usedLicenses: number;
  activeLicenses: number;
  activityLogsCount: number;
  activityByDay: Record<string, number>;
}

export default function AdminSystemSection() {
  const [stats, setStats] = useState<SystemStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [chartData, setChartData] = useState<any[]>([]);
  const [planData, setPlanData] = useState<any[]>([]);

  useEffect(() => {
    loadStats();
    const interval = setInterval(loadStats, 60000);
    return () => clearInterval(interval);
  }, []);

  const loadStats = async () => {
    try {
      const currentUser = auth.currentUser;
      if (!currentUser) throw new Error("Non authentifié");

      const idToken = await currentUser.getIdToken();
      const response = await fetch("/api/admin/system-stats", {
        headers: { Authorization: `Bearer ${idToken}` },
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || data.error || "Erreur serveur");
      }

      const statsData = data.stats || data;

      const defaultStats: SystemStats = {
        totalUsers: statsData.totalUsers || 0,
        adminUsers: statsData.totalAdmins || 0,
        bannedUsers: statsData.bannedUsers || 0,
        freeUsers: statsData.freeUsers || 0,
        proUsers: statsData.proUsers || 0,
        totalMessages: statsData.totalMessages || 0,
        avgMessagesPerUser: statsData.avgMessagesPerUser || 0,
        totalLicenses: statsData.totalLicenses || 0,
        usedLicenses: statsData.usedLicenses || 0,
        activeLicenses: statsData.activeLicenses || 0,
        activityLogsCount: statsData.activityLogsCount || 0,
        activityByDay: statsData.activityByDay || {},
      };

      setStats(defaultStats);
      setError(null);

      const lastSevenDays: any[] = [];
      for (let i = 6; i >= 0; i--) {
        const date = new Date();
        date.setDate(date.getDate() - i);
        const dateStr = date.toISOString().split("T")[0];
        const activity = defaultStats.activityByDay?.[dateStr] || 0;

        lastSevenDays.push({
          date: date.toLocaleDateString("fr-FR", {
            month: "short",
            day: "numeric",
          }),
          activity,
        });
      }
      setChartData(lastSevenDays);

      setPlanData([
        { name: "Free", value: defaultStats.freeUsers, color: "#64748b" },
        { name: "Premium", value: defaultStats.proUsers, color: "#3b82f6" },
        { name: "Admin", value: defaultStats.adminUsers, color: "#8b5cf6" },
      ]);
    } catch (error) {
      const errorMsg =
        error instanceof Error ? error.message : "Erreur de chargement";
      setError(errorMsg);
      console.error("Error loading stats:", error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 size={32} className="animate-spin text-foreground/60" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="space-y-6">
        <div>
          <h2 className="text-lg font-semibold text-white">
            Vue d'ensemble système
          </h2>
          <p className="text-sm text-foreground/60 mt-1">
            Analyse des statistiques en temps réel
          </p>
        </div>

        <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-6">
          <div className="flex items-start gap-3">
            <AlertCircle size={20} className="text-red-400 mt-0.5" />
            <div className="flex-1">
              <p className="text-sm font-medium text-red-300">{error}</p>
              <button
                onClick={loadStats}
                className="text-xs text-red-300/70 hover:text-red-300 mt-3 underline"
              >
                Réessayer le chargement
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (!stats) {
    return null;
  }

  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-lg font-semibold text-white">
          Vue d'ensemble système
        </h2>
        <p className="text-sm text-foreground/60 mt-1">
          Analyse des statistiques en temps réel
        </p>
      </div>

      <div className="grid grid-cols-4 gap-4">
        <MetricCard
          label="Utilisateurs"
          value={stats.totalUsers.toString()}
          subtitle="Actifs"
          icon={Users}
          color="blue"
        />
        <MetricCard
          label="Licences"
          value={stats.activeLicenses.toString()}
          subtitle={`${stats.usedLicenses} utilisées`}
          icon={Zap}
          color="emerald"
        />
        <MetricCard
          label="Messages"
          value={stats.totalMessages.toString()}
          subtitle={`${stats.avgMessagesPerUser} en moyenne`}
          icon={FileText}
          color="purple"
        />
        <MetricCard
          label="Activité admin"
          value={stats.activityLogsCount.toString()}
          subtitle="Actions enregistrées"
          icon={Activity}
          color="amber"
        />
      </div>

      <div className="grid grid-cols-2 gap-6">
        <div className="rounded-lg border border-white/5 bg-white/[0.02] p-6">
          <h3 className="text-sm font-semibold text-white mb-4">
            Activité admin (7 jours)
          </h3>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={chartData}>
              <CartesianGrid
                strokeDasharray="3 3"
                stroke="rgba(255,255,255,0.1)"
              />
              <XAxis
                dataKey="date"
                stroke="rgba(255,255,255,0.5)"
                style={{ fontSize: "12px" }}
              />
              <YAxis
                stroke="rgba(255,255,255,0.5)"
                style={{ fontSize: "12px" }}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: "rgba(0,0,0,0.9)",
                  border: "1px solid rgba(255,255,255,0.2)",
                  borderRadius: "8px",
                }}
                labelStyle={{ color: "#fff" }}
              />
              <Bar dataKey="activity" fill="#3b82f6" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="rounded-lg border border-white/5 bg-white/[0.02] p-6">
          <h3 className="text-sm font-semibold text-white mb-4">
            Distribution des utilisateurs
          </h3>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie
                data={planData}
                cx="50%"
                cy="50%"
                innerRadius={60}
                outerRadius={100}
                paddingAngle={2}
                dataKey="value"
              >
                {planData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  backgroundColor: "rgba(0,0,0,0.9)",
                  border: "1px solid rgba(255,255,255,0.2)",
                  borderRadius: "8px",
                }}
                labelStyle={{ color: "#fff" }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-6">
        <div className="rounded-lg border border-white/5 bg-white/[0.02] p-6">
          <h3 className="text-sm font-semibold text-white mb-6">
            Répartition des utilisateurs
          </h3>
          <div className="space-y-4">
            <StatRow
              label="Utilisateurs gratuits"
              value={stats.freeUsers}
              total={stats.totalUsers}
              color="bg-slate-500"
            />
            <StatRow
              label="Utilisateurs premium"
              value={stats.proUsers}
              total={stats.totalUsers}
              color="bg-blue-500"
            />
            <StatRow
              label="Administrateurs"
              value={stats.adminUsers}
              total={stats.totalUsers}
              color="bg-purple-500"
            />
            <StatRow
              label="Utilisateurs bannis"
              value={stats.bannedUsers}
              total={stats.totalUsers}
              color="bg-red-500"
            />
          </div>
        </div>

        <div className="rounded-lg border border-white/5 bg-white/[0.02] p-6">
          <h3 className="text-sm font-semibold text-white mb-6">
            Statistiques des licences
          </h3>
          <div className="space-y-4">
            <StatRow
              label="Licences actives"
              value={stats.activeLicenses}
              total={stats.totalLicenses}
              color="bg-emerald-500"
            />
            <StatRow
              label="Licences utilisées"
              value={stats.usedLicenses}
              total={stats.totalLicenses}
              color="bg-blue-500"
            />
            <StatRow
              label="Licences disponibles"
              value={stats.totalLicenses - stats.usedLicenses}
              total={stats.totalLicenses}
              color="bg-amber-500"
            />
            <div className="pt-2 border-t border-white/5">
              <p className="text-sm text-foreground/70">
                Taux d'utilisation:{" "}
                <span className="text-white font-semibold">
                  {stats.totalLicenses > 0
                    ? Math.round(
                        (stats.usedLicenses / stats.totalLicenses) * 100,
                      )
                    : 0}
                  %
                </span>
              </p>
            </div>
          </div>
        </div>
      </div>

      <p className="text-xs text-foreground/50 text-center pt-4">
        Données actualisées à {new Date().toLocaleTimeString("fr-FR")}
      </p>
    </div>
  );
}

function MetricCard({
  label,
  value,
  subtitle,
  icon: Icon,
  color,
}: {
  label: string;
  value: string;
  subtitle: string;
  icon: any;
  color: "blue" | "emerald" | "purple" | "amber";
}) {
  const colors = {
    blue: "border-blue-500/20 bg-blue-500/5",
    emerald: "border-emerald-500/20 bg-emerald-500/5",
    purple: "border-purple-500/20 bg-purple-500/5",
    amber: "border-amber-500/20 bg-amber-500/5",
  };

  const iconColors = {
    blue: "text-blue-400",
    emerald: "text-emerald-400",
    purple: "text-purple-400",
    amber: "text-amber-400",
  };

  return (
    <div className={`rounded-lg border p-6 ${colors[color]}`}>
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs text-foreground/70 uppercase tracking-wide mb-2">
            {label}
          </p>
          <p className="text-3xl font-bold text-white">{value}</p>
          <p className="text-xs text-foreground/60 mt-2">{subtitle}</p>
        </div>
        <Icon size={20} className={`${iconColors[color]}`} />
      </div>
    </div>
  );
}

function StatRow({
  label,
  value,
  total,
  color,
}: {
  label: string;
  value: number;
  total: number;
  color: string;
}) {
  const percentage = total > 0 ? (value / total) * 100 : 0;

  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <p className="text-sm text-foreground/80">{label}</p>
        <p className="text-sm font-medium text-white">
          {value} ({percentage.toFixed(0)}%)
        </p>
      </div>
      <div className="h-2 bg-white/5 rounded-full overflow-hidden">
        <div
          className={`h-full ${color}`}
          style={{ width: `${Math.max(percentage, 5)}%` }}
        />
      </div>
    </div>
  );
}
