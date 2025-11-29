import { useState, useEffect } from "react";
import { auth } from "@/lib/firebase";
import { toast } from "sonner";
import { Loader2, Save, AlertCircle } from "lucide-react";

interface AIConfig {
  model: string;
  temperature: number;
  maxTokens: number;
  systemPrompt: string;
}

export default function AdminAIConfigSection() {
  const [config, setConfig] = useState<AIConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tempConfig, setTempConfig] = useState<AIConfig | null>(null);

  useEffect(() => {
    loadConfig();
  }, []);

  const loadConfig = async () => {
    try {
      setLoading(true);
      setError(null);
      const currentUser = auth.currentUser;
      if (!currentUser) throw new Error("Non authentifié");

      const idToken = await currentUser.getIdToken();
      const response = await fetch("/api/admin/ai-config", {
        headers: { Authorization: `Bearer ${idToken}` },
      });

      if (!response.ok) {
        throw new Error("Erreur lors du chargement de la configuration");
      }

      const data = await response.json();
      const configData = data.config || data;
      setConfig(configData);
      setTempConfig({
        ...configData,
        temperature: configData.temperature ?? 0.7,
        maxTokens: configData.maxTokens ?? 2000,
        model: configData.model ?? "gpt-4o-mini",
        systemPrompt:
          configData.systemPrompt ||
          "You are a helpful assistant. Always respond in the user's language.",
      });
    } catch (error) {
      const errorMsg =
        error instanceof Error ? error.message : "Erreur de chargement";
      setError(errorMsg);
      console.error("Error loading config:", error);
    } finally {
      setLoading(false);
    }
  };

  const saveConfig = async () => {
    if (!tempConfig) return;

    try {
      setSaving(true);
      const currentUser = auth.currentUser;
      if (!currentUser) throw new Error("Non authentifié");

      const idToken = await currentUser.getIdToken();
      const response = await fetch("/api/admin/ai-config", {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${idToken}`,
        },
        body: JSON.stringify(tempConfig),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || data.error || "Erreur de sauvegarde");
      }

      setConfig(tempConfig);
      setError(null);
      toast.success("Configuration sauvegardée avec succès");
    } catch (error) {
      const errorMsg =
        error instanceof Error ? error.message : "Erreur de sauvegarde";
      toast.error(errorMsg);
      console.error("Error saving config:", error);
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 size={32} className="animate-spin text-foreground/60" />
      </div>
    );
  }

  if (!tempConfig) {
    return (
      <div className="space-y-6">
        <div>
          <h2 className="text-lg font-semibold text-white">
            Configuration de l'IA
          </h2>
          <p className="text-sm text-foreground/60 mt-1">
            Paramètres du modèle, température, tokens et instructions système
          </p>
        </div>

        <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-6">
          <div className="flex items-start gap-3">
            <AlertCircle size={20} className="text-red-400 mt-0.5" />
            <div>
              <p className="text-sm font-medium text-red-300">
                Impossible de charger la configuration
              </p>
              <button
                onClick={loadConfig}
                className="text-xs text-red-300/70 hover:text-red-300 mt-2 underline"
              >
                Réessayer
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  const hasChanges = JSON.stringify(config) !== JSON.stringify(tempConfig);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold text-white">
          Configuration de l'IA
        </h2>
        <p className="text-sm text-foreground/60 mt-1">
          Paramètres du modèle, température, tokens et instructions système
        </p>
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4">
          <div className="flex items-start gap-3">
            <AlertCircle size={20} className="text-red-400 mt-0.5" />
            <div>
              <p className="text-sm font-medium text-red-300">{error}</p>
            </div>
          </div>
        </div>
      )}

      <div className="max-w-2xl space-y-6 rounded-lg border border-white/5 bg-white/[0.02] p-8">
        <div>
          <label className="block text-sm font-medium text-white mb-3">
            Modèle IA
          </label>
          <input
            type="text"
            value={tempConfig.model}
            onChange={(e) =>
              setTempConfig({ ...tempConfig, model: e.target.value })
            }
            placeholder="ex: gpt-4o-mini, claude-3-5-sonnet, x-ai/grok-4.1-fast:free"
            disabled={saving}
            className="w-full px-4 py-2.5 rounded-lg bg-white/5 border border-white/10 text-white placeholder:text-foreground/40 hover:border-white/20 focus:border-white/30 transition-colors focus:outline-none disabled:opacity-50"
          />
          <p className="text-xs text-foreground/60 mt-2">
            Entrez le nom exact du modèle d'IA à utiliser
          </p>
        </div>

        <div>
          <div className="flex items-center justify-between mb-3">
            <label className="block text-sm font-medium text-white">
              Température
            </label>
            <span className="text-sm font-semibold text-blue-400 bg-blue-500/10 px-3 py-1 rounded">
              {tempConfig.temperature.toFixed(2)}
            </span>
          </div>
          <input
            type="range"
            min="0"
            max="2"
            step="0.1"
            value={tempConfig.temperature}
            onChange={(e) =>
              setTempConfig({
                ...tempConfig,
                temperature: parseFloat(e.target.value),
              })
            }
            disabled={saving}
            className="w-full h-2 bg-white/10 rounded-lg appearance-none cursor-pointer accent-blue-500 disabled:opacity-50"
          />
          <div className="flex justify-between text-xs text-foreground/60 mt-2">
            <span>Déterministe (0)</span>
            <span>Équilibré (1)</span>
            <span>Créatif (2)</span>
          </div>
          <p className="text-xs text-foreground/60 mt-3">
            Contrôle le caractère aléatoire des réponses
          </p>
        </div>

        <div>
          <label className="block text-sm font-medium text-white mb-3">
            Tokens maxim aux
          </label>
          <div className="flex items-center gap-3">
            <input
              type="number"
              min="100"
              max="4000"
              step="100"
              value={tempConfig.maxTokens}
              onChange={(e) =>
                setTempConfig({
                  ...tempConfig,
                  maxTokens: parseInt(e.target.value),
                })
              }
              disabled={saving}
              className="flex-1 px-4 py-2.5 rounded-lg bg-white/5 border border-white/10 text-white hover:border-white/20 focus:border-white/30 transition-colors focus:outline-none disabled:opacity-50"
            />
            <span className="text-sm text-foreground/60">tokens</span>
          </div>
          <p className="text-xs text-foreground/60 mt-2">
            Nombre maximum de tokens dans les réponses (1 token ≈ 4 caractères)
          </p>
        </div>

        <div>
          <label className="block text-sm font-medium text-white mb-3">
            Instruction système
          </label>
          <textarea
            value={tempConfig.systemPrompt}
            onChange={(e) =>
              setTempConfig({
                ...tempConfig,
                systemPrompt: e.target.value,
              })
            }
            disabled={saving}
            rows={6}
            className="w-full px-4 py-2.5 rounded-lg bg-white/5 border border-white/10 text-white hover:border-white/20 focus:border-white/30 transition-colors focus:outline-none resize-none font-mono text-sm disabled:opacity-50"
            placeholder="Entrez l'instruction système pour guider le comportement de l'IA..."
          />
          <p className="text-xs text-foreground/60 mt-2">
            Instructions de base pour guider le comportement de l'IA
          </p>
        </div>
      </div>

      <div className="flex items-center gap-3 pt-4 border-t border-white/5">
        {hasChanges && (
          <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-amber-500/10 border border-amber-500/20">
            <div className="w-2 h-2 rounded-full bg-amber-400" />
            <p className="text-xs text-amber-300">
              Modifications non sauvegardées
            </p>
          </div>
        )}
        <div className="flex-1" />
        <button
          onClick={() => setTempConfig(config)}
          disabled={!hasChanges || saving}
          className="px-4 py-2 rounded-lg bg-white/10 hover:bg-white/20 text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed font-medium"
        >
          Annuler
        </button>
        <button
          onClick={saveConfig}
          disabled={!hasChanges || saving}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-500 hover:bg-blue-600 text-white font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {saving && <Loader2 size={16} className="animate-spin" />}
          <Save size={16} />
          Sauvegarder
        </button>
      </div>
    </div>
  );
}
