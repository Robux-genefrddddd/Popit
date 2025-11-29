import { Loader2, AlertCircle } from "lucide-react";

interface ActionConfirmModalProps {
  type: "promote" | "demote" | "ban" | "unban" | "reset" | "delete" | "plan";
  email: string;
  plan?: "Free" | "Classic" | "Pro";
  onConfirm: () => void;
  onCancel: () => void;
  isLoading: boolean;
}

export default function ActionConfirmModal({
  type,
  email,
  plan,
  onConfirm,
  onCancel,
  isLoading,
}: ActionConfirmModalProps) {
  const messages = {
    promote: {
      title: "Promouvoir en administrateur",
      description: `Êtes-vous sûr de vouloir promouvoir ${email} en administrateur ? Cette personne aura accès complet au panneau de contrôle.`,
      confirmText: "Promouvoir",
      color: "purple" as const,
    },
    demote: {
      title: "Rétrograder en utilisateur",
      description: `Êtes-vous sûr de vouloir rétrograder ${email} ? Cette personne perdra tous les droits administrateur.`,
      confirmText: "Rétrograder",
      color: "slate" as const,
    },
    ban: {
      title: "Bannir cet utilisateur",
      description: `Êtes-vous sûr de vouloir bannir ${email} ? Cette personne ne pourra plus se connecter.`,
      confirmText: "Bannir",
      color: "red" as const,
    },
    unban: {
      title: "Débannir cet utilisateur",
      description: `Êtes-vous sûr de vouloir débannir ${email} ? Cette personne pourra à nouveau se connecter.`,
      confirmText: "Débannir",
      color: "emerald" as const,
    },
    reset: {
      title: "Réinitialiser les messages",
      description: `Êtes-vous sûr de vouloir réinitialiser le compteur de messages pour ${email} ?`,
      confirmText: "Réinitialiser",
      color: "amber" as const,
    },
    delete: {
      title: "Supprimer cet utilisateur",
      description: `Êtes-vous absolument sûr ? La suppression de ${email} est irréversible. Tous les messages et données seront perdus.`,
      confirmText: "Supprimer",
      color: "red" as const,
    },
    plan: {
      title: "Modifier le plan d'utilisateur",
      description: `Êtes-vous sûr de vouloir modifier le plan de ${email} en "${plan}" ?`,
      confirmText: "Modifier",
      color: "blue" as const,
    },
  };

  const msg = messages[type];

  if (!msg) {
    return (
      <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4">
        <div className="bg-[#1a1a1a] border border-white/10 rounded-lg max-w-md w-full shadow-lg p-6">
          <p className="text-red-400 mb-4">
            Configuration invalide: action non reconnue
          </p>
          <button
            onClick={onCancel}
            className="w-full px-4 py-2 rounded-lg bg-white/10 hover:bg-white/20 text-white"
          >
            Fermer
          </button>
        </div>
      </div>
    );
  }

  const colorClasses = {
    purple: "bg-purple-500/10 border-purple-500/20 text-purple-400",
    slate: "bg-slate-500/10 border-slate-500/20 text-slate-400",
    red: "bg-red-500/10 border-red-500/20 text-red-400",
    emerald: "bg-emerald-500/10 border-emerald-500/20 text-emerald-400",
    amber: "bg-amber-500/10 border-amber-500/20 text-amber-400",
    blue: "bg-blue-500/10 border-blue-500/20 text-blue-400",
  };

  const buttonClasses = {
    purple: "bg-purple-500 hover:bg-purple-600 text-white",
    slate: "bg-slate-500 hover:bg-slate-600 text-white",
    red: "bg-red-500 hover:bg-red-600 text-white",
    emerald: "bg-emerald-500 hover:bg-emerald-600 text-white",
    amber: "bg-amber-500 hover:bg-amber-600 text-white",
    blue: "bg-blue-500 hover:bg-blue-600 text-white",
  };

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-[#1a1a1a] border border-white/10 rounded-lg max-w-md w-full shadow-lg">
        {/* Header */}
        <div
          className={`p-6 border-b border-white/5 ${colorClasses[msg.color as keyof typeof colorClasses]}`}
        >
          <div className="flex items-start gap-3">
            <AlertCircle size={24} className="flex-shrink-0 mt-0.5" />
            <h2 className="text-lg font-semibold">{msg.title}</h2>
          </div>
        </div>

        {/* Body */}
        <div className="p-6">
          <p className="text-foreground/80 leading-relaxed">
            {msg.description}
          </p>
        </div>

        {/* Footer */}
        <div className="p-6 border-t border-white/5 flex items-center gap-3">
          <button
            onClick={onCancel}
            disabled={isLoading}
            className="flex-1 px-4 py-2 rounded-lg bg-white/10 hover:bg-white/20 text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Annuler
          </button>
          <button
            onClick={onConfirm}
            disabled={isLoading}
            className={`flex-1 px-4 py-2 rounded-lg font-medium transition-colors flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed ${buttonClasses[msg.color as keyof typeof buttonClasses]}`}
          >
            {isLoading && <Loader2 size={16} className="animate-spin" />}
            {msg.confirmText}
          </button>
        </div>
      </div>
    </div>
  );
}
