import React, { createContext, useContext, useEffect, useState } from "react";
import { db } from "@/lib/firebase";
import { doc, onSnapshot } from "firebase/firestore";

export interface MaintenanceSettings {
  global: boolean;
  partial: boolean;
  planned: boolean;
  ia: boolean;
  license: boolean;
  message: string;
  plannedTime?: string;
  updatedAt?: Date;
  enabledBy?: string;
}

interface MaintenanceContextType {
  maintenance: MaintenanceSettings | null;
  loading: boolean;
  error: string | null;
}

const MaintenanceContext = createContext<MaintenanceContextType | undefined>(
  undefined,
);

export function MaintenanceProvider({
  children,
}: {
  children: React.ReactNode;
}) {
  const [maintenance, setMaintenance] = useState<MaintenanceSettings | null>(
    null,
  );
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    let isMounted = true;

    const unsubscribe = onSnapshot(
      doc(db, "settings", "maintenance"),
      (snapshot) => {
        if (!isMounted) return;

        if (snapshot.exists()) {
          const data = snapshot.data() as any;
          setMaintenance({
            global: data.global ?? false,
            partial: data.partial ?? false,
            planned: data.planned ?? false,
            ia: data.ia ?? false,
            license: data.license ?? false,
            message: data.message ?? "",
            plannedTime: data.plannedTime,
            updatedAt: data.updatedAt?.toDate?.() ?? new Date(),
            enabledBy: data.enabledBy,
          });
        } else {
          setMaintenance({
            global: false,
            partial: false,
            planned: false,
            ia: false,
            license: false,
            message: "",
          });
        }
        setError(null);
        setLoading(false);
      },
      (err: any) => {
        if (!isMounted) return;

        console.error("Error listening to maintenance status:", err);

        // Default to no maintenance if Firestore is unavailable
        setMaintenance({
          global: false,
          partial: false,
          planned: false,
          ia: false,
          license: false,
          message: "",
        });
        setError(null); // Don't show error to user, just use defaults
        setLoading(false);
      },
    );

    return () => {
      isMounted = false;
      unsubscribe();
    };
  }, []);

  return (
    <MaintenanceContext.Provider value={{ maintenance, loading, error }}>
      {children}
    </MaintenanceContext.Provider>
  );
}

export function useMaintenance() {
  const context = useContext(MaintenanceContext);
  if (context === undefined) {
    throw new Error("useMaintenance must be used within a MaintenanceProvider");
  }
  return context;
}
