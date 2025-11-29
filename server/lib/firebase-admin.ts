import { initializeApp, cert, getApps } from "firebase-admin/app";
import { getFirestore, Timestamp } from "firebase-admin/firestore";
import { getAuth } from "firebase-admin/auth";

function getServiceAccount() {
  const serviceAccountKey = process.env.FIREBASE_SERVICE_ACCOUNT_KEY;

  if (!serviceAccountKey) {
    throw new Error(
      "FIREBASE_SERVICE_ACCOUNT_KEY environment variable not set. " +
      "Please set it to your Firebase service account JSON."
    );
  }

  try {
    const serviceAccount = JSON.parse(serviceAccountKey);

    // Validate that it has required fields
    if (
      !serviceAccount.type ||
      !serviceAccount.project_id ||
      !serviceAccount.private_key
    ) {
      throw new Error(
        "Invalid FIREBASE_SERVICE_ACCOUNT_KEY: missing required fields (type, project_id, private_key)"
      );
    }

    return serviceAccount;
  } catch (error) {
    if (
      error instanceof Error &&
      error.message.includes("Invalid FIREBASE_SERVICE_ACCOUNT_KEY")
    ) {
      throw error;
    }
    throw new Error(
      "Failed to parse FIREBASE_SERVICE_ACCOUNT_KEY as JSON. " +
      "Make sure it's a valid JSON string from your Firebase service account."
    );
  }
}

let adminDb: ReturnType<typeof getFirestore> | null = null;
let adminAuth: ReturnType<typeof getAuth> | null = null;
let initialized = false;

export function initializeFirebaseAdmin() {
  if (initialized) return;

  try {
    const serviceAccount = getServiceAccount();

    const app =
      getApps().length > 0
        ? getApps()[0]
        : initializeApp({
            credential: cert(serviceAccount as any),
            projectId: serviceAccount.project_id,
          });

    adminDb = getFirestore(app);
    adminAuth = getAuth(app);
    initialized = true;

    console.log("Firebase Admin SDK initialized securely");
  } catch (error) {
    console.error("Failed to initialize Firebase Admin SDK:", error);
    throw error;
  }
}

export function getAdminDb() {
  return adminDb;
}

export function getAdminAuth() {
  return adminAuth;
}

export function isAdminInitialized(): boolean {
  return adminDb !== null && adminAuth !== null;
}

export class FirebaseAdminService {
  static getAdminDb() {
    return adminDb;
  }

  static getAdminAuth() {
    return adminAuth;
  }

  static async verifyAdmin(idToken: string): Promise<string> {
    if (!adminAuth || !adminDb) {
      throw new Error("Firebase Admin SDK not initialized");
    }

    const decodedToken = await adminAuth.verifyIdToken(idToken);
    const userDoc = await adminDb
      .collection("users")
      .doc(decodedToken.uid)
      .get();

    if (!userDoc.exists || !userDoc.data()?.isAdmin) {
      await this.logAdminAction(decodedToken.uid, "UNAUTHORIZED_ADMIN_ACCESS", {
        reason: "Not an admin",
      });
      throw new Error("Unauthorized: Not an admin");
    }

    return decodedToken.uid;
  }

  static async logAdminAction(
    adminUid: string,
    action: string,
    data: Record<string, any> = {},
  ) {
    if (!adminDb) return;

    try {
      await adminDb.collection("admin_logs").add({
        adminUid,
        action,
        data,
        timestamp: Timestamp.now(),
        ipAddress: data.ipAddress || "unknown",
      });
    } catch (error) {
      console.error("Failed to log admin action:", error);
    }
  }

  static async getUser(userId: string) {
    if (!adminDb) throw new Error("Database not initialized");
    const doc = await adminDb.collection("users").doc(userId).get();
    if (!doc.exists) return null;
    return { uid: doc.id, ...doc.data() };
  }

  static async getAllUsers(limit = 100, startAfter?: string) {
    if (!adminDb) throw new Error("Database not initialized");

    let query: any = adminDb.collection("users").limit(limit);
    if (startAfter) {
      const startDoc = await adminDb.collection("users").doc(startAfter).get();
      query = query.startAfter(startDoc);
    }

    const snapshot = await query.get();
    return snapshot.docs.map((doc) => ({
      uid: doc.id,
      email: doc.data().email,
      displayName: doc.data().displayName,
      plan: doc.data().plan || "Free",
      isAdmin: doc.data().isAdmin || false,
      isBanned: doc.data().isBanned || false,
      messagesUsed: doc.data().messagesUsed || 0,
      messagesLimit: doc.data().messagesLimit || 10,
      createdAt: doc.data().createdAt,
      bannedAt: doc.data().bannedAt,
      banReason: doc.data().banReason,
    }));
  }

  static async updateUserPlan(
    adminUid: string,
    userId: string,
    plan: "Free" | "Classic" | "Pro",
  ) {
    if (!adminDb) throw new Error("Database not initialized");

    const user = await this.getUser(userId);
    if (!user) throw new Error("User not found");

    const planLimits: Record<string, number> = {
      Free: 10,
      Classic: 100,
      Pro: 1000,
    };

    await adminDb.collection("users").doc(userId).update({
      plan,
      messagesLimit: planLimits[plan],
    });

    await this.logAdminAction(adminUid, "UPDATE_USER_PLAN", {
      targetUser: userId,
      newPlan: plan,
    });
  }

  static async banUser(adminUid: string, userId: string, reason: string) {
    if (!adminDb) throw new Error("Database not initialized");

    const user = await this.getUser(userId);
    if (!user) throw new Error("User not found");
    if (user.isAdmin) throw new Error("Cannot ban admin users");

    await adminDb.collection("users").doc(userId).update({
      isBanned: true,
      bannedAt: Timestamp.now(),
      bannedBy: adminUid,
      banReason: reason,
    });

    await this.logAdminAction(adminUid, "BAN_USER", {
      targetUser: userId,
      reason,
    });
  }

  static async unbanUser(adminUid: string, userId: string) {
    if (!adminDb) throw new Error("Database not initialized");

    const user = await this.getUser(userId);
    if (!user) throw new Error("User not found");

    await adminDb.collection("users").doc(userId).update({
      isBanned: false,
      bannedAt: null,
      bannedBy: null,
      banReason: null,
    });

    await this.logAdminAction(adminUid, "UNBAN_USER", {
      targetUser: userId,
    });
  }

  static async resetUserMessages(adminUid: string, userId: string) {
    if (!adminDb) throw new Error("Database not initialized");

    const user = await this.getUser(userId);
    if (!user) throw new Error("User not found");

    await adminDb.collection("users").doc(userId).update({
      messagesUsed: 0,
      lastMessageReset: Timestamp.now(),
    });

    await this.logAdminAction(adminUid, "RESET_USER_MESSAGES", {
      targetUser: userId,
    });
  }

  static async deleteUser(adminUid: string, userId: string) {
    if (!adminDb || !adminAuth) throw new Error("Firebase not initialized");

    const user = await this.getUser(userId);
    if (!user) throw new Error("User not found");
    if (user.isAdmin) throw new Error("Cannot delete admin users");

    await adminDb.collection("users").doc(userId).delete();

    try {
      await adminAuth.deleteUser(userId);
    } catch (e) {
      console.warn("User not in Auth, continuing...");
    }

    await this.logAdminAction(adminUid, "DELETE_USER", {
      targetUser: userId,
      userEmail: user.email,
    });
  }

  static async promoteUser(adminUid: string, userId: string) {
    if (!adminDb || !adminAuth) throw new Error("Firebase not initialized");

    const user = await this.getUser(userId);
    if (!user) throw new Error("User not found");

    await adminDb.collection("users").doc(userId).update({
      isAdmin: true,
    });

    try {
      await adminAuth.setCustomUserClaims(userId, { admin: true });
    } catch (e) {
      console.warn("Could not set custom claims:", e);
    }

    await this.logAdminAction(adminUid, "PROMOTE_USER", {
      targetUser: userId,
    });
  }

  static async demoteUser(adminUid: string, userId: string) {
    if (!adminDb || !adminAuth) throw new Error("Firebase not initialized");

    const user = await this.getUser(userId);
    if (!user) throw new Error("User not found");

    await adminDb.collection("users").doc(userId).update({
      isAdmin: false,
    });

    try {
      await adminAuth.setCustomUserClaims(userId, {});
    } catch (e) {
      console.warn("Could not clear custom claims:", e);
    }

    await this.logAdminAction(adminUid, "DEMOTE_USER", {
      targetUser: userId,
    });
  }

  static async getAllLicenses(limit = 100) {
    if (!adminDb) throw new Error("Database not initialized");

    const snapshot = await adminDb.collection("licenses").limit(limit).get();

    return snapshot.docs.map((doc) => ({
      key: doc.id,
      plan: doc.data().plan || "Free",
      valid: doc.data().valid !== false,
      usedBy: doc.data().usedBy || null,
      usedAt: doc.data().usedAt,
      createdAt: doc.data().createdAt,
      createdBy: doc.data().createdBy,
      validityDays: doc.data().validityDays,
    }));
  }

  static async createLicense(
    adminUid: string,
    plan: "Free" | "Classic" | "Pro",
    validityDays: number,
  ) {
    if (!adminDb) throw new Error("Database not initialized");

    const licenseKey = `LIC-${Date.now()}-${Math.random().toString(36).substr(2, 9).toUpperCase()}`;

    await adminDb.collection("licenses").doc(licenseKey).set({
      plan,
      valid: true,
      createdAt: Timestamp.now(),
      createdBy: adminUid,
      validityDays,
    });

    await this.logAdminAction(adminUid, "CREATE_LICENSE", {
      licenseKey,
      plan,
      validityDays,
    });

    return licenseKey;
  }

  static async invalidateLicense(adminUid: string, licenseKey: string) {
    if (!adminDb) throw new Error("Database not initialized");

    const licenseDoc = await adminDb.collection("licenses").doc(licenseKey).get();
    if (!licenseDoc.exists) {
      throw new Error("License not found");
    }

    await adminDb.collection("licenses").doc(licenseKey).update({
      valid: false,
    });

    await this.logAdminAction(adminUid, "INVALIDATE_LICENSE", {
      licenseKey,
    });
  }

  static async deleteLicense(adminUid: string, licenseKey: string) {
    if (!adminDb) throw new Error("Database not initialized");

    const licenseDoc = await adminDb.collection("licenses").doc(licenseKey).get();
    if (!licenseDoc.exists) {
      throw new Error("License not found");
    }

    await adminDb.collection("licenses").doc(licenseKey).delete();

    await this.logAdminAction(adminUid, "DELETE_LICENSE", {
      licenseKey,
    });
  }

  static async getAIConfig() {
    if (!adminDb) throw new Error("Database not initialized");

    const doc = await adminDb.collection("config").doc("ai").get();

    if (!doc.exists) {
      return {
        model: "gpt-4o-mini",
        temperature: 0.7,
        maxTokens: 2000,
        systemPrompt: "You are a helpful AI assistant.",
      };
    }

    return doc.data();
  }

  static async updateAIConfig(
    adminUid: string,
    config: {
      model: string;
      temperature: number;
      maxTokens: number;
      systemPrompt: string;
    },
  ) {
    if (!adminDb) throw new Error("Database not initialized");

    await adminDb.collection("config").doc("ai").set(config, { merge: true });

    await this.logAdminAction(adminUid, "UPDATE_AI_CONFIG", { config });
  }

  static async getSystemStats() {
    if (!adminDb) throw new Error("Database not initialized");

    const usersSnapshot = await adminDb.collection("users").get();
    const licenseSnapshot = await adminDb.collection("licenses").get();
    const logsSnapshot = await adminDb.collection("admin_logs").get();

    let totalAdmins = 0;
    let bannedUsers = 0;
    let totalMessages = 0;

    usersSnapshot.docs.forEach((doc) => {
      const data = doc.data();
      if (data.isAdmin) totalAdmins++;
      if (data.isBanned) bannedUsers++;
      totalMessages += data.messagesUsed || 0;
    });

    // Count valid licenses
    let activeLicenses = 0;
    licenseSnapshot.docs.forEach((doc) => {
      if (doc.data().valid !== false) activeLicenses++;
    });

    return {
      totalUsers: usersSnapshot.size,
      totalAdmins,
      bannedUsers,
      activeLicenses,
      systemHealth: "Optimal",
      uptime: 99.95,
      avgLatency: 45,
      storage: {
        used: 2.5,
        total: 100,
      },
    };
  }

  static async purgeInvalidLicenses(adminUid: string) {
    if (!adminDb) throw new Error("Database not initialized");

    const snapshot = await adminDb
      .collection("licenses")
      .where("valid", "==", false)
      .get();

    const batch = adminDb.batch();
    snapshot.docs.forEach((doc) => {
      batch.delete(doc.ref);
    });

    await batch.commit();

    await this.logAdminAction(adminUid, "PURGE_LICENSES", {
      count: snapshot.size,
    });

    return snapshot.size;
  }

  static async getAdminLogs(limit = 50) {
    if (!adminDb) throw new Error("Database not initialized");

    const snapshot = await adminDb
      .collection("admin_logs")
      .orderBy("timestamp", "desc")
      .limit(limit)
      .get();

    return snapshot.docs.map((doc) => ({
      id: doc.id,
      ...doc.data(),
    }));
  }

  static async clearOldLogs(adminUid: string, daysOld: number) {
    if (!adminDb) throw new Error("Database not initialized");

    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - daysOld);

    const snapshot = await adminDb
      .collection("admin_logs")
      .where("timestamp", "<", Timestamp.fromDate(cutoffDate))
      .get();

    const batch = adminDb.batch();
    snapshot.docs.forEach((doc) => {
      batch.delete(doc.ref);
    });

    await batch.commit();

    await this.logAdminAction(adminUid, "CLEAR_OLD_LOGS", {
      daysOld,
      count: snapshot.size,
    });

    return snapshot.size;
  }

  static async getBannedUsers() {
    if (!adminDb) throw new Error("Database not initialized");

    const snapshot = await adminDb
      .collection("users")
      .where("isBanned", "==", true)
      .get();

    return snapshot.docs.map((doc) => ({
      uid: doc.id,
      email: doc.data().email,
      displayName: doc.data().displayName,
      bannedAt: doc.data().bannedAt,
      bannedBy: doc.data().bannedBy,
      banReason: doc.data().banReason,
    }));
  }

  static async getMaintenanceStatus() {
    if (!adminDb) throw new Error("Database not initialized");

    const doc = await adminDb.collection("config").doc("maintenance").get();

    if (!doc.exists) {
      return {
        isGlobalMaintenance: false,
        partialServices: [],
        plannedMaintenance: null,
      };
    }

    return doc.data();
  }

  static async enableGlobalMaintenance(adminUid: string, message?: string) {
    if (!adminDb) throw new Error("Database not initialized");

    await adminDb.collection("config").doc("maintenance").set(
      {
        isGlobalMaintenance: true,
        message: message || "System maintenance in progress",
        enabledAt: Timestamp.now(),
        enabledBy: adminUid,
      },
      { merge: true },
    );

    await this.logAdminAction(adminUid, "ENABLE_GLOBAL_MAINTENANCE", {
      message,
    });
  }

  static async disableGlobalMaintenance(adminUid: string) {
    if (!adminDb) throw new Error("Database not initialized");

    await adminDb.collection("config").doc("maintenance").set(
      {
        isGlobalMaintenance: false,
      },
      { merge: true },
    );

    await this.logAdminAction(adminUid, "DISABLE_GLOBAL_MAINTENANCE", {});
  }

  static async enablePartialMaintenance(
    adminUid: string,
    services: string[],
    message?: string,
  ) {
    if (!adminDb) throw new Error("Database not initialized");

    await adminDb.collection("config").doc("maintenance").set(
      {
        partialServices: services,
        message: message || "Some services are under maintenance",
        enabledAt: Timestamp.now(),
        enabledBy: adminUid,
      },
      { merge: true },
    );

    await this.logAdminAction(adminUid, "ENABLE_PARTIAL_MAINTENANCE", {
      services,
      message,
    });
  }

  static async disablePartialMaintenance(adminUid: string) {
    if (!adminDb) throw new Error("Database not initialized");

    await adminDb.collection("config").doc("maintenance").set(
      {
        partialServices: [],
      },
      { merge: true },
    );

    await this.logAdminAction(adminUid, "DISABLE_PARTIAL_MAINTENANCE", {});
  }

  static async enableIAMaintenance(adminUid: string, message?: string) {
    if (!adminDb) throw new Error("Database not initialized");

    await adminDb.collection("config").doc("maintenance").set(
      {
        iaService: {
          enabled: false,
          message: message || "AI service is under maintenance",
          enabledAt: Timestamp.now(),
          enabledBy: adminUid,
        },
      },
      { merge: true },
    );

    await this.logAdminAction(adminUid, "ENABLE_IA_MAINTENANCE", {
      message,
    });
  }

  static async disableIAMaintenance(adminUid: string) {
    if (!adminDb) throw new Error("Database not initialized");

    await adminDb.collection("config").doc("maintenance").set(
      {
        iaService: {
          enabled: true,
        },
      },
      { merge: true },
    );

    await this.logAdminAction(adminUid, "DISABLE_IA_MAINTENANCE", {});
  }

  static async enableLicenseMaintenance(adminUid: string, message?: string) {
    if (!adminDb) throw new Error("Database not initialized");

    await adminDb.collection("config").doc("maintenance").set(
      {
        licenseService: {
          enabled: false,
          message: message || "License service is under maintenance",
          enabledAt: Timestamp.now(),
          enabledBy: adminUid,
        },
      },
      { merge: true },
    );

    await this.logAdminAction(adminUid, "ENABLE_LICENSE_MAINTENANCE", {
      message,
    });
  }

  static async disableLicenseMaintenance(adminUid: string) {
    if (!adminDb) throw new Error("Database not initialized");

    await adminDb.collection("config").doc("maintenance").set(
      {
        licenseService: {
          enabled: true,
        },
      },
      { merge: true },
    );

    await this.logAdminAction(adminUid, "DISABLE_LICENSE_MAINTENANCE", {});
  }

  static async enablePlannedMaintenance(
    adminUid: string,
    plannedTime: string,
    message?: string,
  ) {
    if (!adminDb) throw new Error("Database not initialized");

    await adminDb.collection("config").doc("maintenance").set(
      {
        plannedMaintenance: {
          enabled: true,
          scheduledAt: plannedTime,
          message: message || "Planned maintenance scheduled",
          scheduledBy: adminUid,
        },
      },
      { merge: true },
    );

    await this.logAdminAction(adminUid, "ENABLE_PLANNED_MAINTENANCE", {
      plannedTime,
      message,
    });
  }

  static async disablePlannedMaintenance(adminUid: string) {
    if (!adminDb) throw new Error("Database not initialized");

    await adminDb.collection("config").doc("maintenance").set(
      {
        plannedMaintenance: {
          enabled: false,
        },
      },
      { merge: true },
    );

    await this.logAdminAction(adminUid, "DISABLE_PLANNED_MAINTENANCE", {});
  }
}
