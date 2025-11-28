import { initializeApp, cert, getApps } from "firebase-admin/app";
import { getFirestore, Timestamp } from "firebase-admin/firestore";
import { getAuth } from "firebase-admin/auth";

let adminDb: ReturnType<typeof getFirestore> | null = null;
let adminAuth: ReturnType<typeof getAuth> | null = null;
let initialized = false;

export function initializeFirebaseAdmin() {
  if (initialized) return;

  const serviceAccountKey = process.env.FIREBASE_SERVICE_ACCOUNT_KEY;

  if (!serviceAccountKey) {
    console.error(
      "FIREBASE_SERVICE_ACCOUNT_KEY not set. Admin operations disabled.",
    );
    return;
  }

  try {
    const serviceAccount = JSON.parse(serviceAccountKey);

    const app = getApps().length > 0
      ? getApps()[0]
      : initializeApp({
          credential: cert(serviceAccount),
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

  // Verify admin status via Firebase Admin SDK
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

  // Log admin actions
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

  // Get user by ID
  static async getUser(userId: string) {
    if (!adminDb) throw new Error("Database not initialized");
    const doc = await adminDb.collection("users").doc(userId).get();
    if (!doc.exists) return null;
    return { uid: doc.id, ...doc.data() };
  }

  // Get all users with pagination
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

  // Update user plan
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

  // Ban user
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

  // Unban user
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

  // Reset user messages
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

  // Delete user (both Auth and Firestore)
  static async deleteUser(adminUid: string, userId: string) {
    if (!adminDb || !adminAuth) throw new Error("Firebase not initialized");

    const user = await this.getUser(userId);
    if (!user) throw new Error("User not found");
    if (user.isAdmin) throw new Error("Cannot delete admin users");

    // Delete from Firestore
    await adminDb.collection("users").doc(userId).delete();

    // Delete from Auth
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

  // Promote user to admin
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

  // Demote admin to user
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

  // Get all licenses
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

  // Create license
  static async createLicense(
    adminUid: string,
    plan: "Free" | "Classic" | "Pro",
    validityDays: number,
  ) {
    if (!adminDb) throw new Error("Database not initialized");

    const licenseKey = `LIC-${Date.now()}-${Math.random().toString(36).substr(2, 9).toUpperCase()}`;

    await adminDb.collection("licenses").doc(licenseKey).set({
      key: licenseKey,
      plan,
      validityDays,
      valid: true,
      createdBy: adminUid,
      createdAt: Timestamp.now(),
      usedBy: null,
      usedAt: null,
    });

    await this.logAdminAction(adminUid, "CREATE_LICENSE", {
      licenseKey,
      plan,
      validityDays,
    });

    return licenseKey;
  }

  // Invalidate license
  static async invalidateLicense(adminUid: string, licenseKey: string) {
    if (!adminDb) throw new Error("Database not initialized");

    const license = await adminDb.collection("licenses").doc(licenseKey).get();
    if (!license.exists) throw new Error("License not found");

    await adminDb.collection("licenses").doc(licenseKey).update({
      valid: false,
      invalidatedAt: Timestamp.now(),
      invalidatedBy: adminUid,
    });

    await this.logAdminAction(adminUid, "INVALIDATE_LICENSE", {
      licenseKey,
    });
  }

  // Delete license
  static async deleteLicense(adminUid: string, licenseKey: string) {
    if (!adminDb) throw new Error("Database not initialized");

    const license = await adminDb.collection("licenses").doc(licenseKey).get();
    if (!license.exists) throw new Error("License not found");

    await adminDb.collection("licenses").doc(licenseKey).delete();

    await this.logAdminAction(adminUid, "DELETE_LICENSE", {
      licenseKey,
      plan: license.data().plan,
    });
  }

  // Get system statistics
  static async getSystemStats() {
    if (!adminDb) throw new Error("Database not initialized");

    const usersSnap = await adminDb.collection("users").get();
    const users = usersSnap.docs.map((d) => d.data());
    const licensesSnap = await adminDb.collection("licenses").get();
    const licenses = licensesSnap.docs.map((d) => d.data());

    const totalUsers = users.length;
    const adminUsers = users.filter((u) => u.isAdmin).length;
    const bannedUsers = users.filter((u) => u.isBanned).length;
    const freeUsers = users.filter((u) => u.plan === "Free").length;
    const proUsers = users.filter(
      (u) => u.plan === "Classic" || u.plan === "Pro",
    ).length;
    const totalMessages = users.reduce(
      (sum, u) => sum + (u.messagesUsed || 0),
      0,
    );
    const totalLicenses = licenses.length;
    const usedLicenses = licenses.filter((l) => l.usedBy).length;
    const activeLicenses = licenses.filter((l) => l.valid).length;

    // Get last 7 days activity
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

    const logsSnap = await adminDb
      .collection("admin_logs")
      .where("timestamp", ">=", Timestamp.fromDate(sevenDaysAgo))
      .get();

    const activityByDay: Record<string, number> = {};
    logsSnap.docs.forEach((doc) => {
      const timestamp = doc.data().timestamp.toDate();
      const dayKey = timestamp.toISOString().split("T")[0];
      activityByDay[dayKey] = (activityByDay[dayKey] || 0) + 1;
    });

    return {
      totalUsers,
      adminUsers,
      bannedUsers,
      freeUsers,
      proUsers,
      totalMessages,
      avgMessagesPerUser:
        totalUsers > 0 ? Math.round(totalMessages / totalUsers) : 0,
      totalLicenses,
      usedLicenses,
      activeLicenses,
      activityLogsCount: logsSnap.size,
      activityByDay,
    };
  }

  // Purge invalid licenses
  static async purgeInvalidLicenses(adminUid: string) {
    if (!adminDb) throw new Error("Database not initialized");

    const snapshot = await adminDb
      .collection("licenses")
      .where("valid", "==", false)
      .get();

    let deleted = 0;
    for (const doc of snapshot.docs) {
      await doc.ref.delete();
      deleted++;
    }

    await this.logAdminAction(adminUid, "PURGE_INVALID_LICENSES", {
      deletedCount: deleted,
    });

    return deleted;
  }

  // Get admin logs
  static async getAdminLogs(limit = 100) {
    if (!adminDb) throw new Error("Database not initialized");

    const snapshot = await adminDb
      .collection("admin_logs")
      .orderBy("timestamp", "desc")
      .limit(limit)
      .get();

    return snapshot.docs.map((doc) => ({
      id: doc.id,
      adminUid: doc.data().adminUid,
      action: doc.data().action,
      data: doc.data().data,
      timestamp: doc.data().timestamp,
    }));
  }

  // Clear old logs
  static async clearOldLogs(adminUid: string, daysOld: number = 90) {
    if (!adminDb) throw new Error("Database not initialized");

    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - daysOld);

    const snapshot = await adminDb
      .collection("admin_logs")
      .where("timestamp", "<", Timestamp.fromDate(cutoffDate))
      .get();

    let deleted = 0;
    for (const doc of snapshot.docs) {
      await doc.ref.delete();
      deleted++;
    }

    await this.logAdminAction(adminUid, "CLEAR_OLD_LOGS", {
      daysOld,
      deletedCount: deleted,
    });

    return deleted;
  }

  // Get banned users
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

  // Get AI configuration
  static async getAIConfig() {
    if (!adminDb) throw new Error("Database not initialized");

    const doc = await adminDb.collection("settings").doc("ai_config").get();

    if (!doc.exists) {
      return {
        model: "x-ai/grok-4.1-fast:free",
        temperature: 0.7,
        maxTokens: 2048,
        systemPrompt:
          "You are a helpful assistant. Always respond in the user's language.",
      };
    }

    return doc.data();
  }

  // Update AI configuration
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

    await adminDb.collection("settings").doc("ai_config").set(config);

    await this.logAdminAction(adminUid, "UPDATE_AI_CONFIG", config);
  }

  // Maintenance management

  // Get maintenance status
  static async getMaintenanceStatus() {
    if (!adminDb) throw new Error("Database not initialized");

    try {
      const doc = await adminDb.collection("settings").doc("maintenance").get();
      if (!doc.exists) {
        return {
          global: false,
          partial: false,
          services: [],
          message: "",
          startedAt: null,
        };
      }
      return doc.data();
    } catch (error) {
      console.error("Error getting maintenance status:", error);
      return {
        global: false,
        partial: false,
        services: [],
        message: "",
        startedAt: null,
      };
    }
  }

  // Enable global maintenance
  static async enableGlobalMaintenance(adminUid: string, message: string = "") {
    if (!adminDb) throw new Error("Database not initialized");

    await adminDb
      .collection("settings")
      .doc("maintenance")
      .set({
        global: true,
        partial: false,
        services: [],
        message: message || "Le site est actuellement en maintenance",
        startedAt: Timestamp.now(),
        enabledBy: adminUid,
      });

    await this.logAdminAction(adminUid, "ENABLE_GLOBAL_MAINTENANCE", {
      message,
    });
  }

  // Disable global maintenance
  static async disableGlobalMaintenance(adminUid: string) {
    if (!adminDb) throw new Error("Database not initialized");

    await adminDb.collection("settings").doc("maintenance").set({
      global: false,
      partial: false,
      services: [],
      message: "",
      startedAt: null,
      disabledAt: Timestamp.now(),
      disabledBy: adminUid,
    });

    await this.logAdminAction(adminUid, "DISABLE_GLOBAL_MAINTENANCE", {});
  }

  // Enable partial maintenance
  static async enablePartialMaintenance(
    adminUid: string,
    services: string[] = [],
    message: string = "",
  ) {
    if (!adminDb) throw new Error("Database not initialized");

    await adminDb
      .collection("settings")
      .doc("maintenance")
      .set({
        global: false,
        partial: true,
        services,
        message: message || "Certains services peuvent être indisponibles",
        startedAt: Timestamp.now(),
        enabledBy: adminUid,
      });

    await this.logAdminAction(adminUid, "ENABLE_PARTIAL_MAINTENANCE", {
      services,
      message,
    });
  }

  // Disable partial maintenance
  static async disablePartialMaintenance(adminUid: string) {
    if (!adminDb) throw new Error("Database not initialized");

    await adminDb.collection("settings").doc("maintenance").set({
      global: false,
      partial: false,
      services: [],
      message: "",
      startedAt: null,
      disabledAt: Timestamp.now(),
      disabledBy: adminUid,
    });

    await this.logAdminAction(adminUid, "DISABLE_PARTIAL_MAINTENANCE", {});
  }

  // Enable IA service maintenance
  static async enableIAMaintenance(adminUid: string, message: string = "") {
    if (!adminDb) throw new Error("Database not initialized");

    const currentDoc = await adminDb
      .collection("settings")
      .doc("maintenance")
      .get();
    const currentData = currentDoc.exists ? currentDoc.data() : {};

    await adminDb
      .collection("settings")
      .doc("maintenance")
      .set({
        ...currentData,
        ia: true,
        message: message || "Le service IA est temporairement indisponible",
        updatedAt: Timestamp.now(),
        enabledBy: adminUid,
      });

    await this.logAdminAction(adminUid, "ENABLE_IA_MAINTENANCE", { message });
  }

  // Disable IA service maintenance
  static async disableIAMaintenance(adminUid: string) {
    if (!adminDb) throw new Error("Database not initialized");

    const currentDoc = await adminDb
      .collection("settings")
      .doc("maintenance")
      .get();
    const currentData = currentDoc.exists ? currentDoc.data() : {};

    await adminDb
      .collection("settings")
      .doc("maintenance")
      .set({
        ...currentData,
        ia: false,
        updatedAt: Timestamp.now(),
      });

    await this.logAdminAction(adminUid, "DISABLE_IA_MAINTENANCE", {});
  }

  // Enable License service maintenance
  static async enableLicenseMaintenance(
    adminUid: string,
    message: string = "",
  ) {
    if (!adminDb) throw new Error("Database not initialized");

    const currentDoc = await adminDb
      .collection("settings")
      .doc("maintenance")
      .get();
    const currentData = currentDoc.exists ? currentDoc.data() : {};

    await adminDb
      .collection("settings")
      .doc("maintenance")
      .set({
        ...currentData,
        license: true,
        message:
          message || "Le service de gestion des licences est en maintenance",
        updatedAt: Timestamp.now(),
        enabledBy: adminUid,
      });

    await this.logAdminAction(adminUid, "ENABLE_LICENSE_MAINTENANCE", {
      message,
    });
  }

  // Disable License service maintenance
  static async disableLicenseMaintenance(adminUid: string) {
    if (!adminDb) throw new Error("Database not initialized");

    const currentDoc = await adminDb
      .collection("settings")
      .doc("maintenance")
      .get();
    const currentData = currentDoc.exists ? currentDoc.data() : {};

    await adminDb
      .collection("settings")
      .doc("maintenance")
      .set({
        ...currentData,
        license: false,
        updatedAt: Timestamp.now(),
      });

    await this.logAdminAction(adminUid, "DISABLE_LICENSE_MAINTENANCE", {});
  }

  // Enable Planned maintenance
  static async enablePlannedMaintenance(
    adminUid: string,
    plannedTime: string,
    message: string = "",
  ) {
    if (!adminDb) throw new Error("Database not initialized");

    const currentDoc = await adminDb
      .collection("settings")
      .doc("maintenance")
      .get();
    const currentData = currentDoc.exists ? currentDoc.data() : {};

    await adminDb
      .collection("settings")
      .doc("maintenance")
      .set({
        ...currentData,
        planned: true,
        plannedTime,
        message: message || "Une maintenance est prévue",
        updatedAt: Timestamp.now(),
        enabledBy: adminUid,
      });

    await this.logAdminAction(adminUid, "ENABLE_PLANNED_MAINTENANCE", {
      plannedTime,
      message,
    });
  }

  // Disable Planned maintenance
  static async disablePlannedMaintenance(adminUid: string) {
    if (!adminDb) throw new Error("Database not initialized");

    const currentDoc = await adminDb
      .collection("settings")
      .doc("maintenance")
      .get();
    const currentData = currentDoc.exists ? currentDoc.data() : {};

    await adminDb
      .collection("settings")
      .doc("maintenance")
      .set({
        ...currentData,
        planned: false,
        plannedTime: null,
        updatedAt: Timestamp.now(),
      });

    await this.logAdminAction(adminUid, "DISABLE_PLANNED_MAINTENANCE", {});
  }
}
