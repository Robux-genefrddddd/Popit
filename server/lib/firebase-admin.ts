import { initializeApp, cert, getApps } from "firebase-admin/app";
import { getFirestore, Timestamp } from "firebase-admin/firestore";
import { getAuth } from "firebase-admin/auth";

const serviceAccount = {
  type: "service_account",
  project_id: "keysystem-d0b86-8df89",
  private_key_id: "54352d125eca96439c13f82fa4b79b04cc4026b4",
  private_key:
    "-----BEGIN PRIVATE KEY-----\nMIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDGu7G1nbg/AvMS\nRKF33VGhwJzA4EsqGgWidojXBeEi1IegMSsnkrl3XaN2XqGSUr8RVfSpqh5gKUVp\nj0LwZAOBEh7lolvr/9soTtZDEhjsfcjK0s0yWkt6QRS+kWJPCgPGOBu3kV7bJoxw\n5xhcaKkMmYflnLeM/cpOgnztwbrLxCJc305PIFOu4lzqojPB/avl4F/OHv1fKM83\nqD4oMcUavxfZFcOevCzpTRyAP/3PJVacGCj9yPmGlEAId1wLo2hPclJJh4ZXZ043\n6/fxSIXcEe6YiDXyozaU8ujJ8aEvS0eG9TJd0Wer1fg59036yjXoLWciqnHRQifU\nb7oBrX7hAgMBAAECggEAFOGHzJNj1osSyyqW5KdGen5oegOXIjdVvDpEKoOdojE+\nhuBjrmbGQfp+wGM1CtDS7plfeaw8QNJVTsAUwnlfvOIQiQREMEnT1yphbO6r271j\nqZv4n3/JSnEoItXXxIJC30Lp9qG5m8EzJHHDp4H/sSk4lDGhP5ky9ojTY4/ldp9X\nec03fjc0otSE0l7fmW0KYXh1HuNVXC0DTHcehhEYeN7Y5Ts7fr/IhozJ0KVoYQrQ\nIomlEKbfMWaIJ3zSAKBZ9NzFj9L2Goh2TjS5v7iWZzOtOoCT1FeGveEeu7Xt82sN\notVEQnP2fM5eyXS6FGadNWay0P6DppHWYTRwdw1AgQKBgQD3oZnFFcmt0T11DIpL\nJ1Owi66/IlefF9Doi7VN9LFbBlG343saW+w2x7KCD+RXZkNVQ1aQhIpt2cF6LZqz\ng2Z0uymV5Gsc14NFTxgkPzbQuhvllshciqvEUdHd8EWq284eLLMfxi7myj5zXlU2\nsfSu9BLzK/fL7jii8Xbd84RhKQKBgQDNcwxiW6n3gUD8ulcvTa8ek7ZmxhVII7bL\nxmdD4SG987ylB/b7RhxZh6SNmMLQoDtouPpqqSFnmnfa0mx6OvisTZ74c14RtOJL\nIkO7JGmp1rZMSlNt2z0mXn8TvenDRPPdhBXwsorl+UdheNXIuZpbKJm9EJkL3CQt\nQlZorVzO+QKBgQDH1knZmrOe6fTGuNABxkLrfk4PQQ+k+/tDLzupJYbbBkZ8N7/o\njbYanx2XiGulfIlqDWWWSt/LtqdEifkGVUwhd8kfha5LIEB3dlTtK3Z5CzfoF76p\nr97eF4ldqcEPGUNFZp1HTxAaf6vWPpJWCVaEucNxKlJW6HAcTvC2PQbfwQKBgQCK\niFw+am62bNqET6YASJKfvJyOulyZUzOsPjFdjQ3yhsqaQT+h+YmeOR+VNv+OK61D\nlQ+OIlNbB8Zvr9njpaYOkRxzjV9N8zlvzj/7jbcOBbDQyoFtHxshpzBrAHEC8Zi6\nspkUv193aNpf+Fm3SqexdjQMT4fTfnKKbiPT26osCQKBgQDthnrn3NlYwKTWyVNB\nYUhNLU9YxBKzNpYjzP/+Jtz8qnu0p06oSm7BE2w/ShIMZ5Z/NhFob/h16YDazXtM\neHN8KovntWmnlWAUovlpm1+RyAgyncSzXnZj80TuOzcs11XvL87FnVOcho5NSs3s\nnsj5TT2GsVZxdn3Vr36eedVPvA==\n-----END PRIVATE KEY-----\n",
  client_email:
    "firebase-adminsdk-fbsvc@keysystem-d0b86-8df89.iam.gserviceaccount.com",
  client_id: "109620378360205529977",
  auth_uri: "https://accounts.google.com/o/oauth2/auth",
  token_uri: "https://oauth2.googleapis.com/token",
  auth_provider_x509_cert_url:
    "https://www.googleapis.com/oauth2/v1/certs",
  client_x509_cert_url:
    "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-fbsvc%40keysystem-d0b86-8df89.iam.gserviceaccount.com",
  universe_domain: "googleapis.com",
};

let adminDb: ReturnType<typeof getFirestore> | null = null;
let adminAuth: ReturnType<typeof getAuth> | null = null;
let initialized = false;

export function initializeFirebaseAdmin() {
  if (initialized) return;

  try {
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
