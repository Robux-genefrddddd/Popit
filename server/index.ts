import "dotenv/config";
import express from "express";
import cors from "cors";
import { initializeFirebaseAdmin } from "./lib/firebase-admin";
import { handleDemo } from "./routes/demo";
import { handleGetIP, handleCheckVPN } from "./routes/ip-detection";
import { handleActivateLicense } from "./routes/license";
import { handleDailyReset } from "./routes/daily-reset";
import { handleAIChat } from "./routes/ai";
import {
  handleVerifyAdmin,
  handleGetAllUsers,
  handlePromoteUser,
  handleDemoteUser,
  handleBanUser,
  handleUnbanUser,
  handleResetMessages,
  handleDeleteUser,
  handleUpdateUserPlan,
  handleGetBannedUsers,
  handleGetLicenses,
  handleCreateLicense,
  handleInvalidateLicense,
  handleDeleteLicense,
  handleGetAIConfig as handleGetAIConfigAdmin,
  handleUpdateAIConfig as handleUpdateAIConfigAdmin,
  handleGetSystemStats,
  handlePurgeLicenses,
  handleGetAdminLogs,
  handleClearOldLogs,
  handleGetMaintenanceStatus,
  handleEnableGlobalMaintenance,
  handleDisableGlobalMaintenance,
  handleEnablePartialMaintenance,
  handleDisablePartialMaintenance,
  handleEnableIAMaintenance,
  handleDisableIAMaintenance,
  handleEnableLicenseMaintenance,
  handleDisableLicenseMaintenance,
  handleEnablePlannedMaintenance,
  handleDisablePlannedMaintenance,
} from "./routes/admin";
import {
  handleCheckIPBan,
  handleCheckIPLimit,
  handleRecordUserIP,
  handleUpdateUserIPLogin,
} from "./routes/ip-management";
import { handleGetAIConfig as handleGetAIConfigSettings } from "./routes/settings";
import {
  validateContentType,
  validateRequestSize,
  validateInput,
  serverRateLimit,
  authMiddleware,
} from "./middleware/security";

export function createServer() {
  // Initialize Firebase Admin SDK
  initializeFirebaseAdmin();

  const app = express();

  // Trust proxy (for rate limiting to work correctly)
  app.set("trust proxy", 1);

  // Middleware - Order matters!
  // 1. CORS first (allow trusted origins)
  const corsOrigins = (process.env.CORS_ORIGINS || "")
    .split(",")
    .filter(Boolean);
  app.use(
    cors({
      origin: corsOrigins.length > 0 ? corsOrigins : true,
      credentials: true,
      methods: ["GET", "POST", "PUT", "DELETE"],
      allowedHeaders: ["Content-Type", "Authorization"],
    }),
  );

  // 2. Security headers
  app.use((req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("X-XSS-Protection", "1; mode=block");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    res.setHeader("X-Content-Security-Policy", "default-src 'self'");
    res.setHeader(
      "Strict-Transport-Security",
      "max-age=31536000; includeSubDomains",
    );
    next();
  });

  // 3. Request size validation
  app.use(validateRequestSize);

  // 4. Parse JSON
  app.use(express.json({ limit: "10mb" }));
  app.use(express.urlencoded({ extended: true, limit: "10mb" }));

  // 5. Content-Type validation
  app.use(validateContentType);

  // 6. Input validation (check for suspicious patterns)
  app.use(validateInput);

  // 7. Authentication middleware (extract token from request)
  app.use(authMiddleware);

  // 8. Global rate limiting (100 requests per minute per IP)
  app.use(serverRateLimit(60000, 100));

  // Create API router to handle all API routes
  const apiRouter = express.Router();

  // Example API routes
  apiRouter.get("/ping", (_req, res) => {
    const ping = process.env.PING_MESSAGE ?? "ping";
    res.json({ message: ping });
  });

  apiRouter.get("/demo", handleDemo);

  // IP detection routes (public, with rate limiting)
  apiRouter.get("/get-ip", serverRateLimit(60000, 30), handleGetIP);
  apiRouter.post("/check-vpn", serverRateLimit(60000, 10), handleCheckVPN);

  // IP management routes
  apiRouter.post("/check-ip-ban", handleCheckIPBan);
  apiRouter.post("/check-ip-limit", handleCheckIPLimit);
  apiRouter.post("/record-user-ip", handleRecordUserIP);
  apiRouter.post("/update-user-ip-login", handleUpdateUserIPLogin);

  // License activation route (requires auth, strict rate limit)
  apiRouter.post(
    "/activate-license",
    serverRateLimit(60000, 5),
    handleActivateLicense,
  );

  // Daily reset route (requires auth, strict rate limit)
  apiRouter.post("/daily-reset", serverRateLimit(60000, 5), handleDailyReset);

  // AI chat route (requires auth, very strict rate limit - 10 requests per minute per user)
  apiRouter.post("/ai/chat", serverRateLimit(60000, 10), handleAIChat);
  apiRouter.get("/ai/config", handleGetAIConfigSettings);

  // Admin routes (require authentication + stricter rate limiting)
  const adminRateLimit = serverRateLimit(60000, 10); // 10 requests per minute per user

  // User management
  apiRouter.get("/admin/users", adminRateLimit, handleGetAllUsers);
  apiRouter.post("/admin/promote-user", adminRateLimit, handlePromoteUser);
  apiRouter.post("/admin/demote-user", adminRateLimit, handleDemoteUser);
  apiRouter.post("/admin/ban-user", adminRateLimit, handleBanUser);
  apiRouter.post("/admin/unban-user", adminRateLimit, handleUnbanUser);
  apiRouter.post("/admin/reset-messages", adminRateLimit, handleResetMessages);
  apiRouter.post("/admin/delete-user", adminRateLimit, handleDeleteUser);
  apiRouter.post(
    "/admin/update-user-plan",
    adminRateLimit,
    handleUpdateUserPlan,
  );
  apiRouter.get("/admin/banned-users", adminRateLimit, handleGetBannedUsers);

  // License management
  apiRouter.get("/admin/licenses", adminRateLimit, handleGetLicenses);
  apiRouter.post("/admin/create-license", adminRateLimit, handleCreateLicense);
  apiRouter.post(
    "/admin/invalidate-license",
    adminRateLimit,
    handleInvalidateLicense,
  );
  apiRouter.post("/admin/delete-license", adminRateLimit, handleDeleteLicense);
  apiRouter.post("/admin/purge-licenses", adminRateLimit, handlePurgeLicenses);

  // AI configuration (admin only)
  apiRouter.get("/admin/ai-config", adminRateLimit, handleGetAIConfigAdmin);
  apiRouter.put("/admin/ai-config", adminRateLimit, handleUpdateAIConfigAdmin);

  // System stats
  apiRouter.get("/admin/system-stats", adminRateLimit, handleGetSystemStats);

  // Admin logs
  apiRouter.get("/admin/logs", adminRateLimit, handleGetAdminLogs);
  apiRouter.post("/admin/clear-logs", adminRateLimit, handleClearOldLogs);

  // Verification
  apiRouter.post("/admin/verify", adminRateLimit, handleVerifyAdmin);

  // Maintenance management
  apiRouter.get("/admin/maintenance-status", handleGetMaintenanceStatus);
  apiRouter.post(
    "/admin/enable-global-maintenance",
    adminRateLimit,
    handleEnableGlobalMaintenance,
  );
  apiRouter.post(
    "/admin/disable-global-maintenance",
    adminRateLimit,
    handleDisableGlobalMaintenance,
  );
  apiRouter.post(
    "/admin/enable-partial-maintenance",
    adminRateLimit,
    handleEnablePartialMaintenance,
  );
  apiRouter.post(
    "/admin/disable-partial-maintenance",
    adminRateLimit,
    handleDisablePartialMaintenance,
  );
  apiRouter.post(
    "/admin/enable-ia-maintenance",
    adminRateLimit,
    handleEnableIAMaintenance,
  );
  apiRouter.post(
    "/admin/disable-ia-maintenance",
    adminRateLimit,
    handleDisableIAMaintenance,
  );
  apiRouter.post(
    "/admin/enable-license-maintenance",
    adminRateLimit,
    handleEnableLicenseMaintenance,
  );
  apiRouter.post(
    "/admin/disable-license-maintenance",
    adminRateLimit,
    handleDisableLicenseMaintenance,
  );
  apiRouter.post(
    "/admin/enable-planned-maintenance",
    adminRateLimit,
    handleEnablePlannedMaintenance,
  );
  apiRouter.post(
    "/admin/disable-planned-maintenance",
    adminRateLimit,
    handleDisablePlannedMaintenance,
  );

  // Mount API router
  app.use("/api", apiRouter);

  // 404 handler for API routes only
  app.use("/api", (_req, res) => {
    res.status(404).json({ error: "Not found" });
  });

  // Error handler
  app.use(
    (
      err: unknown,
      _req: express.Request,
      res: express.Response,
      _next: express.NextFunction,
    ) => {
      console.error("Unhandled error:", err);
      res.status(500).json({ error: "Internal server error" });
    },
  );

  return app;
}
