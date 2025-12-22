const path = require("path");
require("dotenv").config({
  path: path.resolve(__dirname, "../.env"),
});

const express = require("express");
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const cors = require("cors");

const authRoutes = require("./routes/authRoutes");
const { verifyAccessToken } = require("./middlewares/authMiddleware");
const logger = require("./config/logger");
const { client } = require("./config/monitor");

const app = express();

/* =======================
   Global middlewares
======================= */
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

app.use(
  cors({
    origin: true,
    credentials: true,
  })
);

/* =======================
   Routes
======================= */
app.use("/api/auth", authRoutes);

app.get("/api/private", verifyAccessToken, (req, res) => {
  logger.info("Private route accessed", {
    userId: req.user.id,
    ip: req.ip,
  });

  res.json({
    message: "Access granted",
    user: req.user,
  });
});

app.get("/metrics", async (req, res) => {
  res.set("Content-Type", client.register.contentType);
  res.end(await client.register.metrics());
});

app.get("/health", (req, res) => {
  res.json({ status: "OK" });
});

/* =======================
   MongoDB connection
======================= */
const PORT = process.env.PORT || 4000;

// Функция для подключения к MongoDB
let isConnected = false;
const connectDB = async () => {
  if (isConnected) {
    console.log("Using existing MongoDB connection");
    return;
  }

  try {
    await mongoose.connect(process.env.MONGO_URI);
    isConnected = true;
    logger.info("MongoDB connected");
    console.log("✅ MongoDB connected");
  } catch (err) {
    logger.error("MongoDB connection failed", {
      error: err.message,
    });
    console.error("❌ MongoDB connection error:", err.message);
    throw err;
  }
};

// Функция для отключения от MongoDB
const disconnectDB = async () => {
  if (mongoose.connection.readyState !== 0) {
    await mongoose.disconnect();
    isConnected = false;
    console.log("MongoDB disconnected");
  }
};

// Запускаем сервер только если это основной модуль
if (require.main === module) {
  (async () => {
    try {
      await connectDB();
      
      app.listen(PORT, () => {
        logger.info(`Server started on port ${PORT}`);
        console.log(`🚀 Server started on port ${PORT}`);
      });
      
      // Обработка graceful shutdown
      process.on('SIGTERM', async () => {
        console.log('SIGTERM received. Closing server...');
        await disconnectDB();
        process.exit(0);
      });
      
    } catch (err) {
      console.error("Failed to start server:", err.message);
      process.exit(1);
    }
  })();
}

module.exports = { app, connectDB, disconnectDB, mongoose };