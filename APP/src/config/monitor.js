// src/config/monitor.js
const client = require("prom-client");

// const collectDefault = client.collectDefaultMetrics;
// collectDefault();

const authSuccess = new client.Counter({
  name: "auth_success_total",
  help: "Количество успешных авторизаций",
});
const authFailure = new client.Counter({
  name: "auth_failure_total",
  help: "Количество неудачных попыток авторизации",
});
const refreshCount = new client.Counter({
  name: "auth_refresh_total",
  help: "Количество refresh токенов использованных",
});
const suspiciousCount = new client.Counter({
  name: "auth_suspicious_total",
  help: "Количество подозрительных событий (повтор refresh или мн. неудачных входов)",
});
const activeRefreshTokens = new client.Gauge({
  name: "auth_active_refresh_tokens",
  help: "Текущее число действующих refresh токенов (оценочно)",
});

module.exports = {
  client,
  authSuccess,
  authFailure,
  refreshCount,
  suspiciousCount,
  activeRefreshTokens,
};
