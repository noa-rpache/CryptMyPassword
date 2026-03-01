// browser/config.js

const CONFIG = {
  API_URL: "http://127.0.0.1:8000",

  get API_KEY() {
    return (typeof window !== "undefined" && window.ENV?.API_KEY) || "my_secret_api_key";
  },

  REQUEST_TIMEOUT: 5000,

  DEBUG: true,
};

// Exportar para Node.js (si es necesario)
if (typeof module !== "undefined" && module.exports) {
  module.exports = CONFIG;
}
