// background.js

var browser = browser || chrome;

const api = "http://127.0.0.1:8000";

async function callApi(endpoint, method = "GET", body = null) {
  console.log("endpoint", endpoint);
  console.log("method", method);
  const options = { method };
  if (body) {
    options.headers = { "Content-Type": "application/json" };
    options.body = JSON.stringify(body);
  }

  const response = await fetch(`${api}${endpoint}`, options);
  if (!response.ok) {
    console.error("API error:", response.status, await response.text());
    return null;
  }
  return await response.json();
}

// Escucha mensajes del content script
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    try {
      let result = null;
      console.log("[BG] Mensaje recibido:", message);
      switch (message.type) {
        case "GENERATE_PASSWORD":
          console.log("[BG] Generando contraseña...");
          result = await callApi("/password", "POST");
          console.log("[BG] Contraseña generada:", result);
          break;
        case "GET_PASSWORD":
          console.log("[BG] Obteniendo contraseña para:", message.domain);
          result = await callApi(`/password/${message.domain}`, "GET");
          console.log("[BG] Contraseña obtenida:", result);
          break;
        case "SAVE_PASSWORD":
          console.log("[BG] Guardando contraseña para:", message.domain);
          result = await callApi("/password/save", "POST", {
            domain: message.domain,
            user: message.user,
            password: message.password,
          });
          console.log("[BG] Contraseña guardada:", result);
          break;
        case "GET_ALL_PASSWORDS":
          console.log("[BG] Obteniendo todas las contraseñas...");
          result = await callApi("/password", "GET");
          console.log("[BG] Todas las contraseñas:", result);
          break;
        case "GET_DEVICES":
          console.log("[BG] Obteniendo dispositivos...");
          result = await callApi("/synchronise", "GET");
          console.log("[BG] Dispositivos obtenidos:", result);
          break;
        case "LINK_DEVICE":
          console.log("[BG] Enlazando dispositivo:", message.name);
          result = await callApi("/synchronise", "POST", {
            name: message.name,
            ip: message.ip,
          });
          console.log("[BG] Dispositivo enlazado:", result);
          break;
        case "AUDIT_PASSWORDS":
          console.log("[BG] Auditando contraseñas...");
          result = await callApi("/password/audit", "GET");
          console.log("[BG] Auditoría completada:", result);
          break;
        default:
          console.warn("[BG] Tipo de mensaje desconocido:", message.type);
      }
      console.log("[BG] Enviando respuesta:", result);
      sendResponse(result);
    } catch (err) {
      console.error("[BG] Error en background:", err);
      sendResponse(null);
    }
  })();

  return true;
});

browser.action.onClicked.addListener(() => {
  browser.tabs.create({
    url: browser.runtime.getURL("dashboard/dashboard.html"),
  });
});
