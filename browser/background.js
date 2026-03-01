// SPDX-FileCopyrightText: 2026 Noa Rodríguez noa.rpache@gmail.com  Pablo Diz pablo.diz.edu@gmail.com  Hugo Freire hugo.freire@udc.es  Eloy Sastre elhoyyy@gmail.com
//
// SPDX-License-Identifier: Apache-2.0

// background.js

var browser = browser || chrome;

async function callApi(endpoint, method = "GET", body = null) {
  const options = {
    method,
    headers: {
      "X-API-Key": CONFIG.API_KEY,
      "Content-Type": "application/json",
    },
  };

  if (body) {
    options.body = JSON.stringify(body);
  }

  const response = await fetch(`${CONFIG.API_URL}${endpoint}`, options);
  if (!response.ok) {
    const errorText = await response.text();
    console.error("API error:", response.status, errorText);
    return {
      success: false,
      message: `Error ${response.status}: ${errorText || "Error desconocido"}`,
    };
  }

  try {
    return await response.json();
  } catch (err) {
    console.error("Error parsing JSON response:", err);
    return { success: true };
  }
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
          console.log(
            "[BG] Sincronizando con peer:",
            message.peer_ip,
            message.peer_port,
          );
          result = await callApi("/synchronise", "POST", {
            peer_ip: message.peer_ip,
            peer_port: message.peer_port,
          });
          console.log("[BG] Resultado sincronización:", result);
          break;
        case "AUDIT_PASSWORDS":
          console.log("[BG] Auditando contraseñas...");
          result = await callApi("/audit", "GET");
          console.log("[BG] Auditoría completada:", result);
          break;
        case "DELETE_PASSWORD":
          console.log("[BG] Eliminando contraseña:", message.domain);
          result = await callApi(`/password/${message.domain}`, "DELETE");
          console.log("[BG] Contraseña eliminada:", result);
          break;
        case "BLE_SEND":
          console.log("[BG] Enviando contraseñas por BLE...");
          result = await callApi("/ble/send", "POST");
          console.log("[BG] BLE send resultado:", result);
          break;
        case "BLE_RECEIVE_START":
          console.log("[BG] Iniciando servidor BLE (recibir)...");
          result = await callApi("/ble/receive", "POST");
          console.log("[BG] BLE receive resultado:", result);
          break;
        case "BLE_RECEIVE_STOP":
          console.log("[BG] Deteniendo servidor BLE...");
          result = await callApi("/ble/stop", "POST");
          console.log("[BG] BLE stop resultado:", result);
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
