// Mostrar/ocultar contraseña

var browser = browser || chrome;

document.querySelectorAll(".toggle-password").forEach((btn) => {
  btn.addEventListener("click", () => {
    const input = btn.previousElementSibling;
    input.type = input.type === "password" ? "text" : "password";
  });
});

//EVENTOS DE LOS onClick

// Botones sincronizar y refrescar
document.getElementById("sync-btn").addEventListener("click", () => {
  loadDevices();
});

document.getElementById("refresh-btn").addEventListener("click", () => {
  loadDevices();
  loadPasswords();
});

// Botón sincronización manual
document.getElementById("manual-sync-btn").addEventListener("click", () => {
  const ip = document.getElementById("manual-ip").value.trim();
  const port = parseInt(document.getElementById("manual-port").value) || 5000;
  if (!ip) {
    alert("Introduce la IP del peer");
    return;
  }
  syncWithPeer(ip, port, "Manual");
});

// Botón verificar contraseñas
document.getElementById("verify-btn").addEventListener("click", () => {
  console.log("Verificando contraseñas contra HIBP...");
  verifyPasswords();
});

//------------------------------------------------------

// Envía mensaje al background y recibe respuesta
function sendMessageToBackground(message) {
  console.log("[DASHBOARD] Enviando mensaje al background:", message);
  return new Promise((resolve, reject) => {
    try {
      browser.runtime.sendMessage(message, (response) => {
        console.log("[DASHBOARD] Respuesta recibida del background:", response);
        if (browser.runtime.lastError) {
          console.error(
            "[DASHBOARD] Error en runtime:",
            browser.runtime.lastError,
          );
          reject(browser.runtime.lastError);
        } else {
          console.log("[DASHBOARD] Resolviendo con:", response);
          resolve(response);
        }
      });
    } catch (err) {
      console.error("[DASHBOARD] Error enviando mensaje:", err);
      reject(err);
    }
  });
}

//------------------------------------------------------

function togglePassword(input, btn) {
  if (input.type === "password") {
    input.type = "text";
    btn.innerHTML = SVG_ICONS.eyeClosed;
    btn.classList.add("active");
  } else {
    input.type = "password";
    btn.innerHTML = SVG_ICONS.eyeOpen;
    btn.classList.remove("active");
  }
}

function copyPassword(password, btn) {
  navigator.clipboard.writeText(password);
  // Visual feedback instead of alert
  const original = btn.innerHTML;
  btn.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#2ecc71" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`;
  btn.style.color = "#2ecc71";
  setTimeout(() => {
    btn.innerHTML = original;
    btn.style.color = "";
  }, 1500);
}

async function deletePassword(domain) {
  console.log("[DELETE] Intentando eliminar contraseña para:", domain);

  const confirmed = confirm(
    `¿Estás seguro de que deseas eliminar la contraseña para ${domain}?\n\nEsta acción no se puede deshacer.`,
  );

  if (!confirmed) {
    console.log("[DELETE] Usuario canceló la eliminación");
    return;
  }

  try {
    console.log("[DELETE] Enviando solicitud de eliminación al background...");
    const result = await sendMessageToBackground({
      type: "DELETE_PASSWORD",
      domain: domain,
    });

    console.log("[DELETE] Resultado:", result);

    if (result && result.success) {
      console.log("[DELETE] Contraseña eliminada exitosamente");
      alert(`Contraseña de ${domain} eliminada exitosamente.`);

      // Recargar la tabla de contraseñas
      loadPasswords();
    } else {
      console.error("[DELETE] Error al eliminar:", result?.message);
      alert(`❌ Error al eliminar: ${result?.message || "Error desconocido"}`);
    }
  } catch (err) {
    console.error("[DELETE] Error eliminando contraseña:", err);
    alert("❌ Error al eliminar la contraseña. Intenta de nuevo.");
  }
}

const SVG_ICONS = {
  eyeOpen: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`,
  eyeClosed: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`,
  copy: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`,
  trash: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>`,
  shield: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`,
};

const createPasswordRowHTML = (pw) => {
  const breachClass = pw.breached ? "password-breached" : "";
  const breachBadge = pw.breached
    ? `<span class="breach-badge" title="${pw.breaches} brechas encontradas">${SVG_ICONS.shield} ${pw.breaches}</span>`
    : "";

  return `
    <tr class="${breachClass}">
      <td>${pw.domain}</td>
      <td>${pw.user}</td>
      <td>
        <div class="password-cell">
          <input type="password" value="${pw.password}" readonly>
          <button class="toggle-password btn-icon" title="Mostrar/ocultar">${SVG_ICONS.eyeOpen}</button>
          <button class="copy-password btn-icon" title="Copiar">${SVG_ICONS.copy}</button>
          <button class="delete-password btn-icon" title="Eliminar">${SVG_ICONS.trash}</button>
          ${breachBadge}
        </div>
      </td>
    </tr>
  `;
};

// Función para rellenar la tabla de contraseñas
async function loadPasswords() {
  try {
    console.log("Cargando contraseñas...");

    const passwords = await sendMessageToBackground({
      type: "GET_ALL_PASSWORDS",
    });

    console.log("Contraseñas recibidas:", passwords);

    const tbody = document.getElementById("password-table");

    if (passwords && Array.isArray(passwords) && passwords.length > 0) {
      tbody.innerHTML = passwords
        .map((pw) => createPasswordRowHTML(pw))
        .join("");

      // Agregar event listeners a los botones
      tbody.querySelectorAll(".password-cell").forEach((cell) => {
        const input = cell.querySelector("input");
        const toggleBtn = cell.querySelector(".toggle-password");
        const copyBtn = cell.querySelector(".copy-password");
        const deleteBtn = cell.querySelector(".delete-password");
        const domain = cell
          .closest("tr")
          .querySelector("td:first-child").textContent;

        toggleBtn.addEventListener("click", () =>
          togglePassword(input, toggleBtn),
        );
        copyBtn.addEventListener("click", () => copyPassword(input.value, copyBtn));
        deleteBtn.addEventListener("click", () => deletePassword(domain));
      });
    } else {
      // Mostrar mensaje si no hay contraseñas
      tbody.innerHTML = `
        <tr>
          <td colspan="3" style="text-align: center; padding: 20px; color: #999;">
            No hay contraseñas guardadas aún
          </td>
        </tr>
      `;
    }
  } catch (err) {
    console.error("Error cargando contraseñas:", err);
    const tbody = document.getElementById("password-table");
    tbody.innerHTML = `
      <tr>
        <td colspan="3" style="text-align: center; padding: 20px; color: #d32f2f;">
          Error al cargar las contraseñas. Intenta recargar la página.
        </td>
      </tr>
    `;
  }
}

async function syncWithPeer(ip, port, deviceId) {
  console.log("[SYNC] Sincronizando con:", deviceId, ip, port);

  const btn = document.querySelector(`[data-peer-id="${deviceId}"]`);
  if (btn) {
    btn.disabled = true;
    btn.textContent = "⏳ Sincronizando...";
  }

  try {
    const result = await sendMessageToBackground({
      type: "LINK_DEVICE",
      peer_ip: ip,
      peer_port: port,
    });

    console.log("[SYNC] Resultado:", result);

    if (result && result.success) {
      alert(`✅ Sincronización exitosa con ${deviceId}\n\nVault v${result.vault_version} — ${result.vault_entries_count} entradas`);
      loadPasswords();
      loadDevices();
    } else {
      alert(`❌ Error sincronizando con ${deviceId}:\n${result?.error || result?.message || "Error desconocido"}`);
    }
  } catch (err) {
    console.error("[SYNC] Error:", err);
    alert(`❌ Error de conexión con ${deviceId}`);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = "Sincronizar";
    }
  }
}

function formatTimeAgo(seconds) {
  if (seconds < 60) return `hace ${seconds}s`;
  if (seconds < 3600) return `hace ${Math.floor(seconds / 60)}m`;
  return `hace ${Math.floor(seconds / 3600)}h`;
}

const createDeviceRowHTML = (peer) => {
  const timeAgo = formatTimeAgo(peer.last_seen_ago_seconds);
  const isRecent = peer.last_seen_ago_seconds < 60;
  const statusDot = isRecent ? "🟢" : "🟡";

  return `
    <div class="device-card" data-ip="${peer.ip}" data-port="${peer.port}" data-peer-id="${peer.device_id}">
      <div class="device-info">
        <div class="device-name">${statusDot} ${peer.device_id}</div>
        <div class="device-details">
          <span class="device-ip">${peer.ip}:${peer.port}</span>
          <span class="device-seen">${timeAgo}</span>
        </div>
      </div>
      <span class="device-select-hint">Click para seleccionar</span>
    </div>
  `;
};

async function loadDevices() {
  try {
    console.log("[DASHBOARD] Cargando dispositivos...");

    const syncBtn = document.getElementById("sync-btn");
    syncBtn.disabled = true;
    syncBtn.textContent = "⏳ Buscando...";

    const data = await sendMessageToBackground({
      type: "GET_DEVICES",
    });

    console.log("[DASHBOARD] Datos sincronización:", data);

    // Mostrar info de mi dispositivo
    const myInfo = document.getElementById("my-device-info");
    if (data && data.device_id) {
      myInfo.innerHTML = `
        <span class="my-device-badge">📱 ${data.device_id}</span>
        <span class="vault-badge">v${data.vault_version}</span>
      `;
    }

    const container = document.getElementById("devices-list");

    if (data && data.active_peers && data.active_peers.length > 0) {
      container.innerHTML = data.active_peers
        .map((peer) => createDeviceRowHTML(peer))
        .join("");

      // Click en tarjeta → autocompletar IP/puerto en formulario
      container.querySelectorAll(".device-card").forEach((card) => {
        card.addEventListener("click", () => {
          // Deseleccionar todas las tarjetas
          container.querySelectorAll(".device-card").forEach(c => c.classList.remove("selected"));
          // Seleccionar esta
          card.classList.add("selected");

          // Auto-rellenar formulario
          const ipInput = document.getElementById("manual-ip");
          const portInput = document.getElementById("manual-port");
          ipInput.value = card.dataset.ip;
          portInput.value = card.dataset.port;

          // Efecto visual de autocompletado
          ipInput.classList.add("autofilled");
          portInput.classList.add("autofilled");
          setTimeout(() => {
            ipInput.classList.remove("autofilled");
            portInput.classList.remove("autofilled");
          }, 2000);
        });
      });
    } else {
      container.innerHTML = `
        <div class="no-devices">
          No se encontraron peers en la red.<br>
          <small>Asegúrate de que otros dispositivos estén ejecutando CryptMyPassword.</small>
        </div>
      `;
    }

    syncBtn.disabled = false;
    syncBtn.textContent = "🔍 Buscar peers";
  } catch (err) {
    console.error("[DASHBOARD] Error cargando dispositivos:", err);
    document.getElementById("devices-list").innerHTML = `
      <div class="no-devices error">❌ Error al buscar dispositivos</div>
    `;
    const syncBtn = document.getElementById("sync-btn");
    syncBtn.disabled = false;
    syncBtn.textContent = "🔍 Buscar peers";
  }
}

// Función para verificar contraseñas contra HIBP
async function verifyPasswords() {
  try {
    console.log("[VERIFY] Iniciando verificación de contraseñas");
    const verifyBtn = document.getElementById("verify-btn");
    verifyBtn.disabled = true;
    verifyBtn.textContent = "Verificando...";

    console.log("[VERIFY] Enviando solicitud AUDIT_PASSWORDS al background...");
    const auditResults = await sendMessageToBackground({
      type: "AUDIT_PASSWORDS",
    });

    console.log("[VERIFY] Resultados de auditoría recibidos:", auditResults);
    const breachedDomains = {};
    if (Array.isArray(auditResults)) {
      auditResults.forEach((result) => {
        breachedDomains[result.domain] = result.breaches;
      });
      console.log("[VERIFY] Mapa creado:", breachedDomains);
    } else {
      console.warn("[VERIFY] auditResults no es un array:", auditResults);
    }

    // Actualizar las filas de la tabla
    console.log("[VERIFY] Actualizando tabla...");
    const tbody = document.getElementById("password-table");

    let rowsUpdated = 0;
    tbody.querySelectorAll("tr").forEach((row) => {
      const domainCell = row.querySelector("td:first-child");
      if (!domainCell) return;

      const domain = domainCell.textContent;
      const passwordCell = row.querySelector(".password-cell");

      if (breachedDomains[domain]) {
        // Marcar como comprometida
        rowsUpdated++;

        if (!passwordCell.querySelector(".breach-badge")) {
          const badge = document.createElement("span");
          badge.className = "breach-badge";
          badge.title = `${breachedDomains[domain]} brechas encontradas`;
          badge.textContent = `⚠️ ${breachedDomains[domain]}`;
          passwordCell.appendChild(badge);
          console.log("[VERIFY] Badge agregado para:", domain);
        }
      } else {
        // Remover marcas de compromiso si las hubiera
        row.classList.remove("password-breached");
        const existingBadge = passwordCell.querySelector(".breach-badge");
        if (existingBadge) {
          existingBadge.remove();
          console.log("[VERIFY] Badge removido para:", domain);
        }
      }
    });
    console.log("[VERIFY] Filas actualizadas:", rowsUpdated);

    // Feedback al usuario
    const totalBreached = Object.keys(breachedDomains).length;
    console.log("[VERIFY] Total comprometidas:", totalBreached);

    const mensaje =
      totalBreached > 0
        ? `Se encontraron ${totalBreached} contraseña(s) comprometida(s). Las filas en rojo requieren atención.`
        : "Todas tus contraseñas están seguras.";

    console.log("[VERIFY] Mostrando alerta:", mensaje);
    alert(mensaje);
    console.log("[VERIFY] Alerta cerrada");

    console.log("[VERIFY] Reactivando botón...");
    verifyBtn.disabled = false;
    console.log("[VERIFY] Botón habilitado");

    verifyBtn.classList.remove("verifying");
    console.log("[VERIFY] Clase 'verifying' removida");

    verifyBtn.textContent = "Verificar contraseñas";
    console.log("[VERIFY] Texto del botón restaurado");
    console.log("[VERIFY] Verificación completada");
  } catch (err) {
    console.error("[VERIFY] ❌ Error verificando contraseñas:", err);
    console.error("[VERIFY] Stack:", err.stack);

    const mensajeError =
      "Error al verificar contraseñas. Intenta de nuevo más tarde.";
    console.log("[VERIFY] Mostrando alerta de error:", mensajeError);
    alert(mensajeError);
    console.log("[VERIFY] Alerta de error cerrada");

    console.log("[VERIFY] Reactivando botón después de error...");
    const verifyBtn = document.getElementById("verify-btn");
    verifyBtn.disabled = false;
    console.log("[VERIFY] Botón habilitado");

    verifyBtn.classList.remove("verifying");
    console.log("[VERIFY] Clase 'verifying' removida");

    verifyBtn.textContent = "Verificar contraseñas";
    console.log("[VERIFY] Texto del botón restaurado");
    console.log("[VERIFY] ❌ Verificación finalizada con error");
  }
}

// Cargar al inicio
document.addEventListener("DOMContentLoaded", () => {
  loadPasswords();
  loadDevices();
});
