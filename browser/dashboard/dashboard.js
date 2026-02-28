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
});

// Botones conectar dispositivos
document.querySelectorAll(".connect-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    const deviceName =
      btn.parentElement.querySelector(".device-name").textContent;
    sendMessageToBackground({
      type: "LINK_DEVICE",
      name: deviceName,
      ip: "mock-ip",
    });
    console.log("Conectar a dispositivo");
  });
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

function copyPassword(password) {
  navigator.clipboard.writeText(password);
  alert("Contraseña copiada al portapapeles");
}

function togglePassword(input, btn) {
  if (input.type === "password") {
    input.type = "text";
    btn.textContent = "🙈";
  } else {
    input.type = "password";
    btn.textContent = "👁";
  }
}

const createPasswordRowHTML = (pw) => {
  const breachClass = pw.breached ? "password-breached" : "";
  const breachBadge = pw.breached
    ? `<span class="breach-badge" title="${pw.breaches} brechas encontradas">⚠️ ${pw.breaches}</span>`
    : "";

  return `
    <tr class="${breachClass}">
      <td>${pw.domain}</td>
      <td>${pw.user}</td>
      <td>
        <div class="password-cell">
          <input type="password" value="${pw.password}" readonly>
          <button class="toggle-password">👁</button>
          <button class="copy-password">📋</button>
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

        toggleBtn.addEventListener("click", () =>
          togglePassword(input, toggleBtn),
        );
        copyBtn.addEventListener("click", () => copyPassword(input.value));
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

async function connectToDevice(name) {
  console.log("Conectando a dispositivo:", name);

  try {
    const result = await sendMessageToBackground({
      type: "LINK_DEVICE",
      name,
      ip: "ip-test",
    });

    console.log("resultado conexión", result);
  } catch (err) {
    console.error("Error conectando a dispositivo:", err);
  }
}

const createDeviceRowHTML = (dev) => {
  return `
    <div class="device-item">
      <div>${dev.name}</div>
      <button class="connect-device">Conectar</button>
    </div>
  `;
};

async function loadDevices() {
  try {
    console.log("[DASHBOARD] Cargando dispositivos...");

    const devices = await sendMessageToBackground({
      type: "GET_DEVICES",
    });

    console.log("[DASHBOARD] Dispositivos recibidos:", devices);
    console.log("[DASHBOARD] Tipo de dispositivos:", typeof devices);
    console.log("[DASHBOARD] Es array?", Array.isArray(devices));

    if (devices) {
      const section = document.getElementById("devices-section");
      const container = document.getElementById("devices-list");

      if (!Array.isArray(devices) || devices.length === 0) {
        console.log("[DASHBOARD] No hay dispositivos o no es array");
        section.classList.add("hidden");
        return;
      }

      console.log("[DASHBOARD] Renderizando", devices.length, "dispositivos");
      container.innerHTML = devices
        .map((dev) => createDeviceRowHTML(dev))
        .join("");

      container.querySelectorAll(".device-item").forEach((item) => {
        const btn = item.querySelector(".connect-device");
        const name = item.querySelector("div").textContent;
        btn.addEventListener("click", () => connectToDevice(name));
      });

      section.classList.remove("hidden");
    } else {
      console.log("[DASHBOARD] devices es null o undefined");
    }
  } catch (err) {
    console.error("[DASHBOARD] Error cargando dispositivos:", err);
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
    // const auditResults = await sendMessageToBackground({
    //   type: "AUDIT_PASSWORDS",
    // });
    const auditResults = [
      {
        domain: "www.linkedin.com",
        breaches: 2,
      },
    ];

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
        ? `⚠️ Se encontraron ${totalBreached} contraseña(s) comprometida(s). Las filas en rojo requieren atención.`
        : "✅ ¡Excelente! Todas tus contraseñas están seguras.";

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
    console.log("[VERIFY] ✅ Verificación completada");
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
});
