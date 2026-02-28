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
  //TODO añadir el endpoint y la modificación de la interfaz, poniendo las filas en rojo
  console.log("Verificar contraseñas");
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
  return `
    <tr>
      <td>${pw.domain}</td>
      <td>${pw.user}</td>
      <td>
        <div class="password-cell">
          <input type="password" value="${pw.password}" readonly>
          <button class="toggle-password">👁</button>
          <button class="copy-password">📋</button>
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

// Cargar al inicio
document.addEventListener("DOMContentLoaded", () => {
  loadPasswords();
});
