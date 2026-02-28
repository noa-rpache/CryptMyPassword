// content.js

// Helpers para UI
const setNativeValue = (element, value) => {
  const valueSetter = Object.getOwnPropertyDescriptor(element, "value")?.set;
  const prototype = Object.getPrototypeOf(element);
  const prototypeValueSetter = Object.getOwnPropertyDescriptor(
    prototype,
    "value",
  )?.set;

  if (prototypeValueSetter && valueSetter !== prototypeValueSetter) {
    prototypeValueSetter.call(element, value);
  } else if (valueSetter) {
    valueSetter.call(element, value);
  } else {
    element.value = value;
  }

  element.dispatchEvent(new Event("input", { bubbles: true }));
  element.dispatchEvent(new Event("change", { bubbles: true }));
};

// Envía mensaje al background y recibe respuesta
function sendMessageToBackground(message) {
  return new Promise((resolve) => {
    browser.runtime.sendMessage(message, resolve);
  });
}

//Función para encontrar el campo del usuario
function detectUserFieldFromPassword(passwordField) {
  const form = passwordField.closest("form");
  if (!form) return null;

  return (
    form.querySelector('input[autocomplete="username"]') ||
    form.querySelector('input[type="email"]') ||
    form.querySelector(
      'input[name*="user" i], input[name*="login" i], input[name*="email" i]',
    )
  );
}

// UI cuando ya hay contraseña
function showExistingPasswordNotice(field, existing, domain) {
  if (document.getElementById("secure-pass-notice")) return;

  console.log("primer if check");

  const notice = document.createElement("div");
  notice.id = "secure-pass-notice";
  notice.innerHTML = `
    <div style="font-weight:600; margin-bottom:8px;">
      Ya tienes una contraseña guardada para este dominio
    </div>
    <button id="use-saved-pass">Usar contraseña guardada</button>
  `;

  document.body.appendChild(notice);
  console.log("se ha apendeado el elemento");

  document.getElementById("use-saved-pass").addEventListener("click", () => {
    console.log("clieck check");
    setNativeValue(field, existing.password);
    notice.innerHTML = "✅ Contraseña aplicada";
    setTimeout(() => notice.remove(), 1500);
  });
}

// UI para generar nueva contraseña
function showGenerateNotice(field, domain) {
  if (document.getElementById("secure-pass-notice")) return;

  const notice = document.createElement("div");
  notice.id = "secure-pass-notice";
  notice.innerHTML = `
    <div style="font-weight:600; margin-bottom:8px;">
      Parece que estás añadiendo una contraseña
    </div>
    <button id="generate-secure-pass">Generar contraseña segura</button>
  `;
  document.body.appendChild(notice);

  document
    .getElementById("generate-secure-pass")
    .addEventListener("click", async () => {
      const newPassObj = await sendMessageToBackground({
        type: "GENERATE_PASSWORD",
      });
      const newPass = newPassObj?.password || "fallback1234";

      setNativeValue(field, newPass);

      // Intentar detectar usuario/email
      const userField = document.querySelector(
        'input[type="email"], input[name*="user"], input[name*="login"]',
      );
      const user = userField ? userField.value : "unknown";

      await sendMessageToBackground({
        type: "SAVE_PASSWORD",
        domain,
        user,
        password: newPass,
      });

      notice.innerHTML = "Contraseña generada y guardada";
      setTimeout(() => notice.remove(), 1500);
    });
}

// MAIN LOOP
(async () => {
  const passwordField = document.querySelector('input[type="password"]');
  if (!passwordField) return;

  console.log("hay campo de contraseña");
  const domain = window.location.hostname;

  const existing = await sendMessageToBackground({
    type: "GET_PASSWORD",
    domain,
  });
  console.log("se ha enviado el mensaje");

  if (existing && existing.password) {
    console.log("Hay contraseña del sitio");
    showExistingPasswordNotice(passwordField, existing, domain);
  } else {
    console.log("No hay contraseña del sitio");
    showGenerateNotice(passwordField, domain);
  }

  const form = passwordField.closest("form");
  if (form) {
    form.addEventListener("submit", () => {
      const finalPassword = passwordField.value;
      const userField = detectUserFieldFromPassword(passwordField);
      const user = userField ? userField.value : null;

      browser.runtime.sendMessage({
        type: "SAVE_PASSWORD",
        domain,
        user,
        password: finalPassword,
      });
    });
  }
})();
