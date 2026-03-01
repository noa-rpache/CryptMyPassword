// content.js

let generatedPasswordFromAPI = null;

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

  const notice = document.createElement("div");
  notice.id = "secure-pass-notice";
  notice.innerHTML = `
    <div style="font-weight:600; margin-bottom:8px;">
      Ya tienes una contraseña guardada para este dominio
    </div>
    <button id="use-saved-pass">Usar contraseña guardada</button>
  `;

  document.body.appendChild(notice);
  document.getElementById("use-saved-pass").addEventListener("click", () => {
    setNativeValue(field, existing.password);
    notice.innerHTML = "Contraseña aplicada";
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
      const button = document.getElementById("generate-secure-pass");

      if (button.disabled) return;

      button.disabled = true;
      button.textContent = "Generando...";
      button.style.backgroundColor = "#d1d5db"; // gris claro
      button.style.color = "#6b7280"; // texto gris oscuro
      button.style.border = "1px solid #9ca3af";
      button.style.cursor = "not-allowed";

      try {
        const newPassObj = await sendMessageToBackground({
          type: "GENERATE_PASSWORD",
        });

        const newPass = newPassObj?.password;

        if (!newPass) {
          throw new Error("No se pudo generar la contraseña");
        }

        generatedPasswordFromAPI = newPass;

        setNativeValue(field, newPass);

        notice.innerHTML = "Contraseña generada.";
        setTimeout(() => notice.remove(), 2000);
      } catch (error) {
        console.error("Error generando contraseña:", error);

        // Restaurar botón si falla
        button.disabled = false;
        button.textContent = originalText;
        button.style.opacity = "1";
        button.style.cursor = "pointer";
      }
    });
}

// MAIN LOOP
(async () => {
  const passwordField = document.querySelector('input[type="password"]');
  if (!passwordField) return;

  let domain = window.location.hostname;

  if (!domain || domain.trim() === "") {
    domain = "local";
  }

  console.log("domain:", domain);

  const existing = await sendMessageToBackground({
    type: "GET_PASSWORD",
    domain,
  });

  if (existing && existing.password) {
    showExistingPasswordNotice(passwordField, existing, domain);
  } else {
    showGenerateNotice(passwordField, domain);
  }

  const form = passwordField.closest("form");
  if (form) {
    form.addEventListener("submit", async () => {
      const finalPassword = generatedPasswordFromAPI || passwordField.value;
      const userField = detectUserFieldFromPassword(passwordField);
      const user = userField ? userField.value : null;

      await sendMessageToBackground({
        type: "SAVE_PASSWORD",
        domain,
        user,
        password: finalPassword,
      });

      console.log("Contraseña guardada.");
    });
  }
})();
