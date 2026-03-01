// SPDX-FileCopyrightText: 2026 Noa Rodríguez noa.rpache@gmail.com  Pablo Diz pablo.diz.edu@gmail.com  Hugo Freire hugo.freire@udc.es  Eloy Sastre elhoyyy@gmail.com
//
// SPDX-License-Identifier: Apache-2.0

async function loadEnv() {
  try {
    const response = await fetch(chrome.runtime.getURL(".env"));
    const text = await response.text();

    const lines = text.split("\n");
    const env = {};

    lines.forEach((line) => {
      // Ignorar comentarios y líneas vacías
      if (line.trim() === "" || line.startsWith("#")) {
        return;
      }

      const [key, ...valueParts] = line.split("=");
      const value = valueParts.join("=").trim();

      // Remover comillas si las tiene
      env[key.trim()] = value.replace(/^["']|["']$/g, "");
    });

    return env;
  } catch (error) {
    console.error("[ENV-LOADER] Error cargando .env:", error);
    return {};
  }
}

// Cargar variables de entorno y hacerlas disponibles globalmente
async function initEnv() {
  window.ENV = await loadEnv();
  console.log("[ENV-LOADER] Variables de entorno cargadas");
  return window.ENV;
}

// Ejecutar automáticamente
initEnv();
