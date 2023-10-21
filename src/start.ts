import { invoke } from "@tauri-apps/api/primitives";

let passwordInputEl: HTMLInputElement | null;
let totpInputEl: HTMLInputElement | null;
let startMsgEl: HTMLElement | null;

function modifyVisibility(element: HTMLElement | null, value: string) {
  if (element) {
    element.style.display = value;
  }
}

async function login() {
  if (passwordInputEl && totpInputEl && startMsgEl) {
    let res: boolean = await invoke("login", {
      password: passwordInputEl.value,
      code: totpInputEl.value,
    });
    if (res) {
      startMsgEl.textContent = "Login successful.";
    } else {
      startMsgEl.textContent = "Login failed."
    }
    if (startMsgEl?.textContent && res) {
      modifyVisibility(document.getElementById("done-button"), "inline");
      modifyVisibility(document.getElementById("login-button"), "none");
      modifyVisibility(document.getElementById("register-button"), "none");
    }
  }
}

async function register() {
  if (passwordInputEl && startMsgEl) {
    let [success, qr]: [boolean, string] = await invoke("register", {
      password: passwordInputEl.value,
    });
    if (success) {
      startMsgEl.textContent = "Scan the QR code with your authenticator app.";
      qr = "data:image/png;base64," + qr;
      const img = document.getElementById("qrcode") as HTMLImageElement;
      img.src = qr as string;
      modifyVisibility(document.getElementById("qrcode"), "block");
      modifyVisibility(document.getElementById("done-button"), "inline");
      modifyVisibility(document.getElementById("login-button"), "none");
      modifyVisibility(document.getElementById("register-button"), "none");
    } else {
      startMsgEl.textContent = "Cannot register - account already exists."
    }
  }
}

async function done() {
  modifyVisibility(document.getElementById("start"), "none");
  modifyVisibility(document.getElementById("data"), "block");
}

window.addEventListener("DOMContentLoaded", () => {
  passwordInputEl = document.querySelector("#password-input");
  totpInputEl = document.querySelector("#totp-input");
  startMsgEl = document.querySelector("#start-msg");

  document.querySelector("#login-button")?.addEventListener("click", () => login());
  document.querySelector("#register-button")?.addEventListener("click", () => register());
  document.querySelector("#done-button")?.addEventListener("click", () => done());
});
