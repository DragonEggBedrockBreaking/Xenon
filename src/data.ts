import { invoke } from "@tauri-apps/api/tauri";
import zxcvbn from "zxcvbn";
import {generate} from "generate-password-ts";

let passwordInputEl: HTMLInputElement | null;
let addWebsiteInputEl: HTMLInputElement | null;
let addUsernameInputEl: HTMLInputElement | null;
let addPasswordInputEl: HTMLInputElement | null;
let addNotesInputEl: HTMLInputElement | null;
let editWebsiteInputEl: HTMLInputElement | null;
let editUsernameInputEl: HTMLInputElement | null;
let editPasswordInputEl: HTMLInputElement | null;
let editNotesInputEl: HTMLInputElement | null;
let newMasterPasswordEl: HTMLInputElement | null;
let searchInputEl: HTMLInputElement | null;
let passwordLengthInputEl: HTMLInputElement | null;
let includeLowercaseInputEl: HTMLInputElement | null;
let includeUppercaseInputEl: HTMLInputElement | null;
let includeNumbersInputEl: HTMLInputElement | null;
let includeSymbolsInputEl: HTMLInputElement | null;
let editNumber: number = -1;

const passwordStrengthToBackgroundColourMap: Map<number, string> = new Map([
    [0, "#800000"],
    [1, "#ff0000"],
    [2, "#ff8000"],
    [3, "#ffff00"],
    [4, "#00ff00"],
]);
const passwordStrengthToTextColorMap: Map<number, string> = new Map([
    [0, "#ffffff"],
    [1, "#000000"],
    [2, "#000000"],
    [3, "#000000"],
    [4, "#000000"],
]);

function modifyVisibility(element: HTMLElement | null, value: string) {
    if (element) {
        element.style.display = value;
    }
}

async function add() {
    if (addWebsiteInputEl && addUsernameInputEl && addPasswordInputEl && addNotesInputEl && passwordInputEl) {
        await invoke("add", {
            website: addWebsiteInputEl.value,
            username: addUsernameInputEl.value,
            password: addPasswordInputEl.value,
            notes: addNotesInputEl.value,
            masterpw: passwordInputEl.value,
        });
        await update_all();
    }
    addWebsiteInputEl!.value = "";
    addUsernameInputEl!.value = "";
    addPasswordInputEl!.value = "";
    addNotesInputEl!.value = "";
}

async function del(index: number) {
    await invoke("delete", {
        index: index,
    });
    await update_all();
}

async function edit() {
    if (editWebsiteInputEl && editUsernameInputEl && editPasswordInputEl && editNotesInputEl && passwordInputEl) {
        await invoke("edit", {
            index: editNumber,
            website: editWebsiteInputEl.value,
            username: editUsernameInputEl.value,
            password: editPasswordInputEl.value,
            notes: editNotesInputEl.value,
            masterpw: passwordInputEl.value,
        });
        await update_all();
    }
    await cancel();
    editWebsiteInputEl!.value = "";
    editUsernameInputEl!.value = "";
    editPasswordInputEl!.value = "";
    editNotesInputEl!.value = "";
}

async function cancel() {
    modifyVisibility(document.querySelector(".edit"), "none");
    modifyVisibility(document.querySelector(".add"), "block");
    editNumber = -1;
}

async function update_all() {
    if (passwordInputEl) {
        let [websites, usernames, passwords, notes]: [string[], string[], string[], string[]] = await invoke("get_all", {
            masterpw: passwordInputEl.value,
        });
        await update(websites, usernames, passwords, notes);
    }
}

async function update_only(filter_type: string) {
    if (searchInputEl && passwordInputEl) {
        let [websites, usernames, passwords, notes]: [string[], string[], string[], string[]] = await invoke("get_only", {
            filter: searchInputEl.value,
            ft: filter_type,
            masterpw: passwordInputEl.value,
        });
        await update(websites, usernames, passwords, notes);
    }
}

async function update(websites: string[], usernames: string[], passwords: string[], notes: string[]) {
    let strengths_text: string[] = [];
    let strengths_background_color: string[] = [];
    let strengths_text_color: string[] = [];
    let strength_warnings: string[] = [];
    passwords.forEach((password) => {
       let strength = zxcvbn(password);
       strengths_text.push(strength.crack_times_display.offline_slow_hashing_1e4_per_second.toString());
       strengths_background_color.push(passwordStrengthToBackgroundColourMap.get(strength.score) ?? "#000000ff");
         strengths_text_color.push(passwordStrengthToTextColorMap.get(strength.score) ?? "#ffffff");
       strength_warnings.push(strength.feedback.warning || strength.feedback.suggestions[0]);
    });
    const table = document.getElementById("main-table");
    if (table) {
        const tbody = table.querySelector("tbody");
        if (tbody) {
            const rows = websites.map((item, index) => {
               return `<tr>
                    <td>${item}</td>
                    <td>${usernames[index]}</td>
                    <td>${passwords[index]}</td>
                    <td>${notes[index]}</td>
                    <td>
                        <button class="row-button-edit" type="button"><span>&#x2710</span></button>
                        <button class="row-button-delete" type="button"><span>&#x274C</span></button>
                    </td>
                    <td style="background-color: ${strengths_background_color[index]}; color: ${strengths_text_color[index]}">
                        ${strengths_text[index]}
                    </td>
                    <td>${strength_warnings[index]}</td>
                </tr>`;
            });
            tbody.innerHTML = rows.join("");
            if (tbody.children.length == 0) {
                table.classList.add("empty-table");
            } else {
                table.classList.remove("empty-table");
            }
        }
        const delete_buttons = table.querySelectorAll(".row-button-delete");
        delete_buttons.forEach((button, index) => {
           button.addEventListener("click", async () => {
               await del(index);
           });
        });
        const edit_buttons = table.querySelectorAll(".row-button-edit");
        edit_buttons.forEach((button, index) => {
              button.addEventListener("click", async () => {
                  if (passwordInputEl) {
                      editNumber = index;
                      modifyVisibility(document.querySelector(".edit"), "block");
                      modifyVisibility(document.querySelector(".add"), "none");
                      let [website, username, pass, notes]: [string, string, string, string] = await invoke("get_row", {
                          index: index,
                          masterpw: passwordInputEl.value,
                      });
                      editWebsiteInputEl!.value = website;
                      editUsernameInputEl!.value = username;
                      editPasswordInputEl!.value = pass;
                      editNotesInputEl!.value = notes;
                  }
              });
        });
    }
}

async function genPassword(inputElement: HTMLInputElement | null) {
    await invoke("print", {msg: "Generating password..."});
    let password = generate({
        length: passwordLengthInputEl?.valueAsNumber!,
        lowercase: includeLowercaseInputEl?.checked!,
        uppercase: includeUppercaseInputEl?.checked!,
        numbers: includeNumbersInputEl?.checked!,
        symbols: includeSymbolsInputEl?.checked!,
        exclude: "\"<>",
    });
    await invoke("print", {msg: "Genned"});
    password = password.replace("<", "");
    await invoke("print", {msg: "Final"});
    inputElement!.value = password.replace(">", "");
}

async function change() {
    if (newMasterPasswordEl && passwordInputEl) {
        await invoke("change_master_password", {
            password: newMasterPasswordEl.value,
        });
        let [websites, usernames, passwords, notes]: [string[], string[], string[], string[]] = await invoke("get_all", {
            masterpw: passwordInputEl.value,
        });
        for (let index = 0; index < websites.length; index++) {
           await invoke("edit",{
               index: index,
               website: usernames[index],
               username: usernames[index],
               password: passwords[index],
               notes: notes[index],
               masterpw: newMasterPasswordEl!.value,
           });
        }
        passwordInputEl.value = newMasterPasswordEl.value;
        newMasterPasswordEl.value = "";
    }
}

window.addEventListener("DOMContentLoaded", () => {
    passwordInputEl = document.querySelector("#password-input");
    addWebsiteInputEl = document.querySelector("#add-website");
    addUsernameInputEl = document.querySelector("#add-username");
    addPasswordInputEl = document.querySelector("#add-password");
    addNotesInputEl = document.querySelector("#add-notes");
    editWebsiteInputEl = document.querySelector("#edit-website");
    editUsernameInputEl = document.querySelector("#edit-username");
    editPasswordInputEl = document.querySelector("#edit-password");
    editNotesInputEl = document.querySelector("#edit-notes");
    newMasterPasswordEl = document.querySelector("#new-master-password");
    searchInputEl = document.querySelector("#search-input");
    passwordLengthInputEl = document.querySelector("#password-length");
    includeLowercaseInputEl = document.querySelector("#include-lowercase");
    includeUppercaseInputEl = document.querySelector("#include-uppercase");
    includeNumbersInputEl = document.querySelector("#include-numbers");
    includeSymbolsInputEl = document.querySelector("#include-symbols");

    document.querySelector("#done-button")?.addEventListener("click", update_all);
    document.querySelector("#add-button")?.addEventListener("click", add);
    document.querySelector("#done-button")?.addEventListener("click", update_all);
    document.querySelector("#edit-button")?.addEventListener("click", edit);
    document.querySelector("#cancel-button")?.addEventListener("click", cancel);
    document.querySelector("#generate-password-add")?.addEventListener("click", () => genPassword(addPasswordInputEl));
    document.querySelector("#generate-password-edit")?.addEventListener("click", () => genPassword(editPasswordInputEl));
    document.querySelector("#change-button")?.addEventListener("click", change);
    document.querySelector("#search-website")?.addEventListener("click", async () => await update_only("website"));
    document.querySelector("#search-username")?.addEventListener("click", async () => await update_only("username"));
    document.querySelector("#reset-search")?.addEventListener("click", async() => {
        await update_all();
        searchInputEl!.value = "";
    });
});
