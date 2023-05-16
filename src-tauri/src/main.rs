#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod start;
mod data;

#[tauri::command]
fn print(msg: String) {
    println!("{}", msg);
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            print,
            start::login,
            start::register,
            start::change_master_password,
            data::add,
            data::get_all,
            data::get_row,
            data::get_only,
            data::delete,
            data::edit
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
