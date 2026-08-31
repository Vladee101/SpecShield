// Windows release builds must not spawn a console window behind the app.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    specshield_app_lib::run();
}
