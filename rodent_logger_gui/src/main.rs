use iced::{
    Element, Subscription, Task,
    widget::{button, column, container, scrollable, text, text_input},
};
use pcap::Device;
use rodent_logger_core::{capture, export_csv, generate_stats, rodent_logger_dir};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

fn main() -> iced::Result {
    iced::application(App::default, update, view)
        .title(title)
        .run()
}

fn title(_state: &App) -> String {
    "Rodent Logger".to_string()
}

#[derive(Debug, Default)]
struct App {
    interfaces: Vec<pcap::Device>,
    selected_interfaces: String,
}

#[derive(Debug, Clone, Copy)]
enum Message {
    ListInterfaces,
}

fn view(state: &App) -> Element<'_, Message> {
    let mut content = column![
        text("Rodent Logger").size(24),
        button("List interfaces").on_press(Message::ListInterfaces),
    ];
    if !state.interfaces.is_empty() {
        content = content.push(text(""));
        for iface in &state.interfaces {
            content = content.push(text(&iface.name));
        }
    }
    container(scrollable(content)).padding(20).into()
}

fn update(state: &mut App, msg: Message) -> iced::Task<Message> {
    match msg {
        Message::ListInterfaces => {
            state.interfaces = pcap::Device::list().unwrap_or_default();
        }
    }
    Task::none()
}
