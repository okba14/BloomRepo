use crate::config::AppConfig;
use crate::db::Database;
use crate::engine::Engine;
use crate::models::RepoItem;
use eframe::egui::{self, Color32, RichText, Stroke, Vec2};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc as tokio_mpsc, Notify, RwLock};

pub enum GuiEvent {
    NewBatch(Vec<RepoItem>),
    CycleFinished {
        cycle: u64,
        new_count: usize,
        priority_total: usize,
        spam_count: usize,
        duration_ms: u128,
        db_total: usize,
        today_total: usize,
    },
    Status(String),
}
pub enum GuiCommand {
    TriggerScan,
    SetPaused(bool),
}

pub struct RepoWatcherApp {
    db: Database,
    monitoring: bool,
    status_text: String,
    total_repos: usize,
    today_repos: usize,
    priority_repos: usize,
    spam_filtered: usize,
    search_query: String,
    priority_only: bool,
    hide_forks: bool,
    feed: Vec<RepoItem>,
    event_rx: Receiver<GuiEvent>,
    command_tx: tokio_mpsc::Sender<GuiCommand>,
    last_cycle: Option<String>,
    show_about_modal: bool,
    app_icon: Option<egui::TextureHandle>,
}

impl RepoWatcherApp {
    fn new(
        db: Database,
        event_rx: Receiver<GuiEvent>,
        command_tx: tokio_mpsc::Sender<GuiCommand>,
        app_icon: Option<egui::TextureHandle>,
    ) -> Self {
        let (total, today, priority) = db.get_stats().unwrap_or_default();
        let feed = db.search("", 100).unwrap_or_default();
        Self {
            db,
            monitoring: true,
            status_text: "Engine ready — monitoring active".into(),
            total_repos: total,
            today_repos: today,
            priority_repos: priority,
            spam_filtered: 0,
            search_query: String::new(),
            priority_only: false,
            hide_forks: true,
            feed,
            event_rx,
            command_tx,
            last_cycle: None,
            show_about_modal: false,
            app_icon,
        }
    }
}

impl eframe::App for RepoWatcherApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                GuiEvent::NewBatch(mut items) => {
                    items.reverse();
                    self.feed.splice(0..0, items);
                    self.feed.truncate(500);
                }
                GuiEvent::CycleFinished {
                    cycle,
                    new_count,
                    priority_total,
                    spam_count,
                    duration_ms,
                    db_total,
                    today_total,
                } => {
                    self.total_repos = db_total;
                    self.today_repos = today_total;
                    self.priority_repos = priority_total;
                    self.spam_filtered += spam_count;
                    self.last_cycle = Some(chrono::Local::now().format("%H:%M:%S").to_string());
                    self.status_text =
                        format!("Cycle #{cycle} completed · {new_count} new · {duration_ms} ms");
                }
                GuiEvent::Status(message) => self.status_text = message,
            }
        }
        ctx.request_repaint_after(Duration::from_millis(500));
        egui::TopBottomPanel::top("header")
            .frame(egui::Frame::none().inner_margin(14.0))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if let Some(ref icon) = self.app_icon {
                        ui.add(egui::Image::new(icon).fit_to_exact_size(egui::vec2(26.0, 26.0)));
                    }
                    ui.heading(
                        RichText::new("BloomRepo")
                            .color(Color32::from_rgb(55, 210, 255))
                            .strong(),
                    );
                    ui.label(RichText::new("ULTRA 2.1").color(Color32::GRAY));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .button("ℹ About")
                            .on_hover_text("Architect & System Information")
                            .clicked()
                        {
                            self.show_about_modal = true;
                        }
                        if ui.button("Open folder").clicked() {
                            let _ = std::process::Command::new("explorer").arg(".").spawn();
                        }
                        if ui.button("Scan now").clicked() {
                            let _ = self.command_tx.try_send(GuiCommand::TriggerScan);
                        }
                        let label = if self.monitoring { "Pause" } else { "Resume" };
                        if ui.button(label).clicked() {
                            self.monitoring = !self.monitoring;
                            let _ = self
                                .command_tx
                                .try_send(GuiCommand::SetPaused(!self.monitoring));
                        }
                        let badge = if self.monitoring {
                            "● LIVE"
                        } else {
                            "● PAUSED"
                        };
                        ui.label(
                            RichText::new(badge)
                                .color(if self.monitoring {
                                    Color32::from_rgb(80, 235, 140)
                                } else {
                                    Color32::YELLOW
                                })
                                .strong(),
                        );
                    });
                });
            });
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("STATUS").color(Color32::GRAY).strong());
                ui.label(&self.status_text);
                if let Some(time) = &self.last_cycle {
                    ui.separator();
                    ui.label(format!("Last cycle {time}"));
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .link(
                            RichText::new("GUIAR OQBA · Systems Architect")
                                .color(Color32::from_rgb(115, 175, 235))
                                .size(11.0),
                        )
                        .on_hover_text("Systems Software Architect & Cyber Security Researcher\nClick to view profile & official contacts")
                        .clicked()
                    {
                        self.show_about_modal = true;
                    }
                    ui.label(
                        RichText::new("Engine by")
                            .color(Color32::from_rgb(110, 120, 135))
                            .size(11.0),
                    );
                });
            });
        });
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                metric(
                    ui,
                    "TOTAL",
                    self.total_repos,
                    Color32::from_rgb(50, 190, 255),
                );
                metric(
                    ui,
                    "TODAY",
                    self.today_repos,
                    Color32::from_rgb(50, 230, 150),
                );
                metric(
                    ui,
                    "PRIORITY",
                    self.priority_repos,
                    Color32::from_rgb(255, 100, 90),
                );
                metric(
                    ui,
                    "FILTERED",
                    self.spam_filtered,
                    Color32::from_rgb(255, 190, 50),
                );
            });
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("SEARCH").color(Color32::GRAY).strong());
                let changed = ui
                    .add(
                        egui::TextEdit::singleline(&mut self.search_query)
                            .hint_text("repository, language, description...")
                            .desired_width(320.0),
                    )
                    .changed();
                if changed {
                    self.feed = self
                        .db
                        .search(self.search_query.trim(), 100)
                        .unwrap_or_default();
                }
                ui.checkbox(&mut self.priority_only, "Priority only");
                ui.checkbox(&mut self.hide_forks, "Hide forks");
            });
            ui.separator();
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for repo in &self.feed {
                        if self.priority_only && !repo.is_priority {
                            continue;
                        }
                        if self.hide_forks && repo.fork {
                            continue;
                        }
                        egui::Frame::group(ui.style())
                            .fill(Color32::from_rgb(25, 29, 38))
                            .stroke(Stroke::new(1.0_f32, Color32::from_rgb(50, 62, 78)))
                            .inner_margin(10.0)
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    let badge = if repo.is_priority {
                                        "PRIORITY"
                                    } else if repo.fork {
                                        "FORK"
                                    } else {
                                        "NEW"
                                    };
                                    ui.label(
                                        RichText::new(badge)
                                            .color(if repo.is_priority {
                                                Color32::from_rgb(255, 100, 80)
                                            } else {
                                                Color32::from_rgb(70, 220, 150)
                                            })
                                            .strong(),
                                    );
                                    ui.label(
                                        RichText::new(&repo.full_name)
                                            .strong()
                                            .color(Color32::WHITE),
                                    );
                                    if let Some(language) = &repo.language {
                                        ui.label(
                                            RichText::new(language)
                                                .color(Color32::from_rgb(70, 190, 255)),
                                        );
                                    }
                                    if repo.stars > 0 {
                                        ui.label(format!("★ {}", repo.stars));
                                    }
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            if ui.button("Open").clicked() {
                                                let _ = webbrowser::open(&repo.html_url);
                                            }
                                        },
                                    );
                                });
                                if let Some(description) = &repo.description {
                                    if !description.trim().is_empty() {
                                        ui.add_space(4.0);
                                        ui.label(
                                            RichText::new(description)
                                                .color(Color32::from_rgb(185, 190, 200)),
                                        );
                                    }
                                }
                            });
                        ui.add_space(4.0);
                    }
                });
        });

        if self.show_about_modal {
            let mut close_clicked = false;
            let mut open = true;
            egui::Window::new("Architect & Developer Profile")
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .frame(
                    egui::Frame::window(ctx.style().as_ref())
                        .fill(Color32::from_rgb(20, 24, 34))
                        .stroke(Stroke::new(1.2_f32, Color32::from_rgb(55, 210, 255)))
                        .inner_margin(egui::Margin::same(18.0)),
                )
                .show(ctx, |ui| {
                    ui.set_width(480.0);
                    ui.vertical_centered(|ui| {
                        if let Some(ref icon) = self.app_icon {
                            ui.add(
                                egui::Image::new(icon).fit_to_exact_size(egui::vec2(64.0, 64.0)),
                            );
                            ui.add_space(8.0);
                        }
                        ui.heading(
                            RichText::new("BloomRepo Engine")
                                .size(20.0)
                                .color(Color32::from_rgb(55, 210, 255))
                                .strong(),
                        );
                        ui.label(
                            RichText::new(
                                "High-Performance GitHub Discovery & Intelligence Engine · v2.1.0",
                            )
                            .size(11.0)
                            .color(Color32::from_rgb(140, 150, 170)),
                        );
                    });

                    ui.add_space(12.0);
                    ui.separator();
                    ui.add_space(8.0);

                    // Architect Profile Card
                    egui::Frame::group(ui.style())
                        .fill(Color32::from_rgb(26, 33, 46))
                        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(45, 60, 85)))
                        .inner_margin(egui::Margin::same(14.0))
                        .show(ui, |ui| {
                            ui.label(
                                RichText::new("LEAD ARCHITECT")
                                    .size(10.0)
                                    .color(Color32::from_rgb(70, 200, 255))
                                    .strong(),
                            );
                            ui.add_space(2.0);
                            ui.label(
                                RichText::new("GUIAR OQBA")
                                    .size(19.0)
                                    .color(Color32::WHITE)
                                    .strong(),
                            );
                            ui.add_space(2.0);
                            ui.label(
                                RichText::new(
                                    "Systems Software Architect & Cyber Security Researcher",
                                )
                                .size(12.5)
                                .color(Color32::from_rgb(185, 200, 220)),
                            );

                            ui.add_space(10.0);
                            ui.horizontal_wrapped(|ui| {
                                badge(ui, "Systems Architecture", Color32::from_rgb(32, 68, 105));
                                badge(ui, "Cyber Security", Color32::from_rgb(78, 38, 98));
                                badge(ui, "Rust Core Engine", Color32::from_rgb(110, 60, 25));
                            });
                        });

                    ui.add_space(10.0);

                    // Contact & Links Card
                    egui::Frame::group(ui.style())
                        .fill(Color32::from_rgb(23, 29, 40))
                        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(38, 48, 66)))
                        .inner_margin(egui::Margin::same(12.0))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new("🌐 Official Website:")
                                        .size(12.0)
                                        .color(Color32::from_rgb(170, 180, 195)),
                                );
                                if ui
                                    .link(
                                        RichText::new("https://guiarx.com/")
                                            .size(12.0)
                                            .color(Color32::from_rgb(70, 210, 255))
                                            .underline(),
                                    )
                                    .on_hover_text("Open official website in browser")
                                    .clicked()
                                {
                                    let _ = webbrowser::open("https://guiarx.com/");
                                }
                            });
                            ui.add_space(6.0);
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new("📧 Business & Inquiries:")
                                        .size(12.0)
                                        .color(Color32::from_rgb(170, 180, 195)),
                                );
                                if ui
                                    .link(
                                        RichText::new("contact@guiarx.com")
                                            .size(12.0)
                                            .color(Color32::from_rgb(90, 230, 160))
                                            .underline(),
                                    )
                                    .on_hover_text("Send an email to contact@guiarx.com")
                                    .clicked()
                                {
                                    let _ = webbrowser::open("mailto:contact@guiarx.com");
                                }
                            });
                            ui.add_space(6.0);
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new("📬 Direct Contact:")
                                        .size(12.0)
                                        .color(Color32::from_rgb(170, 180, 195)),
                                );
                                if ui
                                    .link(
                                        RichText::new("hello@guiarx.com")
                                            .size(12.0)
                                            .color(Color32::from_rgb(255, 185, 70))
                                            .underline(),
                                    )
                                    .on_hover_text("Send direct email to hello@guiarx.com")
                                    .clicked()
                                {
                                    let _ = webbrowser::open("mailto:hello@guiarx.com");
                                }
                            });
                        });

                    ui.add_space(14.0);

                    ui.horizontal(|ui| {
                        if ui.button("🌐 Visit guiarx.com").clicked() {
                            let _ = webbrowser::open("https://guiarx.com/");
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button(RichText::new("Close").strong()).clicked() {
                                close_clicked = true;
                            }
                        });
                    });
                });
            if !open || close_clicked {
                self.show_about_modal = false;
            }
        }
    }
}

fn badge(ui: &mut egui::Ui, text: &str, bg_color: Color32) {
    egui::Frame::group(ui.style())
        .fill(bg_color)
        .stroke(Stroke::NONE)
        .inner_margin(egui::Margin::symmetric(8.0, 3.0))
        .show(ui, |ui| {
            ui.label(
                RichText::new(text)
                    .size(10.5)
                    .color(Color32::WHITE)
                    .strong(),
            );
        });
}

fn metric(ui: &mut egui::Ui, title: &str, value: usize, color: Color32) {
    egui::Frame::group(ui.style())
        .fill(Color32::from_rgb(28, 34, 44))
        .inner_margin(egui::Margin::symmetric(16.0, 10.0))
        .show(ui, |ui| {
            ui.set_min_size(Vec2::new(145.0, 54.0));
            ui.label(RichText::new(title).size(11.0).color(Color32::GRAY));
            ui.label(
                RichText::new(value.to_string())
                    .size(20.0)
                    .color(color)
                    .strong(),
            );
        });
}

pub fn start_gui_mode(config: AppConfig, db: Database) -> Result<(), eframe::Error> {
    let (event_tx, event_rx) = channel();
    let (command_tx, command_rx) = tokio_mpsc::channel(32);
    let bg_config = config.clone();
    let bg_db = db.clone();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        runtime.block_on(run_background(bg_config, bg_db, event_tx, command_rx));
    });
    let icon_bytes = include_bytes!("../img/icon.png");
    let icon_data = eframe::icon_data::from_png_bytes(icon_bytes).ok();

    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([1080.0, 720.0])
        .with_min_inner_size([760.0, 480.0])
        .with_title("BloomRepo");
    if let Some(ref icon) = icon_data {
        viewport = viewport.with_icon(icon.clone());
    }

    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    eframe::run_native(
        "BloomRepo",
        options,
        Box::new(move |cc| {
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
            let app_icon = icon_data.as_ref().map(|data| {
                let color_image = egui::ColorImage::from_rgba_unmultiplied(
                    [data.width as usize, data.height as usize],
                    &data.rgba,
                );
                cc.egui_ctx.load_texture(
                    "bloomrepo_icon",
                    color_image,
                    egui::TextureOptions::LINEAR,
                )
            });
            Ok(Box::new(RepoWatcherApp::new(
                db, event_rx, command_tx, app_icon,
            )))
        }),
    )
}

async fn run_background(
    config: AppConfig,
    db: Database,
    event_tx: Sender<GuiEvent>,
    mut command_rx: tokio_mpsc::Receiver<GuiCommand>,
) {
    let mut engine = Engine::new(config.clone(), db);
    let paused = Arc::new(RwLock::new(false));
    let notify = Arc::new(Notify::new());
    let paused_writer = paused.clone();
    let notify_writer = notify.clone();
    tokio::spawn(async move {
        while let Some(command) = command_rx.recv().await {
            match command {
                GuiCommand::TriggerScan => notify_writer.notify_one(),
                GuiCommand::SetPaused(value) => {
                    *paused_writer.write().await = value;
                    notify_writer.notify_one();
                }
            }
        }
    });
    let mut bg_cycle: u64 = 0;
    loop {
        if *paused.read().await {
            notify.notified().await;
            continue;
        }
        bg_cycle += 1;
        let _ = event_tx.send(GuiEvent::Status(format!("Scanning cycle #{bg_cycle}…")));
        match engine.run_cycle().await {
            Ok(result) => {
                let (total, today, priority) =
                    engine.db.get_stats().unwrap_or((result.db_total, 0, 0));
                let new_count = result.items.len();
                if new_count > 0 {
                    let _ = event_tx.send(GuiEvent::NewBatch(result.items));
                }
                let _ = event_tx.send(GuiEvent::CycleFinished {
                    cycle: result.cycle,
                    new_count,
                    priority_total: priority,
                    spam_count: result.spam_count,
                    duration_ms: result.duration_ms,
                    db_total: total,
                    today_total: today,
                });
            }
            Err(error) => {
                let _ = event_tx.send(GuiEvent::Status(format!("Cycle failed: {error}")));
            }
        }
        tokio::select! { _ = notify.notified() => {}, _ = tokio::time::sleep(Duration::from_secs(config.general.interval_seconds)) => {} }
    }
}
