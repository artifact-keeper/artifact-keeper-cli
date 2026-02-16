use std::io;

use artifact_keeper_sdk::ClientRepositoriesExt;
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use miette::{IntoDiagnostic, Result};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{DefaultTerminal, Frame};

use super::client::build_client;
use crate::config::AppConfig;
use crate::config::credentials::{StoredCredential, get_credential};
use crate::output::format_bytes;

// ---------------------------------------------------------------------------
// Style helpers — eliminate repeated Style::default().fg(...).add_modifier(...)
// ---------------------------------------------------------------------------

fn bold_style() -> Style {
    Style::default().add_modifier(Modifier::BOLD)
}

fn hotkey_style() -> Style {
    Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD)
}

fn dim_style() -> Style {
    Style::default().fg(Color::DarkGray)
}

fn cyan_style() -> Style {
    Style::default().fg(Color::Cyan)
}

fn highlight_style() -> Style {
    Style::default()
        .bg(Color::DarkGray)
        .add_modifier(Modifier::BOLD)
}

fn panel_border_style(active: &Panel, panel: &Panel) -> Style {
    if active == panel {
        cyan_style()
    } else {
        dim_style()
    }
}

// ---------------------------------------------------------------------------
// Span/Line helpers — reduce repetitive span construction
// ---------------------------------------------------------------------------

/// A status-bar hotkey label like " **q**uit ".
fn hotkey_span<'a>(key: &'a str, rest: &'a str) -> Vec<Span<'a>> {
    vec![
        Span::styled(key, hotkey_style()),
        Span::raw(rest),
        Span::raw(" "),
    ]
}

/// A "Label:  value" detail line with a bold label.
fn detail_line(label: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(label.to_owned(), bold_style()),
        Span::raw(value.to_owned()),
    ])
}

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

#[derive(Clone, PartialEq, Eq)]
enum Panel {
    Instances,
    Repos,
    Artifacts,
}

struct InstanceEntry {
    name: String,
    url: String,
    status: String,
}

struct RepoEntry {
    key: String,
    format: String,
    storage_used: i64,
}

struct ArtifactEntry {
    path: String,
    version: Option<String>,
    size_bytes: i64,
    downloads: i64,
    created: String,
}

struct App {
    active_panel: Panel,
    instances: Vec<InstanceEntry>,
    instance_state: ListState,
    repos: Vec<RepoEntry>,
    repo_state: ListState,
    artifacts: Vec<ArtifactEntry>,
    artifact_state: ListState,
    status_message: String,
    loading: bool,
    show_help: bool,
    detail_view: bool,
    config: AppConfig,
    search_query: String,
    searching: bool,
    /// Cached credentials per instance — avoids repeated keychain prompts.
    credential_cache: std::collections::HashMap<String, StoredCredential>,
}

impl App {
    fn new(config: AppConfig) -> Self {
        let instances: Vec<InstanceEntry> = config
            .instances
            .iter()
            .map(|(name, inst)| InstanceEntry {
                name: name.clone(),
                url: inst.url.clone(),
                status: "...".to_string(),
            })
            .collect();

        let mut instance_state = ListState::default();
        if !instances.is_empty() {
            instance_state.select(Some(0));
        }

        Self {
            active_panel: Panel::Instances,
            instances,
            instance_state,
            repos: Vec::new(),
            repo_state: ListState::default(),
            artifacts: Vec::new(),
            artifact_state: ListState::default(),
            status_message: "Press ? for help".to_string(),
            loading: false,
            show_help: false,
            detail_view: false,
            config,
            search_query: String::new(),
            searching: false,
            credential_cache: std::collections::HashMap::new(),
        }
    }

    fn selected_instance(&self) -> Option<&InstanceEntry> {
        self.instance_state
            .selected()
            .and_then(|i| self.instances.get(i))
    }

    fn selected_repo(&self) -> Option<&RepoEntry> {
        self.repo_state.selected().and_then(|i| self.repos.get(i))
    }

    fn selected_artifact(&self) -> Option<&ArtifactEntry> {
        self.artifact_state
            .selected()
            .and_then(|i| self.artifacts.get(i))
    }

    fn active_list_state_mut(&mut self) -> (&mut ListState, usize) {
        match self.active_panel {
            Panel::Instances => (&mut self.instance_state, self.instances.len()),
            Panel::Repos => (&mut self.repo_state, self.repos.len()),
            Panel::Artifacts => (&mut self.artifact_state, self.artifacts.len()),
        }
    }

    fn move_up(&mut self) {
        let (state, len) = self.active_list_state_mut();
        list_prev(state, len);
    }

    fn move_down(&mut self) {
        let (state, len) = self.active_list_state_mut();
        list_next(state, len);
    }

    fn move_left(&mut self) {
        match self.active_panel {
            Panel::Instances => {}
            Panel::Repos => self.active_panel = Panel::Instances,
            Panel::Artifacts => self.active_panel = Panel::Repos,
        }
    }

    fn move_right(&mut self) {
        match self.active_panel {
            Panel::Instances if !self.repos.is_empty() => self.active_panel = Panel::Repos,
            Panel::Repos if !self.artifacts.is_empty() => self.active_panel = Panel::Artifacts,
            _ => {}
        }
    }

    /// Get a cached credential, loading from keychain/file only once per instance.
    fn cached_credential(&mut self, instance_name: &str) -> Option<&StoredCredential> {
        if !self.credential_cache.contains_key(instance_name) {
            if let Ok(cred) = get_credential(instance_name) {
                self.credential_cache
                    .insert(instance_name.to_string(), cred);
            }
        }
        self.credential_cache.get(instance_name)
    }

    /// Build an SDK client using cached credentials (no repeated keychain prompts).
    fn build_cached_client(&mut self, instance_name: &str) -> Option<artifact_keeper_sdk::Client> {
        let instance = self.config.instances.get(instance_name)?.clone();
        let cred = self.cached_credential(instance_name).cloned();
        match cred {
            Some(ref c) => build_client(instance_name, &instance, Some(c)).ok(),
            None => {
                // Fall back to unauthenticated client
                let http_client = reqwest::ClientBuilder::new()
                    .connect_timeout(std::time::Duration::from_secs(15))
                    .timeout(std::time::Duration::from_secs(30))
                    .build()
                    .ok()?;
                Some(artifact_keeper_sdk::Client::new_with_client(
                    &instance.url,
                    http_client,
                ))
            }
        }
    }

    async fn check_instance_health(&mut self) {
        for i in 0..self.instances.len() {
            let name = self.instances[i].name.clone();
            let instance = match self.config.instances.get(&name) {
                Some(i) => i.clone(),
                None => continue,
            };

            let http_client = match reqwest::ClientBuilder::new()
                .connect_timeout(std::time::Duration::from_secs(3))
                .timeout(std::time::Duration::from_secs(5))
                .build()
            {
                Ok(c) => c,
                Err(_) => {
                    self.instances[i].status = "error".to_string();
                    continue;
                }
            };

            // Use unauthenticated client hitting /api/v1/repositories to check health.
            // The /health endpoint is at root level and gets intercepted by reverse proxies.
            let client = artifact_keeper_sdk::Client::new_with_client(&instance.url, http_client);

            match client.list_repositories().page(1).per_page(1).send().await {
                Ok(resp) => {
                    self.instances[i].status = format!("online ({} repos)", resp.pagination.total);
                }
                Err(_) => {
                    self.instances[i].status = "offline".to_string();
                }
            }
        }
    }

    async fn load_repos(&mut self) {
        let instance_name = match self.selected_instance() {
            Some(i) => i.name.clone(),
            None => return,
        };

        let client = match self.build_cached_client(&instance_name) {
            Some(c) => c,
            None => {
                self.status_message = format!("Failed to connect to {instance_name}");
                return;
            }
        };

        self.loading = true;
        self.status_message = format!("Loading repos from {instance_name}...");

        match client.list_repositories().per_page(100).send().await {
            Ok(resp) => {
                self.repos = resp
                    .items
                    .iter()
                    .map(|r| RepoEntry {
                        key: r.key.clone(),
                        format: r.format.clone(),
                        storage_used: r.storage_used_bytes,
                    })
                    .collect();

                self.repo_state = ListState::default();
                if !self.repos.is_empty() {
                    self.repo_state.select(Some(0));
                }
                self.artifacts.clear();
                self.artifact_state = ListState::default();
                self.status_message =
                    format!("{} repositories in {instance_name}", self.repos.len());
            }
            Err(e) => {
                self.status_message = format!("Failed to load repos: {e}");
                self.repos.clear();
            }
        }
        self.loading = false;
    }

    async fn load_artifacts(&mut self) {
        let instance_name = match self.selected_instance() {
            Some(i) => i.name.clone(),
            None => return,
        };

        let repo_key = match self.selected_repo() {
            Some(r) => r.key.clone(),
            None => return,
        };

        let client = match self.build_cached_client(&instance_name) {
            Some(c) => c,
            None => {
                self.status_message = format!("Failed to connect to {instance_name}");
                return;
            }
        };

        self.loading = true;
        self.status_message = format!("Loading artifacts from {repo_key}...");

        let mut req = client.list_artifacts().key(&repo_key).per_page(50);
        if !self.search_query.is_empty() {
            req = req.q(&self.search_query);
        }

        match req.send().await {
            Ok(resp) => {
                self.artifacts = resp
                    .items
                    .iter()
                    .map(|a| ArtifactEntry {
                        path: a.path.clone(),
                        version: a.version.clone(),
                        size_bytes: a.size_bytes,
                        downloads: a.download_count,
                        created: a.created_at.format("%Y-%m-%d").to_string(),
                    })
                    .collect();

                self.artifact_state = ListState::default();
                if !self.artifacts.is_empty() {
                    self.artifact_state.select(Some(0));
                }
                self.status_message = format!("{} artifacts in {repo_key}", self.artifacts.len());
            }
            Err(e) => {
                self.status_message = format!("Failed to load artifacts: {e}");
                self.artifacts.clear();
            }
        }
        self.loading = false;
    }
}

// ---------------------------------------------------------------------------
// List navigation
// ---------------------------------------------------------------------------

fn list_next(state: &mut ListState, len: usize) {
    if len == 0 {
        return;
    }
    let i = match state.selected() {
        Some(i) => (i + 1).min(len - 1),
        None => 0,
    };
    state.select(Some(i));
}

fn list_prev(state: &mut ListState, len: usize) {
    if len == 0 {
        return;
    }
    let i = match state.selected() {
        Some(i) => i.saturating_sub(1),
        None => 0,
    };
    state.select(Some(i));
}

// ---------------------------------------------------------------------------
// Entry point & event loop
// ---------------------------------------------------------------------------

pub async fn execute(_global: &crate::cli::GlobalArgs) -> Result<()> {
    let config = AppConfig::load()?;

    if config.instances.is_empty() {
        eprintln!("No instances configured. Run `ak instance add <name> <url>` first.");
        return Ok(());
    }

    enable_raw_mode().into_diagnostic()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).into_diagnostic()?;

    let terminal = ratatui::init();
    let result = run_app(terminal, config).await;

    disable_raw_mode().ok();
    execute!(io::stdout(), LeaveAlternateScreen).ok();
    ratatui::restore();

    result
}

async fn run_app(mut terminal: DefaultTerminal, config: AppConfig) -> Result<()> {
    let mut app = App::new(config);

    app.check_instance_health().await;
    app.load_repos().await;

    loop {
        terminal.draw(|f| draw(f, &mut app)).into_diagnostic()?;

        if !event::poll(std::time::Duration::from_millis(100)).into_diagnostic()? {
            continue;
        }

        let Event::Key(key) = event::read().into_diagnostic()? else {
            continue;
        };

        if app.searching {
            match key.code {
                KeyCode::Enter => {
                    app.searching = false;
                    app.load_artifacts().await;
                }
                KeyCode::Esc => {
                    app.searching = false;
                    app.search_query.clear();
                }
                KeyCode::Backspace => {
                    app.search_query.pop();
                }
                KeyCode::Char(c) => {
                    app.search_query.push(c);
                }
                _ => {}
            }
            continue;
        }

        if app.show_help {
            app.show_help = false;
            continue;
        }

        match key.code {
            KeyCode::Char('q') | KeyCode::Char('Q') => break,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
            KeyCode::Char('?') => app.show_help = true,
            KeyCode::Char('k') | KeyCode::Up => app.move_up(),
            KeyCode::Char('j') | KeyCode::Down => app.move_down(),
            KeyCode::Char('h') | KeyCode::Left => app.move_left(),
            KeyCode::Char('l') | KeyCode::Right => app.move_right(),
            KeyCode::Char('/') => {
                app.searching = true;
                app.search_query.clear();
            }
            KeyCode::Char('i') => {
                app.detail_view = !app.detail_view;
            }
            KeyCode::Tab => {
                app.active_panel = match app.active_panel {
                    Panel::Instances => Panel::Repos,
                    Panel::Repos => Panel::Artifacts,
                    Panel::Artifacts => Panel::Instances,
                };
            }
            KeyCode::Enter => match app.active_panel {
                Panel::Instances => {
                    app.load_repos().await;
                    if !app.repos.is_empty() {
                        app.active_panel = Panel::Repos;
                    }
                }
                Panel::Repos => {
                    app.load_artifacts().await;
                    if !app.artifacts.is_empty() {
                        app.active_panel = Panel::Artifacts;
                    }
                }
                Panel::Artifacts => {
                    app.detail_view = !app.detail_view;
                }
            },
            KeyCode::Char('r') => {
                app.check_instance_health().await;
                if app.active_panel == Panel::Repos || app.active_panel == Panel::Artifacts {
                    app.load_repos().await;
                }
                app.status_message = "Refreshed".to_string();
            }
            _ => {}
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Drawing
// ---------------------------------------------------------------------------

fn draw(f: &mut Frame, app: &mut App) {
    let size = f.area();

    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(5), Constraint::Length(1)])
        .split(size);

    if app.detail_view {
        draw_detail(f, app, main_layout[0]);
    } else {
        draw_panels(f, app, main_layout[0]);
    }

    draw_status_bar(f, app, main_layout[1]);

    if app.show_help {
        draw_help_overlay(f, size);
    }
}

/// Render a list panel with a titled border, highlight, and stateful selection.
fn render_panel(
    f: &mut Frame,
    title: &str,
    items: Vec<ListItem>,
    border_style: Style,
    state: &mut ListState,
    area: Rect,
) {
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(border_style);

    let list = List::new(items)
        .block(block)
        .highlight_style(highlight_style())
        .highlight_symbol("> ");

    f.render_stateful_widget(list, area, state);
}

fn draw_panels(f: &mut Frame, app: &mut App, area: Rect) {
    let panels = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(35),
            Constraint::Percentage(40),
        ])
        .split(area);

    // Instances panel
    let instance_items: Vec<ListItem> = app
        .instances
        .iter()
        .map(|inst| {
            let status_color = instance_status_color(&inst.status);
            ListItem::new(Line::from(vec![
                Span::raw(&inst.name),
                Span::raw(" "),
                Span::styled(&inst.status, Style::default().fg(status_color)),
            ]))
        })
        .collect();

    render_panel(
        f,
        " Instances ",
        instance_items,
        panel_border_style(&app.active_panel, &Panel::Instances),
        &mut app.instance_state,
        panels[0],
    );

    // Repos panel
    let repo_items: Vec<ListItem> = app
        .repos
        .iter()
        .map(|r| {
            ListItem::new(Line::from(vec![
                Span::raw(&r.key),
                Span::raw(" "),
                Span::styled(format!("({})", r.format), dim_style()),
                Span::raw(" "),
                Span::styled(format_bytes(r.storage_used), cyan_style()),
            ]))
        })
        .collect();

    render_panel(
        f,
        " Repositories ",
        repo_items,
        panel_border_style(&app.active_panel, &Panel::Repos),
        &mut app.repo_state,
        panels[1],
    );

    // Artifacts panel
    let artifact_items: Vec<ListItem> = app
        .artifacts
        .iter()
        .map(|a| {
            let version = a.version.as_deref().unwrap_or("");
            ListItem::new(Line::from(vec![
                Span::raw(&a.path),
                Span::raw(" "),
                Span::styled(version, Style::default().fg(Color::Yellow)),
                Span::raw(" "),
                Span::styled(format_bytes(a.size_bytes), dim_style()),
            ]))
        })
        .collect();

    let artifacts_title = if app.searching {
        format!(" Artifacts [/{}] ", app.search_query)
    } else {
        " Artifacts ".to_string()
    };

    render_panel(
        f,
        &artifacts_title,
        artifact_items,
        panel_border_style(&app.active_panel, &Panel::Artifacts),
        &mut app.artifact_state,
        panels[2],
    );
}

fn draw_detail(f: &mut Frame, app: &mut App, area: Rect) {
    let layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // Left: artifact list
    let items: Vec<ListItem> = app
        .artifacts
        .iter()
        .map(|a| {
            let version = a.version.as_deref().unwrap_or("");
            ListItem::new(format!("{} {}", a.path, version))
        })
        .collect();

    render_panel(
        f,
        " Artifacts ",
        items,
        cyan_style(),
        &mut app.artifact_state,
        layout[0],
    );

    // Right: detail
    let detail = if let Some(a) = app.selected_artifact() {
        let instance = app
            .selected_instance()
            .map(|i| i.name.as_str())
            .unwrap_or("-");
        let repo = app.selected_repo().map(|r| r.key.as_str()).unwrap_or("-");
        vec![
            detail_line("Path:      ", &a.path),
            detail_line("Version:   ", a.version.as_deref().unwrap_or("-")),
            detail_line("Size:      ", &format_bytes(a.size_bytes)),
            detail_line("Downloads: ", &a.downloads.to_string()),
            detail_line("Created:   ", &a.created),
            Line::from(""),
            detail_line("Instance:  ", instance),
            detail_line("Repo:      ", repo),
        ]
    } else {
        vec![Line::from("No artifact selected")]
    };

    let detail_block = Block::default()
        .title(" Details ")
        .borders(Borders::ALL)
        .border_style(cyan_style());

    let detail_widget = Paragraph::new(detail)
        .block(detail_block)
        .wrap(Wrap { trim: false });

    f.render_widget(detail_widget, layout[1]);
}

fn draw_status_bar(f: &mut Frame, app: &App, area: Rect) {
    let loading_indicator = if app.loading { " [loading] " } else { "" };

    let mut spans: Vec<Span> = Vec::new();
    spans.extend(hotkey_span(" q", "uit"));
    spans.extend(hotkey_span("/", "search"));
    spans.extend(hotkey_span("i", "nfo"));
    spans.extend(hotkey_span("r", "efresh"));
    spans.extend(hotkey_span("?", "help"));
    spans.push(Span::raw(" "));
    spans.push(Span::styled(&app.status_message, dim_style()));
    spans.push(Span::styled(loading_indicator, cyan_style()));

    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_help_overlay(f: &mut Frame, area: Rect) {
    let help_area = centered_rect(60, 70, area);

    let help_text = vec![
        Line::from(Span::styled("Keyboard Shortcuts", hotkey_style())),
        Line::from(""),
        Line::from("  h/Left      Move to left panel"),
        Line::from("  l/Right     Move to right panel"),
        Line::from("  j/Down      Move down in list"),
        Line::from("  k/Up        Move up in list"),
        Line::from("  Enter       Select / expand"),
        Line::from("  Tab         Cycle panels"),
        Line::from(""),
        Line::from("  /           Search artifacts"),
        Line::from("  i           Toggle detail view"),
        Line::from("  r           Refresh data"),
        Line::from("  ?           Toggle this help"),
        Line::from("  q           Quit"),
        Line::from("  Ctrl+C      Quit"),
        Line::from(""),
        Line::from(Span::styled("Press any key to close", dim_style())),
    ];

    let help_block = Block::default()
        .title(" Help ")
        .borders(Borders::ALL)
        .border_style(cyan_style());

    let help = Paragraph::new(help_text)
        .block(help_block)
        .wrap(Wrap { trim: false });

    f.render_widget(Clear, help_area);
    f.render_widget(help, help_area);
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

fn instance_status_color(status: &str) -> Color {
    if status.starts_with("online") {
        Color::Green
    } else if status == "offline" || status == "error" {
        Color::Red
    } else if status == "..." {
        Color::DarkGray
    } else {
        Color::Yellow
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}
