use std::io;

use artifact_keeper_sdk::types::{
    DashboardResponse, FacetsResponse, FindingResponse, GrowthSummary, PaginationInfo,
    PeerInstanceResponse, RepositoryStorageBreakdown, ScanResponse, SearchResultItem,
    SyncPolicyResponse,
};
use artifact_keeper_sdk::{
    ClientAnalyticsExt, ClientPeersExt, ClientRepositoriesExt, ClientSearchExt, ClientSecurityExt,
};
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

#[derive(Clone, Debug, PartialEq, Eq)]
enum Panel {
    Instances,
    Repos,
    Artifacts,
    Security,
    Replication,
    Analytics,
}

struct InstanceEntry {
    name: String,
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

#[derive(Default)]
struct SecurityState {
    dashboard: Option<DashboardResponse>,
    scans: Vec<ScanResponse>,
    scan_list_state: ListState,
    selected_findings: Vec<FindingResponse>,
    finding_list_state: ListState,
    showing_findings: bool,
}

#[derive(Default)]
struct ReplicationState {
    peers: Vec<PeerInstanceResponse>,
    peer_list_state: ListState,
    policies: Vec<SyncPolicyResponse>,
    loaded: bool,
}

#[derive(Default)]
struct AnalyticsState {
    storage: Vec<RepositoryStorageBreakdown>,
    growth: Option<GrowthSummary>,
    storage_list_state: ListState,
    loaded: bool,
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
    // Global search state (Meilisearch-powered, cross-repo)
    global_searching: bool,
    global_search_query: String,
    global_search_results: Vec<SearchResultItem>,
    global_search_facets: Option<FacetsResponse>,
    global_search_pagination: Option<PaginationInfo>,
    global_search_state: ListState,
    global_search_submitted: bool,
    // Security panel state
    security: SecurityState,
    // Replication panel state
    replication: ReplicationState,
    // Analytics panel state
    analytics: AnalyticsState,
}

impl App {
    fn new(config: AppConfig) -> Self {
        let instances: Vec<InstanceEntry> = config
            .instances
            .keys()
            .map(|name| InstanceEntry {
                name: name.clone(),
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
            global_searching: false,
            global_search_query: String::new(),
            global_search_results: Vec::new(),
            global_search_facets: None,
            global_search_pagination: None,
            global_search_state: ListState::default(),
            global_search_submitted: false,
            security: SecurityState::default(),
            replication: ReplicationState::default(),
            analytics: AnalyticsState::default(),
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
            Panel::Security => {
                if self.security.showing_findings {
                    (
                        &mut self.security.finding_list_state,
                        self.security.selected_findings.len(),
                    )
                } else {
                    (
                        &mut self.security.scan_list_state,
                        self.security.scans.len(),
                    )
                }
            }
            Panel::Replication => (
                &mut self.replication.peer_list_state,
                self.replication.peers.len(),
            ),
            Panel::Analytics => (
                &mut self.analytics.storage_list_state,
                self.analytics.storage.len(),
            ),
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
            Panel::Security => self.active_panel = Panel::Artifacts,
            Panel::Replication => self.active_panel = Panel::Security,
            Panel::Analytics => self.active_panel = Panel::Replication,
        }
    }

    fn move_right(&mut self) {
        match self.active_panel {
            Panel::Instances if !self.repos.is_empty() => self.active_panel = Panel::Repos,
            Panel::Repos if !self.artifacts.is_empty() => self.active_panel = Panel::Artifacts,
            Panel::Artifacts => self.active_panel = Panel::Security,
            Panel::Security => self.active_panel = Panel::Replication,
            Panel::Replication => self.active_panel = Panel::Analytics,
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

    fn exit_global_search(&mut self) {
        self.global_searching = false;
        self.global_search_submitted = false;
        self.global_search_query.clear();
        self.global_search_results.clear();
        self.global_search_facets = None;
        self.global_search_pagination = None;
    }

    async fn global_search(&mut self) {
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
        self.status_message = format!("Searching '{}'...", self.global_search_query);

        match client
            .advanced_search()
            .query(&self.global_search_query)
            .per_page(50)
            .send()
            .await
        {
            Ok(resp) => {
                self.global_search_facets = Some(resp.facets.clone());
                self.global_search_pagination = Some(resp.pagination.clone());
                let total = resp.pagination.total;
                self.global_search_results = resp.items.clone();
                self.global_search_state = ListState::default();
                if !self.global_search_results.is_empty() {
                    self.global_search_state.select(Some(0));
                }
                self.status_message = format!(
                    "{total} results for '{}' on {instance_name}",
                    self.global_search_query
                );
                self.global_search_submitted = true;
            }
            Err(e) => {
                self.status_message = format!("Search failed: {e}");
                self.global_search_results.clear();
                self.global_search_facets = None;
                self.global_search_pagination = None;
            }
        }
        self.loading = false;
    }

    async fn navigate_to_search_result(&mut self) {
        let result = match self
            .global_search_state
            .selected()
            .and_then(|i| self.global_search_results.get(i))
        {
            Some(r) => r.clone(),
            None => return,
        };

        // Find the repo in the loaded repos list
        let repo_idx = self
            .repos
            .iter()
            .position(|r| r.key == result.repository_key);

        if let Some(idx) = repo_idx {
            self.repo_state.select(Some(idx));
            self.search_query = result.name.clone();
            self.load_artifacts().await;

            // Try to select the matching artifact
            if let Some(artifact_idx) = self.artifacts.iter().position(|a| {
                a.path == result.path.as_deref().unwrap_or("") || a.path == result.name
            }) {
                self.artifact_state.select(Some(artifact_idx));
            }
        } else {
            self.status_message = format!(
                "Repo '{}' not in loaded list — select the correct instance",
                result.repository_key
            );
            return;
        }

        self.exit_global_search();
        self.active_panel = Panel::Artifacts;
    }

    async fn load_security_data(&mut self) {
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
        self.status_message = "Loading security dashboard...".to_string();

        if let Ok(resp) = client.get_dashboard().send().await {
            self.security.dashboard = Some(resp.into_inner());
        }

        match client.list_scans().per_page(50).send().await {
            Ok(resp) => {
                let inner = resp.into_inner();
                self.security.scans = inner.items;
                self.security.scan_list_state = ListState::default();
                if !self.security.scans.is_empty() {
                    self.security.scan_list_state.select(Some(0));
                }
                self.status_message =
                    format!("{} scans on {instance_name}", self.security.scans.len());
            }
            Err(e) => {
                self.status_message = format!("Failed to load scans: {e}");
                self.security.scans.clear();
            }
        }

        self.loading = false;
    }

    async fn load_replication_data(&mut self) {
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
        self.status_message = "Loading replication data...".to_string();

        match client.list_peers().per_page(50).send().await {
            Ok(resp) => {
                let inner = resp.into_inner();
                self.replication.peers = inner.items;
                self.replication.peer_list_state = ListState::default();
                if !self.replication.peers.is_empty() {
                    self.replication.peer_list_state.select(Some(0));
                }
            }
            Err(e) => {
                self.status_message = format!("Failed to load peers: {e}");
                self.replication.peers.clear();
            }
        }

        if let Ok(resp) = client.list_sync_policies().send().await {
            let inner = resp.into_inner();
            self.replication.policies = inner.items;
        }

        self.replication.loaded = true;
        let peer_count = self.replication.peers.len();
        let policy_count = self.replication.policies.len();
        self.status_message =
            format!("{peer_count} peers, {policy_count} sync policies on {instance_name}");
        self.loading = false;
    }

    async fn load_analytics_data(&mut self) {
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
        self.status_message = "Loading analytics data...".to_string();

        match client.get_storage_breakdown().send().await {
            Ok(resp) => {
                self.analytics.storage = resp.into_inner();
                self.analytics.storage_list_state = ListState::default();
                if !self.analytics.storage.is_empty() {
                    self.analytics.storage_list_state.select(Some(0));
                }
            }
            Err(e) => {
                self.status_message = format!("Failed to load storage breakdown: {e}");
                self.analytics.storage.clear();
            }
        }

        if let Ok(resp) = client.get_growth_summary().send().await {
            self.analytics.growth = Some(resp.into_inner());
        }

        self.analytics.loaded = true;
        let repo_count = self.analytics.storage.len();
        self.status_message =
            format!("{repo_count} repositories in storage breakdown on {instance_name}");
        self.loading = false;
    }

    async fn load_findings(&mut self) {
        let scan_id = match self
            .security
            .scan_list_state
            .selected()
            .and_then(|i| self.security.scans.get(i))
        {
            Some(scan) => scan.id,
            None => return,
        };

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
        self.status_message = "Loading findings...".to_string();

        match client.list_findings().id(scan_id).per_page(50).send().await {
            Ok(resp) => {
                let inner = resp.into_inner();
                self.security.selected_findings = inner.items;
                self.security.finding_list_state = ListState::default();
                if !self.security.selected_findings.is_empty() {
                    self.security.finding_list_state.select(Some(0));
                }
                self.security.showing_findings = true;
                self.status_message =
                    format!("{} findings in scan", self.security.selected_findings.len());
            }
            Err(e) => {
                self.status_message = format!("Failed to load findings: {e}");
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

        // Global search: typing query
        if app.global_searching && !app.global_search_submitted {
            match key.code {
                KeyCode::Enter => {
                    if !app.global_search_query.is_empty() {
                        app.global_search().await;
                    }
                }
                KeyCode::Esc => app.exit_global_search(),
                KeyCode::Backspace => {
                    app.global_search_query.pop();
                }
                KeyCode::Char(c) => app.global_search_query.push(c),
                _ => {}
            }
            continue;
        }

        // Global search: navigating results
        if app.global_searching && app.global_search_submitted {
            match key.code {
                KeyCode::Esc => app.exit_global_search(),
                KeyCode::Char('j') | KeyCode::Down => {
                    let len = app.global_search_results.len();
                    list_next(&mut app.global_search_state, len);
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    let len = app.global_search_results.len();
                    list_prev(&mut app.global_search_state, len);
                }
                KeyCode::Enter => app.navigate_to_search_result().await,
                KeyCode::Char('/') => {
                    app.global_search_submitted = false;
                    app.global_search_query.clear();
                }
                KeyCode::Char('q') | KeyCode::Char('Q') => app.exit_global_search(),
                _ => {}
            }
            continue;
        }

        // Per-repo search: typing filter
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
                let next = match app.active_panel {
                    Panel::Instances => Panel::Repos,
                    Panel::Repos => Panel::Artifacts,
                    Panel::Artifacts => Panel::Security,
                    Panel::Security => Panel::Replication,
                    Panel::Replication => Panel::Analytics,
                    Panel::Analytics => Panel::Instances,
                };
                if next == Panel::Security && app.security.dashboard.is_none() {
                    app.active_panel = next;
                    app.load_security_data().await;
                } else if next == Panel::Replication && !app.replication.loaded {
                    app.active_panel = next;
                    app.load_replication_data().await;
                } else if next == Panel::Analytics && !app.analytics.loaded {
                    app.active_panel = next;
                    app.load_analytics_data().await;
                } else {
                    app.active_panel = next;
                }
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
                Panel::Security => {
                    if !app.security.showing_findings {
                        app.load_findings().await;
                    }
                }
                Panel::Replication => {}
                Panel::Analytics => {}
            },
            KeyCode::Esc => {
                if app.active_panel == Panel::Security && app.security.showing_findings {
                    app.security.showing_findings = false;
                    app.security.selected_findings.clear();
                    app.security.finding_list_state = ListState::default();
                    app.status_message = format!("{} scans loaded", app.security.scans.len());
                }
            }
            KeyCode::Char('4') => {
                if app.security.dashboard.is_none() {
                    app.active_panel = Panel::Security;
                    app.load_security_data().await;
                } else {
                    app.active_panel = Panel::Security;
                }
            }
            KeyCode::Char('5') => {
                if !app.replication.loaded {
                    app.active_panel = Panel::Replication;
                    app.load_replication_data().await;
                } else {
                    app.active_panel = Panel::Replication;
                }
            }
            KeyCode::Char('6') => {
                if !app.analytics.loaded {
                    app.active_panel = Panel::Analytics;
                    app.load_analytics_data().await;
                } else {
                    app.active_panel = Panel::Analytics;
                }
            }
            KeyCode::Char('s') | KeyCode::Char('S') => {
                app.global_searching = true;
                app.global_search_submitted = false;
                app.global_search_query.clear();
            }
            KeyCode::Char('r') => {
                app.check_instance_health().await;
                if app.active_panel == Panel::Repos || app.active_panel == Panel::Artifacts {
                    app.load_repos().await;
                }
                if app.active_panel == Panel::Security {
                    app.security.dashboard = None;
                    app.load_security_data().await;
                }
                if app.active_panel == Panel::Replication {
                    app.replication.loaded = false;
                    app.load_replication_data().await;
                }
                if app.active_panel == Panel::Analytics {
                    app.analytics.loaded = false;
                    app.load_analytics_data().await;
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

    if app.global_searching {
        draw_global_search(f, app, main_layout[0]);
    } else if app.active_panel == Panel::Security {
        draw_security_panel(f, app, main_layout[0]);
    } else if app.active_panel == Panel::Replication {
        draw_replication_panel(f, app, main_layout[0]);
    } else if app.active_panel == Panel::Analytics {
        draw_analytics_panel(f, app, main_layout[0]);
    } else if app.detail_view {
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

    if app.global_searching && app.global_search_submitted {
        spans.extend(hotkey_span(" Esc", " back"));
        spans.extend(hotkey_span("Enter", " go to"));
        spans.extend(hotkey_span("/", " new search"));
        spans.extend(hotkey_span("j/k", " navigate"));
    } else if app.global_searching {
        spans.extend(hotkey_span(" Enter", " search"));
        spans.extend(hotkey_span("Esc", " cancel"));
    } else if app.active_panel == Panel::Security {
        spans.extend(hotkey_span(" q", "uit"));
        if app.security.showing_findings {
            spans.extend(hotkey_span("Esc", " back to scans"));
        } else {
            spans.extend(hotkey_span("Enter", " view findings"));
        }
        spans.extend(hotkey_span("Tab", " next panel"));
        spans.extend(hotkey_span("r", "efresh"));
        spans.extend(hotkey_span("?", "help"));
    } else if app.active_panel == Panel::Replication || app.active_panel == Panel::Analytics {
        spans.extend(hotkey_span(" q", "uit"));
        spans.extend(hotkey_span("Tab", " next panel"));
        spans.extend(hotkey_span("r", "efresh"));
        spans.extend(hotkey_span("?", "help"));
    } else {
        spans.extend(hotkey_span(" q", "uit"));
        spans.extend(hotkey_span("s", " search all"));
        spans.extend(hotkey_span("/", " filter"));
        spans.extend(hotkey_span("i", "nfo"));
        spans.extend(hotkey_span("r", "efresh"));
        spans.extend(hotkey_span("?", "help"));
    }

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
        Line::from("  Enter       Select / expand / drill into findings"),
        Line::from("  Esc         Back (findings to scans)"),
        Line::from("  Tab         Cycle panels (1-6)"),
        Line::from("  4           Jump to Security panel"),
        Line::from("  5           Jump to Replication panel"),
        Line::from("  6           Jump to Analytics panel"),
        Line::from(""),
        Line::from("  s           Global search (all repos)"),
        Line::from("  /           Filter artifacts in repo"),
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
// Global search drawing
// ---------------------------------------------------------------------------

fn draw_global_search(f: &mut Frame, app: &mut App, area: Rect) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(28), Constraint::Min(40)])
        .split(area);

    draw_facets_panel(f, app, columns[0]);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(5)])
        .split(columns[1]);

    draw_search_input(f, app, right[0]);
    draw_search_results(f, app, right[1]);
}

fn draw_search_input(f: &mut Frame, app: &App, area: Rect) {
    let cursor = if !app.global_search_submitted {
        "_"
    } else {
        ""
    };
    let input_text = format!("{}{cursor}", app.global_search_query);

    let block = Block::default()
        .title(" Global Search (Esc to close) ")
        .borders(Borders::ALL)
        .border_style(cyan_style());

    let paragraph = Paragraph::new(Line::from(vec![
        Span::styled("Search: ", bold_style()),
        Span::raw(input_text),
    ]))
    .block(block);

    f.render_widget(paragraph, area);
}

fn draw_search_results(f: &mut Frame, app: &mut App, area: Rect) {
    if !app.global_search_submitted {
        let block = Block::default()
            .title(" Results ")
            .borders(Borders::ALL)
            .border_style(dim_style());
        let msg = Paragraph::new("Type a query and press Enter to search across all repositories.")
            .block(block)
            .wrap(Wrap { trim: false });
        f.render_widget(msg, area);
        return;
    }

    if app.global_search_results.is_empty() {
        let block = Block::default()
            .title(" Results ")
            .borders(Borders::ALL)
            .border_style(dim_style());
        let msg = Paragraph::new("No results found.")
            .block(block)
            .wrap(Wrap { trim: false });
        f.render_widget(msg, area);
        return;
    }

    let total = app
        .global_search_pagination
        .as_ref()
        .map(|p| p.total)
        .unwrap_or(app.global_search_results.len() as i64);

    let title = format!(" Results ({total} total) ");

    let items: Vec<ListItem> = app
        .global_search_results
        .iter()
        .map(|r| {
            let format_str = r.format.as_deref().unwrap_or("?");
            let version_str = r.version.as_deref().unwrap_or("");
            let size_str = r.size_bytes.map(format_bytes).unwrap_or_default();

            ListItem::new(Line::from(vec![
                Span::raw(&r.name),
                Span::raw("  "),
                Span::styled(&r.repository_key, Style::default().fg(Color::Green)),
                Span::raw("  "),
                Span::styled(format_str, Style::default().fg(Color::Magenta)),
                Span::raw("  "),
                Span::styled(version_str, Style::default().fg(Color::Yellow)),
                Span::raw("  "),
                Span::styled(size_str, dim_style()),
            ]))
        })
        .collect();

    render_panel(
        f,
        &title,
        items,
        cyan_style(),
        &mut app.global_search_state,
        area,
    );
}

fn draw_facets_panel(f: &mut Frame, app: &App, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();

    if let Some(ref facets) = app.global_search_facets {
        lines.push(Line::from(Span::styled("Formats", bold_style())));
        for fv in facets.formats.iter().take(8) {
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(&fv.value, Style::default().fg(Color::Magenta)),
                Span::raw(" "),
                Span::styled(format!("({})", fv.count), dim_style()),
            ]));
        }

        lines.push(Line::from(""));

        lines.push(Line::from(Span::styled("Repositories", bold_style())));
        for fv in facets.repositories.iter().take(8) {
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(&fv.value, Style::default().fg(Color::Green)),
                Span::raw(" "),
                Span::styled(format!("({})", fv.count), dim_style()),
            ]));
        }

        if !facets.content_types.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled("Content Types", bold_style())));
            for fv in facets.content_types.iter().take(5) {
                lines.push(Line::from(vec![
                    Span::raw("  "),
                    Span::raw(&fv.value),
                    Span::raw(" "),
                    Span::styled(format!("({})", fv.count), dim_style()),
                ]));
            }
        }
    } else {
        lines.push(Line::from(Span::styled(
            "Facets appear after search",
            dim_style(),
        )));
    }

    let block = Block::default()
        .title(" Facets ")
        .borders(Borders::ALL)
        .border_style(dim_style());

    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });

    f.render_widget(paragraph, area);
}

// ---------------------------------------------------------------------------
// Security panel drawing
// ---------------------------------------------------------------------------

fn severity_style(severity: &str) -> Style {
    match severity.to_uppercase().as_str() {
        "CRITICAL" => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        "HIGH" => Style::default().fg(Color::Red),
        "MEDIUM" => Style::default().fg(Color::Yellow),
        _ => dim_style(), // LOW, INFO, UNKNOWN
    }
}

fn draw_security_panel(f: &mut Frame, app: &mut App, area: Rect) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(5)])
        .split(area);

    // Dashboard summary bar
    draw_security_dashboard(f, app, layout[0]);

    if app.security.showing_findings {
        draw_findings_list(f, app, layout[1]);
    } else {
        draw_scan_list(f, app, layout[1]);
    }
}

fn draw_security_dashboard(f: &mut Frame, app: &App, area: Rect) {
    let spans = if let Some(ref dash) = app.security.dashboard {
        let medium = dash
            .total_findings
            .saturating_sub(dash.critical_findings)
            .saturating_sub(dash.high_findings);

        vec![
            Span::styled(" Scans: ", bold_style()),
            Span::raw(format!("{}", dash.total_scans)),
            Span::raw("  "),
            Span::styled("Findings: ", bold_style()),
            Span::raw(format!("{}", dash.total_findings)),
            Span::raw(" ("),
            Span::styled(
                format!("C:{}", dash.critical_findings),
                severity_style("CRITICAL"),
            ),
            Span::raw(" "),
            Span::styled(format!("H:{}", dash.high_findings), severity_style("HIGH")),
            Span::raw(" "),
            Span::styled(format!("M:{medium}"), severity_style("MEDIUM")),
            Span::raw(")  "),
            Span::styled("Grade A: ", bold_style()),
            Span::styled(
                format!("{}", dash.repos_grade_a),
                Style::default().fg(Color::Green),
            ),
            Span::raw("  "),
            Span::styled("Grade F: ", bold_style()),
            Span::styled(
                format!("{}", dash.repos_grade_f),
                Style::default().fg(Color::Red),
            ),
        ]
    } else {
        vec![Span::styled("Loading dashboard...", dim_style())]
    };

    let block = Block::default()
        .title(" Security Dashboard ")
        .borders(Borders::ALL)
        .border_style(cyan_style());

    let paragraph = Paragraph::new(Line::from(spans)).block(block);
    f.render_widget(paragraph, area);
}

fn draw_scan_list(f: &mut Frame, app: &mut App, area: Rect) {
    if app.security.scans.is_empty() {
        let block = Block::default()
            .title(" Scans ")
            .borders(Borders::ALL)
            .border_style(cyan_style());
        let msg = Paragraph::new("No scans found. Run `ak scan run` to start a scan.")
            .block(block)
            .wrap(Wrap { trim: false });
        f.render_widget(msg, area);
        return;
    }

    let title = format!(
        " Scans ({}) - Enter to view findings ",
        app.security.scans.len()
    );

    let items: Vec<ListItem> = app
        .security
        .scans
        .iter()
        .map(|scan| {
            let name = scan.artifact_name.as_deref().unwrap_or("unknown");
            let date = scan.created_at.format("%Y-%m-%d %H:%M");

            let mut spans = vec![
                Span::raw(format!("{name}  ")),
                Span::styled(&scan.scan_type, Style::default().fg(Color::Magenta)),
                Span::raw("  "),
                Span::styled(
                    &scan.status,
                    match scan.status.as_str() {
                        "completed" => Style::default().fg(Color::Green),
                        "failed" => Style::default().fg(Color::Red),
                        "running" | "pending" => Style::default().fg(Color::Yellow),
                        _ => dim_style(),
                    },
                ),
                Span::raw("  "),
            ];

            if scan.critical_count > 0 {
                spans.push(Span::styled(
                    format!("C:{} ", scan.critical_count),
                    severity_style("CRITICAL"),
                ));
            }
            if scan.high_count > 0 {
                spans.push(Span::styled(
                    format!("H:{} ", scan.high_count),
                    severity_style("HIGH"),
                ));
            }
            if scan.medium_count > 0 {
                spans.push(Span::styled(
                    format!("M:{} ", scan.medium_count),
                    severity_style("MEDIUM"),
                ));
            }
            if scan.low_count > 0 {
                spans.push(Span::styled(format!("L:{} ", scan.low_count), dim_style()));
            }

            spans.push(Span::styled(format!("  {date}"), dim_style()));

            ListItem::new(Line::from(spans))
        })
        .collect();

    render_panel(
        f,
        &title,
        items,
        cyan_style(),
        &mut app.security.scan_list_state,
        area,
    );
}

fn draw_findings_list(f: &mut Frame, app: &mut App, area: Rect) {
    if app.security.selected_findings.is_empty() {
        let block = Block::default()
            .title(" Findings (Esc to go back) ")
            .borders(Borders::ALL)
            .border_style(cyan_style());
        let msg = Paragraph::new("No findings in this scan.")
            .block(block)
            .wrap(Wrap { trim: false });
        f.render_widget(msg, area);
        return;
    }

    let title = format!(
        " Findings ({}) - Esc to go back ",
        app.security.selected_findings.len()
    );

    let items: Vec<ListItem> = app
        .security
        .selected_findings
        .iter()
        .map(|finding| {
            let sev = &finding.severity;
            let cve = finding.cve_id.as_deref().unwrap_or("");
            let component = finding.affected_component.as_deref().unwrap_or("");
            let fixed = finding
                .fixed_version
                .as_deref()
                .map(|v| format!(" (fix: {v})"))
                .unwrap_or_default();

            ListItem::new(Line::from(vec![
                Span::styled(format!("{sev:<8} "), severity_style(sev)),
                Span::raw(format!("{cve:<16} ")),
                Span::raw(&finding.title),
                Span::raw("  "),
                Span::styled(component, dim_style()),
                Span::styled(fixed, Style::default().fg(Color::Green)),
            ]))
        })
        .collect();

    render_panel(
        f,
        &title,
        items,
        cyan_style(),
        &mut app.security.finding_list_state,
        area,
    );
}

// ---------------------------------------------------------------------------
// Replication panel drawing
// ---------------------------------------------------------------------------

fn peer_status_style(status: &str) -> Style {
    match status.to_lowercase().as_str() {
        "online" | "active" | "connected" => Style::default().fg(Color::Green),
        "offline" | "disconnected" => Style::default().fg(Color::Red),
        "syncing" => Style::default().fg(Color::Yellow),
        _ => dim_style(),
    }
}

fn draw_replication_panel(f: &mut Frame, app: &mut App, area: Rect) {
    let layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // Left: peer list
    if app.replication.peers.is_empty() {
        let block = Block::default()
            .title(" Peers ")
            .borders(Borders::ALL)
            .border_style(cyan_style());
        let msg = Paragraph::new("No peers found. Run `ak peer register` to add a peer.")
            .block(block)
            .wrap(Wrap { trim: false });
        f.render_widget(msg, layout[0]);
    } else {
        let title = format!(" Peers ({}) ", app.replication.peers.len());
        let items: Vec<ListItem> = app
            .replication
            .peers
            .iter()
            .map(|peer| {
                let cache_pct = if peer.cache_usage_percent > 0.0 {
                    format!(" {:.0}%", peer.cache_usage_percent)
                } else {
                    String::new()
                };
                let region = peer
                    .region
                    .as_deref()
                    .map(|r| format!(" [{r}]"))
                    .unwrap_or_default();

                ListItem::new(Line::from(vec![
                    Span::raw(&peer.name),
                    Span::raw("  "),
                    Span::styled(&peer.status, peer_status_style(&peer.status)),
                    Span::styled(region, Style::default().fg(Color::Magenta)),
                    Span::styled(cache_pct, dim_style()),
                ]))
            })
            .collect();

        render_panel(
            f,
            &title,
            items,
            cyan_style(),
            &mut app.replication.peer_list_state,
            layout[0],
        );
    }

    // Right: sync policies
    let mut lines: Vec<Line> = Vec::new();

    lines.push(Line::from(Span::styled("Sync Policies", bold_style())));
    lines.push(Line::from(""));

    if app.replication.policies.is_empty() {
        lines.push(Line::from(Span::styled(
            "No sync policies configured.",
            dim_style(),
        )));
    } else {
        for policy in &app.replication.policies {
            let enabled = if policy.enabled { "ON" } else { "OFF" };
            let enabled_style = if policy.enabled {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::Red)
            };
            let mode = &policy.replication_mode;

            lines.push(Line::from(vec![
                Span::styled(&policy.name, bold_style()),
                Span::raw("  "),
                Span::styled(enabled, enabled_style),
                Span::raw("  "),
                Span::styled(mode, Style::default().fg(Color::Magenta)),
                Span::raw(format!("  pri:{}", policy.priority)),
            ]));

            if !policy.description.is_empty() {
                lines.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(&policy.description, dim_style()),
                ]));
            }
        }
    }

    // Show selected peer detail below policies
    if let Some(idx) = app.replication.peer_list_state.selected() {
        if let Some(peer) = app.replication.peers.get(idx) {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled("Selected Peer", bold_style())));
            lines.push(detail_line("  Name:     ", &peer.name));
            lines.push(detail_line("  Endpoint: ", &peer.endpoint_url));
            lines.push(detail_line("  Status:   ", &peer.status));

            if let Some(ref region) = peer.region {
                lines.push(detail_line("  Region:   ", region));
            }
            if peer.cache_size_bytes > 0 {
                lines.push(detail_line(
                    "  Cache:    ",
                    &format!(
                        "{} / {}",
                        format_bytes(peer.cache_used_bytes),
                        format_bytes(peer.cache_size_bytes)
                    ),
                ));
            }
            if let Some(ref ts) = peer.last_sync_at {
                lines.push(detail_line(
                    "  Last sync: ",
                    &ts.format("%Y-%m-%d %H:%M").to_string(),
                ));
            }
        }
    }

    let block = Block::default()
        .title(" Policies & Details ")
        .borders(Borders::ALL)
        .border_style(dim_style());

    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });

    f.render_widget(paragraph, layout[1]);
}

// ---------------------------------------------------------------------------
// Analytics panel drawing
// ---------------------------------------------------------------------------

fn draw_analytics_panel(f: &mut Frame, app: &mut App, area: Rect) {
    let layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // Left: storage breakdown list
    if app.analytics.storage.is_empty() {
        let block = Block::default()
            .title(" Storage Breakdown ")
            .borders(Borders::ALL)
            .border_style(cyan_style());
        let msg = Paragraph::new("No storage data available.")
            .block(block)
            .wrap(Wrap { trim: false });
        f.render_widget(msg, layout[0]);
    } else {
        let title = format!(" Storage Breakdown ({}) ", app.analytics.storage.len());
        let items: Vec<ListItem> = app
            .analytics
            .storage
            .iter()
            .map(|entry| {
                ListItem::new(Line::from(vec![
                    Span::raw(&entry.repository_name),
                    Span::raw("  "),
                    Span::styled(format_bytes(entry.storage_bytes), cyan_style()),
                    Span::raw("  "),
                    Span::styled(format!("{} artifacts", entry.artifact_count), dim_style()),
                    Span::raw("  "),
                    Span::styled(&entry.format, Style::default().fg(Color::Magenta)),
                ]))
            })
            .collect();

        render_panel(
            f,
            &title,
            items,
            cyan_style(),
            &mut app.analytics.storage_list_state,
            layout[0],
        );
    }

    // Right: growth summary + selected repo detail
    let mut lines: Vec<Line> = Vec::new();

    lines.push(Line::from(Span::styled("Growth Summary", bold_style())));
    lines.push(Line::from(""));

    if let Some(ref growth) = app.analytics.growth {
        lines.push(detail_line(
            "  Period:         ",
            &format!("{} to {}", growth.period_start, growth.period_end),
        ));
        lines.push(detail_line(
            "  Storage Start:  ",
            &format_bytes(growth.storage_bytes_start),
        ));
        lines.push(detail_line(
            "  Storage End:    ",
            &format_bytes(growth.storage_bytes_end),
        ));
        lines.push(detail_line(
            "  Growth:         ",
            &format!(
                "{} ({:.1}%)",
                format_bytes(growth.storage_growth_bytes),
                growth.storage_growth_percent
            ),
        ));
        lines.push(Line::from(""));
        lines.push(detail_line(
            "  Artifacts Start: ",
            &growth.artifacts_start.to_string(),
        ));
        lines.push(detail_line(
            "  Artifacts End:   ",
            &growth.artifacts_end.to_string(),
        ));
        lines.push(detail_line(
            "  Artifacts Added: ",
            &growth.artifacts_added.to_string(),
        ));
        lines.push(detail_line(
            "  Downloads:       ",
            &growth.downloads_in_period.to_string(),
        ));
    } else {
        lines.push(Line::from(Span::styled(
            "  No growth data available.",
            dim_style(),
        )));
    }

    // Show selected storage entry detail
    if let Some(idx) = app.analytics.storage_list_state.selected() {
        if let Some(entry) = app.analytics.storage.get(idx) {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Selected Repository",
                bold_style(),
            )));
            lines.push(detail_line("  Name:       ", &entry.repository_name));
            lines.push(detail_line("  Key:        ", &entry.repository_key));
            lines.push(detail_line("  Format:     ", &entry.format));
            lines.push(detail_line(
                "  Storage:    ",
                &format_bytes(entry.storage_bytes),
            ));
            lines.push(detail_line(
                "  Artifacts:  ",
                &entry.artifact_count.to_string(),
            ));
            lines.push(detail_line(
                "  Downloads:  ",
                &entry.download_count.to_string(),
            ));
            if let Some(ref ts) = entry.last_upload_at {
                lines.push(detail_line(
                    "  Last Upload: ",
                    &ts.format("%Y-%m-%d %H:%M").to_string(),
                ));
            }
        }
    }

    let block = Block::default()
        .title(" Growth & Details ")
        .borders(Borders::ALL)
        .border_style(dim_style());

    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });

    f.render_widget(paragraph, layout[1]);
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

fn instance_status_color(status: &str) -> Color {
    match status {
        s if s.starts_with("online") => Color::Green,
        "offline" | "error" => Color::Red,
        "..." => Color::DarkGray,
        _ => Color::Yellow,
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

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // peer_status_style
    // -----------------------------------------------------------------------

    #[test]
    fn peer_status_style_online_is_green() {
        assert_eq!(peer_status_style("online").fg, Some(Color::Green));
    }

    #[test]
    fn peer_status_style_active_is_green() {
        assert_eq!(peer_status_style("active").fg, Some(Color::Green));
    }

    #[test]
    fn peer_status_style_connected_is_green() {
        assert_eq!(peer_status_style("connected").fg, Some(Color::Green));
    }

    #[test]
    fn peer_status_style_offline_is_red() {
        assert_eq!(peer_status_style("offline").fg, Some(Color::Red));
    }

    #[test]
    fn peer_status_style_disconnected_is_red() {
        assert_eq!(peer_status_style("disconnected").fg, Some(Color::Red));
    }

    #[test]
    fn peer_status_style_syncing_is_yellow() {
        assert_eq!(peer_status_style("syncing").fg, Some(Color::Yellow));
    }

    #[test]
    fn peer_status_style_unknown_is_dim() {
        assert_eq!(peer_status_style("unknown").fg, Some(Color::DarkGray));
    }

    #[test]
    fn peer_status_style_case_insensitive() {
        assert_eq!(peer_status_style("ONLINE").fg, Some(Color::Green));
        assert_eq!(peer_status_style("Offline").fg, Some(Color::Red));
        assert_eq!(peer_status_style("SYNCING").fg, Some(Color::Yellow));
    }

    // -----------------------------------------------------------------------
    // instance_status_color
    // -----------------------------------------------------------------------

    #[test]
    fn instance_status_online_is_green() {
        assert_eq!(instance_status_color("online (5 repos)"), Color::Green);
    }

    #[test]
    fn instance_status_offline_is_red() {
        assert_eq!(instance_status_color("offline"), Color::Red);
    }

    #[test]
    fn instance_status_error_is_red() {
        assert_eq!(instance_status_color("error"), Color::Red);
    }

    #[test]
    fn instance_status_loading_is_dark_gray() {
        assert_eq!(instance_status_color("..."), Color::DarkGray);
    }

    #[test]
    fn instance_status_other_is_yellow() {
        assert_eq!(instance_status_color("connecting"), Color::Yellow);
    }

    // -----------------------------------------------------------------------
    // severity_style
    // -----------------------------------------------------------------------

    #[test]
    fn severity_critical_is_bold_red() {
        let s = severity_style("CRITICAL");
        assert_eq!(s.fg, Some(Color::Red));
        assert!(s.add_modifier.contains(Modifier::BOLD));
    }

    #[test]
    fn severity_high_is_red() {
        assert_eq!(severity_style("HIGH").fg, Some(Color::Red));
    }

    #[test]
    fn severity_medium_is_yellow() {
        assert_eq!(severity_style("MEDIUM").fg, Some(Color::Yellow));
    }

    #[test]
    fn severity_low_is_dim() {
        assert_eq!(severity_style("LOW").fg, Some(Color::DarkGray));
    }

    #[test]
    fn severity_case_insensitive() {
        assert_eq!(severity_style("critical").fg, Some(Color::Red));
        assert_eq!(severity_style("high").fg, Some(Color::Red));
        assert_eq!(severity_style("medium").fg, Some(Color::Yellow));
    }

    // -----------------------------------------------------------------------
    // Panel navigation
    // -----------------------------------------------------------------------

    #[test]
    fn panel_equality() {
        assert_eq!(Panel::Instances, Panel::Instances);
        assert_eq!(Panel::Replication, Panel::Replication);
        assert_ne!(Panel::Instances, Panel::Replication);
    }

    // -----------------------------------------------------------------------
    // List navigation helpers
    // -----------------------------------------------------------------------

    #[test]
    fn list_next_empty() {
        let mut state = ListState::default();
        list_next(&mut state, 0);
        assert_eq!(state.selected(), None);
    }

    #[test]
    fn list_next_advances() {
        let mut state = ListState::default();
        state.select(Some(0));
        list_next(&mut state, 5);
        assert_eq!(state.selected(), Some(1));
    }

    #[test]
    fn list_next_clamps_at_end() {
        let mut state = ListState::default();
        state.select(Some(4));
        list_next(&mut state, 5);
        assert_eq!(state.selected(), Some(4));
    }

    #[test]
    fn list_next_from_none() {
        let mut state = ListState::default();
        list_next(&mut state, 3);
        assert_eq!(state.selected(), Some(0));
    }

    #[test]
    fn list_prev_empty() {
        let mut state = ListState::default();
        list_prev(&mut state, 0);
        assert_eq!(state.selected(), None);
    }

    #[test]
    fn list_prev_moves_back() {
        let mut state = ListState::default();
        state.select(Some(3));
        list_prev(&mut state, 5);
        assert_eq!(state.selected(), Some(2));
    }

    #[test]
    fn list_prev_clamps_at_zero() {
        let mut state = ListState::default();
        state.select(Some(0));
        list_prev(&mut state, 5);
        assert_eq!(state.selected(), Some(0));
    }

    // -----------------------------------------------------------------------
    // Style helpers
    // -----------------------------------------------------------------------

    #[test]
    fn bold_style_has_bold_modifier() {
        assert!(bold_style().add_modifier.contains(Modifier::BOLD));
    }

    #[test]
    fn hotkey_style_is_yellow_bold() {
        let s = hotkey_style();
        assert_eq!(s.fg, Some(Color::Yellow));
        assert!(s.add_modifier.contains(Modifier::BOLD));
    }

    #[test]
    fn dim_style_is_dark_gray() {
        assert_eq!(dim_style().fg, Some(Color::DarkGray));
    }

    #[test]
    fn cyan_style_is_cyan() {
        assert_eq!(cyan_style().fg, Some(Color::Cyan));
    }

    #[test]
    fn highlight_style_has_dark_gray_bg() {
        let s = highlight_style();
        assert_eq!(s.bg, Some(Color::DarkGray));
        assert!(s.add_modifier.contains(Modifier::BOLD));
    }

    #[test]
    fn panel_border_active_is_cyan() {
        let s = panel_border_style(&Panel::Repos, &Panel::Repos);
        assert_eq!(s.fg, Some(Color::Cyan));
    }

    #[test]
    fn panel_border_inactive_is_dim() {
        let s = panel_border_style(&Panel::Repos, &Panel::Artifacts);
        assert_eq!(s.fg, Some(Color::DarkGray));
    }
}
