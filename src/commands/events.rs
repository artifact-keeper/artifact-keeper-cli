//! `ak events tail`: the server-sent stream at `GET /api/v1/events/stream`.

use clap::Subcommand;
use futures::StreamExt;
use miette::Result;

use super::client::{raw_http_client, resolve_base_url_and_auth};
use super::helpers::{raw_err, sdk_err};
use crate::cli::GlobalArgs;
use crate::output::OutputFormat;

#[derive(Subcommand)]
pub enum EventsCommand {
    /// Print events as they happen, until you stop it or the server closes the stream.
    /// JSON and YAML print one document per event, as {"event": ..., "data": ...}
    Tail {
        /// Stop after this many `entity.changed` events
        #[arg(long)]
        count: Option<u64>,

        /// Stop after this many seconds
        #[arg(long)]
        max_time: Option<u64>,
    },
}

impl EventsCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Tail { count, max_time } => tail(count, max_time, global).await,
        }
    }
}

/// One event of a server-sent stream.
#[derive(Debug, Default, PartialEq, Eq)]
struct Event {
    name: String,
    data: String,
}

/// Puts a server-sent stream back together from chunks, which can split anywhere.
#[derive(Default)]
struct Parser {
    buffer: Vec<u8>,
    current: Event,
}

impl Parser {
    fn push(&mut self, chunk: &[u8]) -> Vec<Event> {
        self.buffer.extend_from_slice(chunk);
        let mut done = Vec::new();
        while let Some(end) = self.buffer.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = self.buffer.drain(..=end).collect();
            let line = String::from_utf8_lossy(&line);
            let line = line.trim_end_matches(['\r', '\n']);
            if line.is_empty() {
                let event = std::mem::take(&mut self.current);
                if !event.data.is_empty() || !event.name.is_empty() {
                    done.push(event);
                }
                continue;
            }
            // A line starting with a colon is a comment: the server's keep-alive.
            let Some((field, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.strip_prefix(' ').unwrap_or(value);
            match field {
                "event" => self.current.name = value.to_string(),
                "data" => {
                    if !self.current.data.is_empty() {
                        self.current.data.push('\n');
                    }
                    self.current.data.push_str(value);
                }
                _ => {}
            }
        }
        done
    }
}

fn print_event(event: &Event, global: &GlobalArgs) {
    let data: serde_json::Value =
        serde_json::from_str(&event.data).unwrap_or_else(|_| event.data.clone().into());
    match global.format {
        OutputFormat::Quiet => println!("{}", event.data),
        OutputFormat::Table => println!("{}  {}", event.name, event.data),
        OutputFormat::Json => println!(
            "{}",
            serde_json::json!({ "event": event.name, "data": data })
        ),
        OutputFormat::Yaml => print!(
            "---\n{}",
            serde_yaml::to_string(&serde_json::json!({ "event": event.name, "data": data }))
                .unwrap_or_default()
        ),
    }
}

async fn tail(count: Option<u64>, max_time: Option<u64>, global: &GlobalArgs) -> Result<()> {
    let (base_url, auth_header) = resolve_base_url_and_auth(global)?;
    let url = format!("{}/api/v1/events/stream", base_url.trim_end_matches('/'));
    let follow = async {
        let resp = raw_http_client()?
            .get(&url)
            .header(reqwest::header::AUTHORIZATION, auth_header)
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .send()
            .await
            .map_err(|e| sdk_err("connect to the event stream", e))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(raw_err("Failed to connect to the event stream", status, &body).into());
        }

        let mut parser = Parser::default();
        let mut stream = resp.bytes_stream();
        let mut changes = 0;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| sdk_err("read the event stream", e))?;
            for event in parser.push(&chunk) {
                let is_change = event.name == "entity.changed";
                // Quiet means the events and nothing else.
                if is_change || !matches!(global.format, OutputFormat::Quiet) {
                    print_event(&event, global);
                }
                changes += u64::from(is_change);
                if count.is_some_and(|count| changes >= count) {
                    return Ok(());
                }
            }
        }
        eprintln!("The server closed the event stream.");
        Result::<()>::Ok(())
    };
    match max_time {
        Some(seconds) => {
            let limit = std::time::Duration::from_secs(seconds);
            tokio::time::timeout(limit, follow).await.unwrap_or(Ok(()))
        }
        None => follow.await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(name: &str, data: &str) -> Event {
        Event {
            name: name.into(),
            data: data.into(),
        }
    }

    #[test]
    fn an_event_can_arrive_split_across_chunks() {
        let mut parser = Parser::default();
        assert!(parser.push(b"event: entity.cha").is_empty());
        assert!(parser.push(b"nged\ndata: {\"a\"").is_empty());
        assert_eq!(
            parser.push(b":1}\n\nevent: next\ndata: x\n\n"),
            vec![event("entity.changed", "{\"a\":1}"), event("next", "x")]
        );
    }

    #[test]
    fn keep_alive_comments_are_not_events() {
        let mut parser = Parser::default();
        assert!(parser.push(b": ping\n\n").is_empty());
        assert_eq!(parser.push(b"data: x\r\n\r\n"), vec![event("", "x")]);
    }

    #[test]
    fn data_on_several_lines_is_joined() {
        let mut parser = Parser::default();
        assert_eq!(
            parser.push(b"data: a\ndata: b\n\n"),
            vec![event("", "a\nb")]
        );
    }
}
