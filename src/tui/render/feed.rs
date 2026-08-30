// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Single-line, horizontally scrollable access and runtime feeds.

use ratatui::prelude::*;
use ratatui::widgets::Paragraph;

use crate::tui::format;
use crate::tui::model::{
    AccessPhase, AccessRecord, AccessStatus, App, EventLevel, FeedKind, Focus, RuntimeRecord,
    access_matches, runtime_matches,
};

use super::{accent, dim, palette, panel, render_empty};

pub(super) fn render_specific_feed(frame: &mut Frame<'_>, area: Rect, app: &App, feed: FeedKind) {
    let empty_title = match feed {
        FeedKind::Access => " ACCESS ",
        FeedKind::Runtime => " RUNTIME ",
    };
    let focused = app.focus == Focus::Feed && app.feed == feed;
    let Some(instance) = app.selected() else {
        render_empty(frame, area, empty_title, "No events", app);
        return;
    };
    let filter = app.filter.to_ascii_lowercase();
    let visible = usize::from(area.height.saturating_sub(2)).max(1);
    let vertical_scroll = if app.feed == feed { app.feed_scroll } else { 0 };
    let horizontal_scroll = app.feed_horizontal_scroll(feed);
    let paused = app.paused && app.feed == feed;
    let (lines, total, matched) = match feed {
        FeedKind::Access => {
            let records = instance
                .access
                .iter()
                .filter(|record| access_matches(record, &filter))
                .collect::<Vec<_>>();
            let matched = records.len();
            let lines = visible_tail(records, vertical_scroll, visible)
                .into_iter()
                .map(|record| access_line(record, app))
                .collect::<Vec<_>>();
            (lines, instance.access.len(), matched)
        }
        FeedKind::Runtime => {
            let records = instance
                .runtime
                .iter()
                .filter(|record| runtime_matches(record, &filter))
                .collect::<Vec<_>>();
            let matched = records.len();
            let lines = visible_tail(records, vertical_scroll, visible)
                .into_iter()
                .map(|record| runtime_line(record, app))
                .collect::<Vec<_>>();
            (lines, instance.runtime.len(), matched)
        }
    };
    let label = match feed {
        FeedKind::Access => "ACCESS",
        FeedKind::Runtime => "RUNTIME",
    };
    let title = if app.filter.is_empty() {
        format!(" {label} · {total} ")
    } else {
        format!(" {label} · {matched}/{total} ")
    };
    let pan = if focused && horizontal_scroll != 0 {
        format!(" · x+{horizontal_scroll}")
    } else {
        String::new()
    };
    let block = panel(&title, focused, app).title_bottom(Line::from(format!(
        " {}{}{pan} ",
        if paused { "PAUSED · " } else { "" },
        if app.filter.is_empty() {
            "all".to_owned()
        } else {
            format!("filter={}", app.filter)
        }
    )));
    if lines.is_empty() {
        frame.render_widget(
            Paragraph::new("No matching events")
                .alignment(Alignment::Center)
                .style(dim(app))
                .block(block),
            area,
        );
    } else {
        frame.render_widget(
            Paragraph::new(lines)
                .scroll((0, u16::try_from(horizontal_scroll).unwrap_or(u16::MAX)))
                .block(block),
            area,
        );
    }
}

fn visible_tail<T>(records: Vec<&T>, scroll: usize, visible: usize) -> Vec<&T> {
    let end = records.len().saturating_sub(scroll.min(records.len()));
    let start = end.saturating_sub(visible);
    records[start..end].to_vec()
}

fn access_line(record: &AccessRecord, app: &App) -> Line<'static> {
    let (status, status_color) = match (record.phase, record.status) {
        (AccessPhase::Start, _) => ("LIVE", palette::INFO),
        (_, Some(AccessStatus::Success)) => ("OK", palette::SUCCESS),
        (_, Some(AccessStatus::Ended)) => ("END", Color::DarkGray),
        (_, Some(AccessStatus::Error)) => ("ERR", palette::FAILURE),
        (_, Some(AccessStatus::Timeout)) => ("TIME", palette::WARNING),
        (_, Some(AccessStatus::Rejected)) => ("DENY", palette::TLS),
        (AccessPhase::Finish, None) => ("DONE", Color::DarkGray),
    };
    let client = record
        .client
        .as_deref()
        .map(|value| format::client_address(value, app.reveal_clients))
        .unwrap_or_else(|| "—".to_owned());
    let target = record.target.as_deref().unwrap_or("—");
    let mut spans = vec![
        Span::styled(format::clock_time(record.timestamp_ms), dim(app)),
        Span::raw(" "),
        Span::styled(
            format!("{:<4}", record.protocol.to_ascii_uppercase()),
            accent(app, palette::protocol(&record.protocol)),
        ),
        Span::styled(
            format!(
                "{:<3}",
                record
                    .wire_version
                    .as_deref()
                    .unwrap_or("—")
                    .to_ascii_uppercase()
            ),
            dim(app),
        ),
        Span::raw(" "),
        Span::styled(format!("{status:<4}"), accent(app, status_color)),
        Span::raw(format!(
            " {} {} {}",
            client,
            if app.capabilities.unicode { "→" } else { ">" },
            target
        )),
    ];
    if app.reveal_clients
        && let Some(tag) = record.session_tag.as_deref()
    {
        spans.push(Span::styled(format!(" S:{tag}"), dim(app)));
    }
    if let Some(duration) = record.duration_ms {
        spans.push(Span::styled(
            format!("  {}", format::duration_ms(duration)),
            dim(app),
        ));
    }
    if record.upload_bytes.is_some() || record.download_bytes.is_some() {
        spans.push(Span::raw(format!(
            " ↑{} ↓{}",
            record
                .upload_bytes
                .map(format::bytes)
                .unwrap_or_else(|| "—".to_owned()),
            record
                .download_bytes
                .map(format::bytes)
                .unwrap_or_else(|| "—".to_owned())
        )));
    }
    if let Some(message) = record.message.as_deref() {
        spans.push(Span::styled(
            format!(" · {}", normalize_message(message)),
            dim(app),
        ));
    }
    Line::from(spans)
}

fn runtime_line(record: &RuntimeRecord, app: &App) -> Line<'static> {
    let (symbol, color) = match record.level {
        EventLevel::Debug => ("·", Color::DarkGray),
        EventLevel::Info => ("●", palette::INFO),
        EventLevel::Warn => ("▲", palette::WARNING),
        EventLevel::Error => ("×", palette::FAILURE),
    };
    let symbol = if app.capabilities.unicode {
        symbol
    } else {
        match record.level {
            EventLevel::Debug | EventLevel::Info => "*",
            EventLevel::Warn => "!",
            EventLevel::Error => "x",
        }
    };
    let client = record
        .client
        .as_deref()
        .map(|value| format::client_address(value, app.reveal_clients));
    let mut spans = vec![
        Span::styled(format::clock_time(record.timestamp_ms), dim(app)),
        Span::raw(" "),
        Span::styled(format!("{symbol} "), accent(app, color)),
        Span::styled(
            format!("{:<10} ", record.kind),
            Style::default().add_modifier(Modifier::BOLD),
        ),
    ];
    if let Some(client) = client {
        spans.push(Span::styled(format!("[{client}] "), dim(app)));
    }
    spans.push(Span::raw(normalize_message(&record.message)));
    Line::from(spans)
}

fn normalize_message(message: &str) -> String {
    message.split_whitespace().collect::<Vec<_>>().join(" ")
}
