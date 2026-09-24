use std::path::{Path, PathBuf};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
};
use tokio::fs;

use super::centered_rect;

struct FilePickerEntry {
    name: String,
    path: PathBuf,
    is_dir: bool,
}

pub(crate) struct FilePicker {
    cwd: PathBuf,
    entries: Vec<FilePickerEntry>,
    selected: usize,
}

impl FilePicker {
    pub(crate) async fn from_current_dir() -> Result<Self, String> {
        let cwd =
            std::env::current_dir().map_err(|error| format!("read current directory: {error}"))?;
        Self::open(cwd).await
    }

    async fn open(cwd: PathBuf) -> Result<Self, String> {
        let entries = read_entries(&cwd).await?;
        Ok(Self {
            cwd,
            entries,
            selected: 0,
        })
    }

    async fn reload(&mut self) -> Result<(), String> {
        self.entries = read_entries(&self.cwd).await?;
        self.selected = self.selected.min(self.entries.len().saturating_sub(1));
        Ok(())
    }

    fn move_selection(&mut self, delta: isize) {
        if self.entries.is_empty() {
            self.selected = 0;
            return;
        }
        let last = self.entries.len() - 1;
        self.selected = self.selected.saturating_add_signed(delta).min(last);
    }

    async fn enter_selected(&mut self) -> Result<PickerAction, String> {
        let Some(entry) = self.entries.get(self.selected) else {
            return Ok(PickerAction::None);
        };
        let path = entry.path.clone();
        let is_dir = entry.is_dir;
        if is_dir {
            self.cwd = path;
            self.selected = 0;
            self.reload().await?;
            Ok(PickerAction::None)
        } else {
            Ok(PickerAction::Upload(path))
        }
    }

    async fn go_parent(&mut self) -> Result<(), String> {
        let Some(parent) = self.cwd.parent() else {
            return Ok(());
        };
        self.cwd = parent.to_path_buf();
        self.selected = 0;
        self.reload().await
    }

    pub(crate) async fn handle_key(&mut self, key: KeyEvent) -> Result<PickerAction, String> {
        match key.code {
            KeyCode::Esc => Ok(PickerAction::Cancel),
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                Ok(PickerAction::Cancel)
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_selection(-1);
                Ok(PickerAction::None)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_selection(1);
                Ok(PickerAction::None)
            }
            KeyCode::PageUp => {
                self.move_selection(-10);
                Ok(PickerAction::None)
            }
            KeyCode::PageDown => {
                self.move_selection(10);
                Ok(PickerAction::None)
            }
            KeyCode::Home => {
                self.selected = 0;
                Ok(PickerAction::None)
            }
            KeyCode::End => {
                self.selected = self.entries.len().saturating_sub(1);
                Ok(PickerAction::None)
            }
            KeyCode::Backspace | KeyCode::Left => {
                self.go_parent().await?;
                Ok(PickerAction::None)
            }
            KeyCode::Enter | KeyCode::Right => self.enter_selected().await,
            KeyCode::Char('r') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.reload().await?;
                Ok(PickerAction::None)
            }
            _ => Ok(PickerAction::None),
        }
    }

    pub(crate) fn render(&self, frame: &mut Frame<'_>, area: Rect) {
        let popup_height = area.height.saturating_sub(4).clamp(8, 22);
        let popup = centered_rect(78, popup_height, area);
        frame.render_widget(Clear, popup);
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" Send file (YMODEM) ");
        let inner = block.inner(popup);
        frame.render_widget(block, popup);
        let sections = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Min(1),
                Constraint::Length(1),
            ])
            .split(inner);
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(" Path: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(self.cwd.display().to_string()),
            ])),
            sections[0],
        );
        let visible = sections[1].height as usize;
        let start = self.selected.saturating_add(1).saturating_sub(visible);
        let lines = self
            .entries
            .iter()
            .enumerate()
            .skip(start)
            .take(visible)
            .map(|(index, entry)| {
                let marker = if index == self.selected { "> " } else { "  " };
                let style = if index == self.selected {
                    Style::default().add_modifier(Modifier::REVERSED)
                } else {
                    Style::default()
                };
                Line::from(format!("{marker}{}", entry.name)).style(style)
            })
            .collect::<Vec<_>>();
        frame.render_widget(Paragraph::new(lines), sections[1]);
        frame.render_widget(
            Paragraph::new(" Enter open/send · Backspace parent · Esc cancel"),
            sections[2],
        );
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum PickerAction {
    None,
    Cancel,
    Upload(PathBuf),
}

async fn read_entries(cwd: &Path) -> Result<Vec<FilePickerEntry>, String> {
    let mut entries = Vec::new();
    if let Some(parent) = cwd.parent() {
        entries.push(FilePickerEntry {
            name: "../".to_owned(),
            path: parent.to_path_buf(),
            is_dir: true,
        });
    }
    let mut directory = fs::read_dir(cwd)
        .await
        .map_err(|error| format!("open directory {}: {error}", cwd.display()))?;
    let mut children = Vec::new();
    while let Some(entry) = directory
        .next_entry()
        .await
        .map_err(|error| format!("read directory {}: {error}", cwd.display()))?
    {
        let path = entry.path();
        let is_dir = entry
            .file_type()
            .await
            .map(|file_type| file_type.is_dir())
            .unwrap_or(false);
        let mut name = entry.file_name().to_string_lossy().into_owned();
        if is_dir {
            name.push('/');
        }
        children.push(FilePickerEntry { name, path, is_dir });
    }
    children.sort_by(|left, right| {
        right
            .is_dir
            .cmp(&left.is_dir)
            .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
            .then_with(|| left.name.cmp(&right.name))
    });
    entries.extend(children);
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn lists_parent_and_directories_before_files() {
        let root = std::env::temp_dir().join(format!(
            "microtun-telnet-picker-test-{}",
            std::process::id()
        ));
        let child = root.join("child");
        let _ = fs::remove_dir_all(&root).await;
        fs::create_dir_all(&child).await.unwrap();
        fs::write(root.join("z.bin"), b"z").await.unwrap();
        fs::write(root.join("a.bin"), b"a").await.unwrap();
        let picker = FilePicker::open(child.clone()).await.unwrap();
        assert_eq!(picker.entries[0].name, "../");

        let root_picker = FilePicker::open(root.clone()).await.unwrap();
        let names = root_picker
            .entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["../", "child/", "a.bin", "z.bin"]);

        fs::remove_dir_all(root).await.unwrap();
    }

    #[test]
    fn navigation_clamps_selection() {
        let mut picker = FilePicker {
            cwd: PathBuf::from("."),
            entries: vec![
                FilePickerEntry {
                    name: "a".to_owned(),
                    path: PathBuf::from("a"),
                    is_dir: false,
                },
                FilePickerEntry {
                    name: "b".to_owned(),
                    path: PathBuf::from("b"),
                    is_dir: false,
                },
            ],
            selected: 0,
        };
        picker.move_selection(-1);
        assert_eq!(picker.selected, 0);
        picker.move_selection(99);
        assert_eq!(picker.selected, 1);
    }
}
