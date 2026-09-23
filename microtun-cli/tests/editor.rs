use microtun_cli::editor::{Editor, EditorEvent};

fn typed(editor: &mut Editor<64, 4>, text: &str) {
    for byte in text.bytes() {
        editor.feed(byte);
    }
}

fn line(editor: &Editor<64, 4>) -> &str {
    core::str::from_utf8(editor.line()).unwrap()
}

#[test]
fn ss3_arrows_move_the_cursor() {
    let mut editor = Editor::<64, 4>::new();
    typed(&mut editor, "abc");
    assert_eq!(editor.cursor(), 3);

    // `ESC O D` is what a terminal in application cursor-key mode sends for Left.
    assert_eq!(editor.feed(0x1b), EditorEvent::None);
    assert_eq!(editor.feed(b'O'), EditorEvent::None);
    assert_eq!(editor.feed(b'D'), EditorEvent::Redraw);
    assert_eq!(editor.cursor(), 2);

    assert_eq!(editor.feed(0x1b), EditorEvent::None);
    assert_eq!(editor.feed(b'O'), EditorEvent::None);
    assert_eq!(editor.feed(b'C'), EditorEvent::Redraw);
    assert_eq!(editor.cursor(), 3);
}

#[test]
fn csi_arrows_still_work() {
    let mut editor = Editor::<64, 4>::new();
    typed(&mut editor, "abc");
    for byte in [0x1b, b'[', b'D'] {
        editor.feed(byte);
    }
    assert_eq!(editor.cursor(), 2);
}

#[test]
fn a_lone_escape_does_not_swallow_the_next_character() {
    let mut editor = Editor::<64, 4>::new();
    editor.feed(0x1b);
    assert_eq!(editor.feed(b'a'), EditorEvent::Echo(b'a'));
    assert_eq!(line(&editor), "a");
}

#[test]
fn replace_range_uses_an_absolute_offset() {
    let mut editor = Editor::<64, 4>::new();
    typed(&mut editor, "net sta");
    assert!(editor.replace_range(4, "", "static", false, true));
    assert_eq!(line(&editor), "net static ");
    assert_eq!(editor.cursor(), 11);
}

#[test]
fn replace_range_can_quote_the_inserted_value() {
    let mut editor = Editor::<64, 4>::new();
    typed(&mut editor, "set na");
    assert!(editor.replace_range(4, "", "name with spaces", true, false));
    assert_eq!(line(&editor), "set \"name with spaces\"");
}

#[test]
fn replace_range_can_replace_a_quoted_token() {
    let mut editor = Editor::<64, 4>::new();
    typed(&mut editor, "set \"na");
    // The completer reports the token start, which a backwards whitespace scan would also find
    // here, but the opening quote must be replaced rather than kept.
    assert!(editor.replace_range(4, "", "nadir", false, true));
    assert_eq!(line(&editor), "set nadir ");
}

#[test]
fn ctrl_w_deletes_the_previous_word() {
    let mut editor = Editor::<64, 4>::new();
    typed(&mut editor, "one two");
    assert_eq!(editor.feed(0x17), EditorEvent::Redraw);
    assert_eq!(line(&editor), "one ");
}

#[test]
fn utf8_backspace_removes_a_whole_character() {
    let mut editor = Editor::<64, 4>::new();
    typed(&mut editor, "aé");
    assert_eq!(editor.len(), 3);
    editor.feed(0x7f);
    assert_eq!(line(&editor), "a");
}

#[test]
fn history_recalls_previous_lines_in_order() {
    let mut editor = Editor::<64, 4>::new();
    typed(&mut editor, "first");
    editor.remember();
    editor.clear();
    typed(&mut editor, "second");
    editor.remember();
    editor.clear();

    for byte in [0x1b, b'[', b'A'] {
        editor.feed(byte);
    }
    assert_eq!(line(&editor), "second");
    for byte in [0x1b, b'[', b'A'] {
        editor.feed(byte);
    }
    assert_eq!(line(&editor), "first");
    for byte in [0x1b, b'[', b'B'] {
        editor.feed(byte);
    }
    assert_eq!(line(&editor), "second");
}

#[test]
fn crlf_and_cr_nul_submit_exactly_once() {
    let mut editor = Editor::<64, 4>::new();
    typed(&mut editor, "go");
    assert_eq!(editor.feed(b'\r'), EditorEvent::Submit);
    assert_eq!(editor.feed(b'\n'), EditorEvent::None);

    editor.clear();
    typed(&mut editor, "go");
    assert_eq!(editor.feed(b'\r'), EditorEvent::Submit);
    assert_eq!(editor.feed(0), EditorEvent::None);
}
