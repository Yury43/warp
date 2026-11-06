use std::collections::HashMap;
use std::sync::Arc;

use futures::FutureExt as _;
use warpui::elements::Empty;
use warpui::platform::WindowStyle;
use warpui::{App, AppContext, Element, Entity, ModelHandle, TypedActionView, View, ViewContext};

use super::command_executor::testing::TestCommandExecutor;
use super::{
    BootstrapSessionType, ExecuteCommandOptions, ExecutorCommandEvent, InBandCommandExecutor,
    Session, SessionId, SessionInfo, Sessions, SessionsEvent,
};
use crate::terminal::event::ExecutedExecutorCommandEvent;

#[test]
fn aborting_one_request_preserves_other_in_band_results() {
    App::test((), |_app| async move {
        let (commands_tx, commands_rx) = async_channel::unbounded();
        let (cancel_tx, _cancel_rx) = async_channel::unbounded();
        let executor = Arc::new(InBandCommandExecutor::new(commands_tx, cancel_tx));
        let session = Session::new(SessionInfo::new_for_test(), executor.clone());
        let mut history = Box::pin(session.execute_command(
            "cat history",
            None,
            None,
            ExecuteCommandOptions::default(),
        ));
        assert!(history.as_mut().now_or_never().is_none());
        let ExecutorCommandEvent::ExecuteCommand { command, .. } = commands_rx.try_recv().unwrap()
        else {
            panic!("Expected the history request to start");
        };
        let mut obsolete = Box::pin(session.execute_command(
            "ls old-prefix",
            None,
            None,
            ExecuteCommandOptions::default(),
        ));
        assert!(obsolete.as_mut().now_or_never().is_none());
        drop(obsolete);
        session.cancel_commands_on_request_abort();
        assert!(
            history.as_mut().now_or_never().is_none(),
            "Aborting a typing request must not cancel history loading"
        );
        executor.handle_executed_command_event(ExecutedExecutorCommandEvent {
            command_id: command.command_id,
            exit_code: 0,
            output: b"cd work".to_vec(),
        });
        assert_eq!(history.await.unwrap().stdout, b"cd work");
    });
}

struct TestView {
    events: Vec<SessionsEvent>,
}

impl Entity for TestView {
    type Event = usize;
}

impl View for TestView {
    fn render<'a>(&self, _: &AppContext) -> Box<dyn Element> {
        Empty::new().finish()
    }

    fn ui_name() -> &'static str {
        "TestView"
    }
}

impl TypedActionView for TestView {
    type Action = ();
}

impl TestView {
    fn new(model: ModelHandle<Sessions>, ctx: &mut ViewContext<Self>) -> Self {
        ctx.subscribe_to_model(&model, |me, _, event, _| {
            me.events.push(event.to_owned());
        });
        Self { events: Vec::new() }
    }
}

#[test]
fn test_set_env_var_emits_event() {
    App::test((), |mut app| async move {
        let model_handle = app.add_model(|_| Sessions::new_for_test());
        let session_id: SessionId = 0.into();
        let (_, view_handle) = app.add_window(WindowStyle::NotStealFocus, |ctx| {
            TestView::new(model_handle.clone(), ctx)
        });
        view_handle.read(&app, |view, _ctx| {
            assert!(view.events.is_empty());
        });
        model_handle.update(&mut app, |sessions, ctx| {
            let new_vars = HashMap::from_iter([("foo".to_string(), "bar".to_string())]);
            sessions.set_env_vars_for_session(session_id, new_vars, ctx)
        });

        view_handle.read(&app, |view, _ctx| {
            assert_eq!(view.events.len(), 1);
            let expected_session_id = session_id;
            let event = view.events.first().expect("checked length already");
            if let SessionsEvent::EnvironmentVariablesUpdated { session_id } = event {
                assert_eq!(*session_id, expected_session_id);
            } else {
                assert!(matches!(
                    event,
                    SessionsEvent::EnvironmentVariablesUpdated { .. }
                ));
            }
        });
    });
}

#[test]
fn test_set_env_var_emits_no_event_when_no_change() {
    App::test((), |mut app| async move {
        let model_handle = app.add_model(|_| Sessions::new_for_test());
        let session_id: SessionId = 0.into();
        let (_, view_handle) = app.add_window(WindowStyle::NotStealFocus, |ctx| {
            TestView::new(model_handle.clone(), ctx)
        });
        view_handle.read(&app, |view, _ctx| {
            assert!(view.events.is_empty());
        });
        model_handle.update(&mut app, |sessions, ctx| {
            let new_vars = HashMap::from_iter([("foo".to_string(), "bar".to_string())]);
            sessions.set_env_vars_for_session(session_id, new_vars, ctx)
        });

        view_handle.read(&app, |view, _ctx| {
            assert_eq!(view.events.len(), 1);
        });

        model_handle.update(&mut app, |sessions, ctx| {
            let new_vars = HashMap::from_iter([("foo".to_string(), "bar".to_string())]);
            sessions.set_env_vars_for_session(session_id, new_vars, ctx)
        });

        view_handle.read(&app, |view, _ctx| {
            assert_eq!(view.events.len(), 1);
        });
    });
}

#[test]
fn test_malicious_histfile_path_does_not_execute_injected_commands() {
    App::test((), |_app| async move {
        // If escaping is missing, `touch /tmp/warp_injection_test` would execute
        // as a side effect of reading history.
        let marker = "/tmp/warp_injection_test";
        // Clean up in case a previous broken run left the marker.
        let _ = std::fs::remove_file(marker);

        let malicious_histfile = format!("/tmp/x'; touch {marker}; echo '");

        let session_info = SessionInfo::new_for_test()
            .with_session_type(BootstrapSessionType::WarpifiedRemote)
            .with_histfile(Some(malicious_histfile));
        let session = Session::new(session_info, Arc::new(TestCommandExecutor::default()));

        // read_history for a WarpifiedRemote session calls read_history_from_file,
        // which builds `cat '{escaped_path}'` and executes it via TestCommandExecutor
        let _ = session.read_history(false).await;

        assert!(
            !std::path::Path::new(marker).exists(),
            "Injected command executed — escaping regression!"
        );
    });
}

#[cfg(not(windows))]
#[test]
fn can_resolve_cwd_to_native_path_accepts_posix_path() {
    let session = Session::test();
    assert!(session.can_resolve_cwd_to_native_path("/Users/foo/bar"));
}

#[cfg(windows)]
#[test]
fn can_resolve_cwd_to_native_path_accepts_windows_drive_path() {
    let session = Session::test();
    assert!(session.can_resolve_cwd_to_native_path(r"E:\CLAUDE-BASE"));
}

#[cfg(windows)]
#[test]
fn can_resolve_cwd_to_native_path_rejects_unix_encoded_path_on_windows() {
    let session_info =
        SessionInfo::new_for_test().with_shell_type(crate::terminal::shell::ShellType::Bash);
    let session = Session::new(session_info, Arc::new(TestCommandExecutor::default()));
    assert!(!session.can_resolve_cwd_to_native_path("/E:/CLAUDE-BASE"));
}

#[cfg(windows)]
#[test]
fn powershell_read_command_embeds_escaped_path_without_args() {
    use std::ffi::{OsStr, OsString};

    use super::powershell_read_all_text_command;

    // The path is embedded directly inside a single-quoted PowerShell literal.
    let raw = r"C:\Users\dev\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt";
    let command = powershell_read_all_text_command(OsStr::new(raw));
    assert_eq!(
        command,
        OsString::from(format!("[System.IO.File]::ReadAllText('{raw}')"))
    );

    // A single quote in the path is doubled so it can't terminate the literal.
    let command = powershell_read_all_text_command(OsStr::new(r"C:\o'brien\history.txt"));
    assert_eq!(
        command,
        OsString::from(r"[System.IO.File]::ReadAllText('C:\o''brien\history.txt')")
    );
}
