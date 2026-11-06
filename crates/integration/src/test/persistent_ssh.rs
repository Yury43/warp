use std::collections::HashMap;
use std::time::Duration;

use settings::Setting as _;
use warp::features::FeatureFlag;
use warp::integration_testing::step::new_step_with_default_assertions;
use warp::integration_testing::terminal::{
    assert_input_is_focused, assert_long_running_block_executing_for_single_terminal_in_tab,
    wait_until_bootstrapped_single_pane_for_tab,
};
use warp::integration_testing::view_getters::{
    single_input_suggestions_view_for_tab, single_input_view_for_tab, single_terminal_view_for_tab,
};
use warp::settings::{NativeShellCompletionsEnabled, WarpCompletionsEnabled};
use warp::terminal::history::History;
use warp::terminal::model::session::SessionId;
use warpui_core::integration::TestStep;
use warpui_core::{SingletonEntity as _, async_assert};

use super::new_builder;
use crate::Builder;
use crate::util::{ShellRcType, write_rc_files_for_test};

fn persistent_shell_builder() -> Builder {
    new_builder()
        .set_should_run_test(|| cfg!(unix))
        .with_setup(|utils| {
            let home = utils.test_dir();
            let init = include_str!("../../../../app/assets/bundled/bootstrap/bash_init_shell.sh")
                .replace("@@WARP_SESSION_ID@@", "$WARP_SESSION_ID")
                .replace("$_hostname", "persistent-test-host")
                .replace("@@USING_CON_PTY_BOOLEAN@@", "false");
            let mut bootstrap = init.into_bytes();
            bootstrap.extend_from_slice(
                include_str!("../../../../app/assets/bundled/bootstrap/bash.sh")
                    .replace(
                        "#include bundled/bootstrap/bash_body.sh",
                        include_str!("../../../../app/assets/bundled/bootstrap/bash_body.sh"),
                    )
                    .replace("@@USING_CON_PTY_BOOLEAN@@", "false")
                    .replace("$_hostname", "persistent-test-host")
                    .as_bytes(),
            );
            std::fs::write(home.join("persistent-bootstrap.sh"), bootstrap).unwrap();
            std::fs::write(
                home.join("persistent_shell.py"),
                include_bytes!("../../assets/persistent_shell.py"),
            )
            .unwrap();
            std::fs::write(
                home.join("persistent_client.py"),
                include_bytes!("../../../../app/src/persistent_ssh/client.py"),
            )
            .unwrap();
            let remote = home.join("remote-files");
            std::fs::create_dir(&remote).unwrap();
            std::fs::write(remote.join("remote_apple.txt"), "REMOTE_COMPLETION_OK\n").unwrap();
            std::fs::write(remote.join("remote_avocado.txt"), "").unwrap();
            std::fs::write(home.join("remote-history"), "cd /persistent-history-fixture\n").unwrap();
            write_rc_files_for_test(&home,
                "_persistent_cd() { COMPREPLY=(arcadia arcadia-wt); }; complete -F _persistent_cd cd\nif [[ -n $WARP_IS_SSH ]]; then HISTFILE=$HOME/remote-history; fi",
                [ShellRcType::Bash]);
        })
        .with_step(wait_until_bootstrapped_single_pane_for_tab(0))
}

pub fn test_persistent_shell_uses_warp_completions() -> Builder {
    persistent_shell_builder()
        .with_step(bootstrap_remote_shell())
        .with_step(wait_for_remote_history())
        .with_step(remote_completion_step())
}

pub fn test_persistent_shell_uses_native_completions() -> Builder {
    FeatureFlag::NativeShellCompletions.set_enabled(true);
    persistent_shell_builder()
        .with_user_defaults(HashMap::from([
            (
                WarpCompletionsEnabled::storage_key().to_string(),
                "false".to_string(),
            ),
            (
                NativeShellCompletionsEnabled::storage_key().to_string(),
                "true".to_string(),
            ),
        ]))
        .with_step(bootstrap_remote_shell())
        .with_step(wait_for_remote_history())
        .with_step(
            new_step_with_default_assertions("Complete remote Bash directories")
                .with_typed_characters(&["cd ar"])
                .with_keystrokes(&["tab"])
                .set_timeout(Duration::from_secs(30))
                .add_named_assertion(
                    "Remote native directory suggestions appear",
                    |app, window_id| {
                        let suggestions = single_input_suggestions_view_for_tab(app, window_id, 0);
                        suggestions.read(app, |view, _ctx| {
                            let items: Vec<_> =
                                view.items().iter().map(|item| item.text()).collect();
                            async_assert!(
                                items.contains(&"arcadia") && items.contains(&"arcadia-wt"),
                                "Expected native directories, got {items:?}"
                            )
                        })
                    },
                ),
        )
}

pub fn test_persistent_shell_imports_remote_history() -> Builder {
    persistent_shell_builder()
        .with_step(bootstrap_remote_shell())
        .with_step(wait_for_remote_history())
        .with_step(
            new_step_with_default_assertions("Recall remote history with Up")
                .with_typed_characters(&["cd /persistent-history"])
                .with_keystrokes(&["up"])
                .add_named_assertion(
                    "Up recalls a command from the remote history file",
                    |app, window_id| {
                        single_input_view_for_tab(app, window_id, 0).read(app, |input, ctx| {
                            let buffer = input.buffer_text(ctx);
                            async_assert!(
                                buffer == "cd /persistent-history-fixture",
                                "Expected remote history command, got {buffer:?}"
                            )
                        })
                    },
                ),
        )
}

pub fn test_persistent_shell_reattaches_to_running_command() -> Builder {
    persistent_shell_builder()
        .with_step(
            TestStep::new("Reattach to a shell waiting for input")
                .with_typed_characters(&["python3 ~/persistent_shell.py --resume"])
                .with_keystrokes(&["enter"])
                .add_named_assertion("Restored command is running", |app, window_id| {
                    let terminal = single_terminal_view_for_tab(app, window_id, 0);
                    terminal.read(app, |view, _ctx| {
                        let model = view.model.lock();
                        let block = model.block_list().active_block();
                        async_assert!(block.session_id().is_some_and(|id| id.as_u64() == 424242) && block.command_to_string().contains("saved=preserved"), "Expected restored remote command; active={:?}", block.command_to_string())
                    })
                })
                .add_named_assertion("Running command has terminal focus", assert_long_running_block_executing_for_single_terminal_in_tab(true, 0)),
        )
        .with_step(
            new_step_with_default_assertions("Deliver input without re-running bootstrap")
                .with_typed_characters(&["hello"])
                .with_keystrokes(&["enter"])
                .add_named_assertion("Running command receives only user input", |app, window_id| {
                    let terminal = single_terminal_view_for_tab(app, window_id, 0);
                    terminal.read(app, |view, _ctx| {
                        let model = view.model.lock();
                        let output = model.block_list().blocks().iter().map(|block| block.output_to_string()).collect::<Vec<_>>().join("\n");
                        async_assert!(output.contains("RESUMED:preserved:hello"), "Expected preserved environment and unmodified input, got {output:?}")
                    })
                }),
        )
        .with_step(wait_for_remote_prompt())
        .with_step(wait_for_remote_history())
        .with_step(remote_completion_step())
}

fn remote_completion_step() -> TestStep {
    new_step_with_default_assertions("Complete remote filenames in Warp's menu")
        .with_typed_characters(&["cat ./remote_a"])
        .with_keystrokes(&["tab"])
        .set_timeout(Duration::from_secs(30))
        .add_named_assertion("Both remote files appear", |app, window_id| {
            let suggestions = single_input_suggestions_view_for_tab(app, window_id, 0);
            suggestions.read(app, |view, _ctx| {
                let items: Vec<_> = view.items().iter().map(|item| item.text()).collect();
                async_assert!(
                    items.iter().any(|text| text.ends_with("remote_apple.txt"))
                        && items
                            .iter()
                            .any(|text| text.ends_with("remote_avocado.txt")),
                    "Expected remote filenames in completion menu, got {items:?}"
                )
            })
        })
}

fn wait_for_remote_prompt() -> TestStep {
    new_step_with_default_assertions("Wait for the remote editor to regain focus")
        .add_named_assertion("Remote input editor is focused", assert_input_is_focused())
}

fn bootstrap_remote_shell() -> TestStep {
    TestStep::new("Bootstrap the persistent remote shell")
        .with_typed_characters(&["python3 ~/persistent_shell.py"])
        .with_keystrokes(&["enter"])
        .add_named_assertion("Remote shell is integrated", |app, window_id| {
            let terminal = single_terminal_view_for_tab(app, window_id, 0);
            terminal.read(app, |view, ctx| {
                let model = view.model.lock();
                let session = model
                    .block_list()
                    .active_block()
                    .session_id()
                    .and_then(|id| view.sessions(ctx).get(id));
                async_assert!(
                    session.is_some_and(
                        |session| !session.is_local() && session.id().as_u64() == 424242
                    ),
                    "Expected an integrated remote shell"
                )
            })
        })
}

fn wait_for_remote_history() -> TestStep {
    new_step_with_default_assertions("Load remote history before the first command")
        .add_named_assertion("Remote history is available", |app, _window_id| {
            History::handle(app).read(app, |history, _ctx| {
                let commands = history
                    .commands(SessionId::from(424242))
                    .unwrap_or_default();
                async_assert!(
                    commands
                        .iter()
                        .any(|entry| entry.command == "cd /persistent-history-fixture"),
                    "Expected imported remote history"
                )
            })
        })
}
