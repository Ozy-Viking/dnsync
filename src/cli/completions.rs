#[cfg(any(feature = "technitium", feature = "pangolin", feature = "cloudflare"))]
pub fn generate_completions(shell: clap_complete::Shell) {
    use clap::CommandFactory;
    use clap_complete::generate;
    use std::io::{self, Write};

    use crate::cli::Cli;

    let mut cmd = Cli::command();
    let bin_name = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_else(|| cmd.get_name().to_string());
    let fn_name = bin_name.replace('-', "_");

    let mut out = io::stdout();

    // For zsh, patch the generated output so --server specs point at our
    // dynamic helper instead of the default (_default) completer.
    if shell == clap_complete::Shell::Zsh {
        let mut buf: Vec<u8> = Vec::new();
        generate(shell, &mut cmd, &bin_name, &mut buf);
        let raw = String::from_utf8_lossy(&buf);
        let patched: String = raw
            .lines()
            .map(|line| {
                if line.contains("'*--server=") {
                    line.replace(":_default'", &format!(":_{fn_name}_server_ids'"))
                } else {
                    line.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        let patched = if raw.ends_with('\n') {
            patched + "\n"
        } else {
            patched
        };
        out.write_all(patched.as_bytes()).ok();
        let helper = format!(
            "\n# Dynamic --server completion from config\n\
             _{fn_name}_server_ids() {{\n\
             \tlocal -a ids=(\"${{(@f)$({bin_name} _servers 2>/dev/null)}}\")\n\
             \t_describe 'server ID' ids\n\
             }}\n"
        );
        out.write_all(helper.as_bytes()).ok();
        return;
    }

    generate(shell, &mut cmd, &bin_name, &mut out);

    let dynamic = match shell {
        clap_complete::Shell::Fish => format!(
            "\n# Dynamic --server completion from config\n\
             complete -e -c {bin_name} -l server\n\
             complete -c {bin_name} -l server -r -a '({bin_name} _servers 2>/dev/null)'\n"
        ),
        clap_complete::Shell::Bash => format!(
            "\n# Dynamic --server completion from config\n\
             __{fn_name}_complete() {{\n\
             \tlocal cur prev\n\
             \tcur=\"${{COMP_WORDS[COMP_CWORD]}}\"\n\
             \tprev=\"${{COMP_WORDS[COMP_CWORD-1]}}\"\n\
             \tif [[ \"$prev\" == \"--server\" ]]; then\n\
             \t\tmapfile -t COMPREPLY < <(compgen -W \"$({bin_name} _servers 2>/dev/null)\" -- \"$cur\")\n\
             \t\treturn\n\
             \tfi\n\
             \t_{fn_name} \"$@\"\n\
             }}\n\
             complete -F __{fn_name}_complete {bin_name}\n"
        ),
        _ => String::new(),
    };

    if !dynamic.is_empty() {
        out.write_all(dynamic.as_bytes()).ok();
    }
}
