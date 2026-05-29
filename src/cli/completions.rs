#[cfg(any(
    feature = "technitium",
    feature = "pangolin",
    feature = "cloudflare",
    feature = "unifi",
    feature = "pihole"
))]
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
        let patched = patch_zsh_server_completion(&raw, &fn_name);
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
             \tif [[ \"$cur\" == --server=* ]]; then\n\
             \t\tlocal value=\"${{cur#--server=}}\"\n\
             \t\tmapfile -t COMPREPLY < <(compgen -P \"--server=\" -W \"$({bin_name} _servers 2>/dev/null)\" -- \"$value\")\n\
             \t\treturn\n\
             \tfi\n\
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

#[cfg(any(
    feature = "technitium",
    feature = "pangolin",
    feature = "cloudflare",
    feature = "unifi",
    feature = "pihole"
))]
fn patch_zsh_server_completion(raw: &str, fn_name: &str) -> String {
    let helper = format!(":_{fn_name}_server_ids'");
    let patched: String = raw
        .lines()
        .map(|line| {
            if line.contains("'--server=[") || line.contains("'*--server=[") {
                line.replace(":_default'", &helper)
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    if raw.ends_with('\n') {
        patched + "\n"
    } else {
        patched
    }
}

#[cfg(test)]
mod tests {
    use super::patch_zsh_server_completion;

    #[test]
    fn zsh_patch_updates_repeatable_and_single_server_options_only() {
        let raw = "\
'*--server=[DNS server ID from the config file]:SERVERS:_default' \\
'--server=[A configured server entry to query]:SERVER:_default' \\
'--server-name=[TLS SNI server name]:SERVER_NAME:_default' \\
";

        let patched = patch_zsh_server_completion(raw, "dns");

        assert!(
            patched.contains(
                "'*--server=[DNS server ID from the config file]:SERVERS:_dns_server_ids'"
            )
        );
        assert!(
            patched
                .contains("'--server=[A configured server entry to query]:SERVER:_dns_server_ids'")
        );
        assert!(patched.contains("'--server-name=[TLS SNI server name]:SERVER_NAME:_default'"));
        assert!(patched.ends_with('\n'));
    }
}
