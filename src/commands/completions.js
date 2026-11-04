import { CliError } from '../errors.js';

export async function completionsCommand({ context }) {
  const { parsedArgs, stdout } = context;
  const shell = parsedArgs.positional?.[0] || parsedArgs.flags?.shell;

  if (!shell) {
    throw new CliError('Missing shell argument. Supported shells: bash, zsh, powershell, fish');
  }

  const commands = 'run history show recover triage verify search patterns context doctor verify-integrity rebuild hook export-shared import-shared mcp help version init stats completions clear setup event scrub';
  const globalFlags = '--help --version --json --no-color --limit --offset --root';

  if (shell === 'bash') {
    stdout.write(`# Bash: Add to ~/.bashrc:
#   eval "$(rewind completions bash)"

_rewind() {
  local cur prev
  cur="\${COMP_WORDS[COMP_CWORD]}"
  prev="\${COMP_WORDS[COMP_CWORD-1]}"
  
  local commands="${commands}"
  local global_flags="${globalFlags}"

  case $prev in
    show|recover|verify)
      local ids=$(rewind history --json 2>/dev/null | grep -o '"id":[ ]*"[^"]*"' | cut -d'"' -f4 2>/dev/null)
      COMPREPLY=( $(compgen -W "$ids" -- "$cur") )
      return 0
      ;;
    hook)
      COMPREPLY=( $(compgen -W "bash zsh powershell fish record" -- "$cur") )
      return 0
      ;;
    completions)
      COMPREPLY=( $(compgen -W "bash zsh powershell fish" -- "$cur") )
      return 0
      ;;
  esac

  if [[ "$cur" == -* ]]; then
    COMPREPLY=( $(compgen -W "$global_flags" -- "$cur") )
  else
    if [ "$COMP_CWORD" -eq 1 ]; then
      COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
    fi
  fi
}
complete -F _rewind rewind
`);
  } else if (shell === 'zsh') {
    stdout.write(`# Zsh: Add to ~/.zshrc:
#   eval "$(rewind completions zsh)"

#compdef rewind

_rewind() {
  local -a commands
  commands=(
    'run:Execute a command'
    'history:List failure records'
    'show:Inspect failure details'
    'recover:Guide recovery'
    'triage:Interactive triage'
    'verify:Execute verification'
    'search:Search historical failures'
    'patterns:Analyze patterns'
    'context:Output diagnostic context'
    'doctor:Self-diagnostics'
    'verify-integrity:Audit integrity'
    'rebuild:Reconstruct projections'
    'hook:Shell integration'
    'export-shared:Export recovery bundle'
    'import-shared:Import recovery bundle'
    'mcp:Start MCP server'
    'help:Show help'
    'version:Show version'
    'init:Initialize'
    'stats:Show stats'
    'completions:Generate completions'
    'clear:Clear data'
    'setup:Configure AI agent integrations'
    'event:Ingest external agent events'
    'scrub:Scrub secrets and re-seal journal'
  )

  local -a global_flags
  global_flags=(
    '--help[Show help]'
    '--version[Show version]'
    '--json[Output JSON]'
    '--no-color[Disable color]'
    '--limit[Limit results]'
    '--offset[Offset results]'
    '--root[Project root]'
  )

  local curcontext="$curcontext" state line
  typeset -A opt_args

  _arguments -C \\
    $global_flags \\
    '1: :->cmds' \\
    '*:: :->args'

  case $state in
    cmds)
      _describe -t commands 'rewind commands' commands
      ;;
    args)
      case $words[1] in
        show|recover|verify)
          local -a ids
          ids=($(rewind history --json 2>/dev/null | grep -o '"id":[ ]*"[^"]*"' | cut -d'"' -f4 2>/dev/null))
          _describe -t ids 'incident ids' ids
          ;;
        hook)
          local -a hook_cmds
          hook_cmds=('bash' 'zsh' 'powershell' 'fish' 'record')
          _describe -t hook_cmds 'hook commands' hook_cmds
          ;;
        completions)
          local -a shells
          shells=('bash' 'zsh' 'powershell' 'fish')
          _describe -t shells 'shells' shells
          ;;
      esac
      ;;
  esac
}

compdef _rewind rewind
`);
  } else if (shell === 'powershell') {
    stdout.write(`# PowerShell: Add to your profile:
#   Invoke-Expression (& rewind completions powershell | Out-String)

$scriptblock = {
    param($wordToComplete, $commandAst, $cursorPosition)

    $commands = @('run', 'history', 'show', 'recover', 'triage', 'verify', 'search', 'patterns', 'context', 'doctor', 'verify-integrity', 'rebuild', 'hook', 'export-shared', 'import-shared', 'mcp', 'help', 'version', 'init', 'stats', 'completions', 'clear', 'setup', 'event', 'scrub')
    $globalFlags = @('--help', '--version', '--json', '--no-color', '--limit', '--offset', '--root')

    $astElements = $commandAst.CommandElements
    $command = $null
    if ($astElements.Count -ge 2) {
        $command = $astElements[1].Value
    }

    if ($astElements.Count -eq 2 -or ($astElements.Count -eq 3 -and $wordToComplete -ne '')) {
        if ($wordToComplete -match '^-') {
            $globalFlags | Where-Object { $_ -like "$wordToComplete*" }
        } else {
            $commands | Where-Object { $_ -like "$wordToComplete*" }
        }
    }
    elseif ($command -in @('show', 'recover', 'verify')) {
        try {
            $json = rewind history --json 2>$null | ConvertFrom-Json
            $ids = @($json.data | ForEach-Object { $_.id })
            $ids | Where-Object { $_ -like "$wordToComplete*" }
        } catch {}
    }
    elseif ($command -eq 'hook') {
        @('bash', 'zsh', 'powershell', 'fish', 'record') | Where-Object { $_ -like "$wordToComplete*" }
    }
    elseif ($command -eq 'completions') {
        @('bash', 'zsh', 'powershell', 'fish') | Where-Object { $_ -like "$wordToComplete*" }
    }
}

Register-ArgumentCompleter -Native -CommandName rewind -ScriptBlock $scriptblock
`);
  } else if (shell === 'fish') {
    stdout.write(`# Fish: Add to ~/.config/fish/completions/rewind.fish:
#   rewind completions fish > ~/.config/fish/completions/rewind.fish

set -l commands ${commands}
set -l global_flags ${globalFlags}

complete -c rewind -f

# Global flags
complete -c rewind -n "not __fish_seen_subcommand_from $commands" -l help -d "Show help"
complete -c rewind -n "not __fish_seen_subcommand_from $commands" -l version -d "Show version"
complete -c rewind -n "not __fish_seen_subcommand_from $commands" -l json -d "Output JSON"
complete -c rewind -n "not __fish_seen_subcommand_from $commands" -l no-color -d "Disable color"
complete -c rewind -n "not __fish_seen_subcommand_from $commands" -l limit -d "Limit results"
complete -c rewind -n "not __fish_seen_subcommand_from $commands" -l offset -d "Offset results"
complete -c rewind -n "not __fish_seen_subcommand_from $commands" -l root -d "Project root"

# Commands
complete -c rewind -n "not __fish_seen_subcommand_from $commands" -a "run" -d "Execute a command"
complete -c rewind -n "not __fish_seen_subcommand_from $commands" -a "history" -d "List failure records"
complete -c rewind -n "not __fish_seen_subcommand_from $commands" -a "show" -d "Inspect failure details"
complete -c rewind -n "not __fish_seen_subcommand_from $commands" -a "recover" -d "Guide recovery"
complete -c rewind -n "not __fish_seen_subcommand_from $commands" -a "triage" -d "Interactive triage"
complete -c rewind -n "not __fish_seen_subcommand_from $commands" -a "verify" -d "Execute verification"
complete -c rewind -n "not __fish_seen_subcommand_from $commands" -a "search" -d "Search historical failures"
complete -c rewind -n "not __fish_seen_subcommand_from $commands" -a "patterns" -d "Analyze patterns"
complete -c rewind -n "not __fish_seen_subcommand_from $commands" -a "context" -d "Output diagnostic context"
complete -c rewind -n "not __fish_seen_subcommand_from $commands" -a "doctor" -d "Self-diagnostics"
complete -c rewind -n "not __fish_seen_subcommand_from $commands" -a "verify-integrity" -d "Audit integrity"
complete -c rewind -n "not __fish_seen_subcommand_from $commands" -a "rebuild" -d "Reconstruct projections"
complete -c rewind -n "not __fish_seen_subcommand_from $commands" -a "hook" -d "Shell integration"
complete -c rewind -n "not __fish_seen_subcommand_from $commands" -a "export-shared" -d "Export recovery bundle"
complete -c rewind -n "not __fish_seen_subcommand_from $commands" -a "import-shared" -d "Import recovery bundle"
complete -c rewind -n "not __fish_seen_subcommand_from $commands" -a "mcp" -d "Start MCP server"
complete -c rewind -n "not __fish_seen_subcommand_from $commands" -a "help" -d "Show help"
complete -c rewind -n "not __fish_seen_subcommand_from $commands" -a "version" -d "Show version"
complete -c rewind -n "not __fish_seen_subcommand_from $commands" -a "init" -d "Initialize"
complete -c rewind -n "not __fish_seen_subcommand_from $commands" -a "stats" -d "Show stats"
complete -c rewind -n "not __fish_seen_subcommand_from $commands" -a "completions" -d "Generate completions"
complete -c rewind -n "not __fish_seen_subcommand_from $commands" -a "clear" -d "Clear data"
complete -c rewind -n "not __fish_seen_subcommand_from $commands" -a "setup" -d "Configure AI agent integrations"
complete -c rewind -n "not __fish_seen_subcommand_from $commands" -a "event" -d "Ingest external agent events"
complete -c rewind -n "not __fish_seen_subcommand_from $commands" -a "scrub" -d "Scrub secrets and re-seal journal"

# Dynamic completions for show, recover, verify
complete -c rewind -n "__fish_seen_subcommand_from show recover verify" -a "(rewind history --json 2>/dev/null | grep -o '\\\"id\\\":[ ]*\\\"[^\\\"]*\\\"' | cut -d'\\\"' -f4 2>/dev/null)"

# Hook subcommands
complete -c rewind -n "__fish_seen_subcommand_from hook" -a "bash zsh powershell fish record"

# Completions subcommands
complete -c rewind -n "__fish_seen_subcommand_from completions" -a "bash zsh powershell fish"
`);
  } else {
    throw new CliError(`Unsupported shell: ${shell}. Supported shells: bash, zsh, powershell, fish`);
  }

  return 0;
}
