# jq helpers for eggrd logs. Tested with jq 1.7.1 on eggrd 0.7.0 output.
#
#   jq -nR -L docs/security/examples 'include "eggrd"; [recs | access] | length' edge.log
#
# Reads any of the shapes eggrd's lines arrive in:
#   - the stdout line (`docker logs`, `kubectl logs`, journald export):
#       {"timestamp":…,"level":…,"fields":{"message":"request",…,"path":…},"target":"edgeguard::proxy"}
#   - a Docker json-file line, which wraps it: {"log":"{…}\n","stream":"stdout","time":…}
#   - a [log.ship] schema-2 record: {"schema":2,"ts":…,"target":"/path?query",…}
#   - a record already normalised by examples/vector.yaml (has `kind`)
# and gives every record the schema-2 names: `ts`, `target` (the request target), plus `message`,
# `level` and `module` (the Rust module that wrote it). Lines that are not JSON (a CRI prefix,
# a stack trace) are skipped: strip a CRI prefix first with  sed -E 's/^[^ ]+ [^ ]+ [^ ]+ //'.

def rec:
  (if has("log") and (.log | type) == "string" then (.log | fromjson? // empty) else . end)
  | select(type == "object" and (has("fields") or has("kind") or has("schema")))
  | if has("fields") then
      (.fields + {ts: .timestamp, level: .level, module: .target})
      | (if .message == "request" then (.target = .path | del(.path)) else . end)
    elif has("kind") then .
    elif has("schema") then . + {message: "request", level: "INFO"}
    else . end
  | .message //= "";

# Every parsed record, from -nR input.
# Lines that are not JSON, or JSON that is not an object (a bare number, string or array), are skipped.
def recs: inputs | (fromjson? // empty) | select(type == "object") | rec;

def access: select(.message == "request");
def events: select(.message != "request");

# The path without its query string.
def path_only: (.target // .path // "") | split("?")[0];

# A classifier for investigation, broader than the edge's never-valid-paths rule (EG-HARD-083): it
# matches at any depth, so it also counts probes that rule lets through (/test/phpinfo.php,
# /blog/wp-admin/). Keep the dotfile names in step with the rule when you change either.
# Probe paths the internet sends to every site: dotfiles, PHP, WordPress, appliances, SAP, CGI,
# traversal. Extend it with your own app's never-valid prefixes.
def probe_re: "(?i)(/\\.env|/\\.git|/\\.aws|/\\.ds_store|/\\.svn|\\.php|/wp-|/wordpress|xmlrpc|/cgi-bin|/actuator|/server-status|/remote/login|/owa/|/autodiscover|/developmentserver|/vendor/phpunit|/boaform|/hnap1|docker-compose|/config\\.json|\\.\\./|%2e%2e|\\.\\.;|backup\\.(zip|tar|sql))";
def is_probe: (path_only | test(probe_re)) or ((.target // "") | test("(?i)%2e%2e|\\.\\.;"));

# Count by a key: [ … ] | count_by(.status) -> {"200": 10, "429": 3}
def count_by(f): group_by(f) | map({key: (.[0] | f | tostring), value: length}) | from_entries;
