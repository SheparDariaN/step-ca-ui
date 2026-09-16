#!/usr/bin/env bash
# Step-CA UI — Provisioner playbook CLI
# Supports JWK (with optional SAN domain restrictions), ACME, SCEP, and SSHPOP.
# Modes: create | register-only | list
set -euo pipefail

VERBOSE=0
LANG_CHOICE=""
MODE=""
PLAYBOOK=""
ASSUME_YES=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --verbose|-v) VERBOSE=1; shift ;;
    --yes|-y) ASSUME_YES=1; shift ;;
    --lang) LANG_CHOICE="${2:-}"; shift 2 ;;
    --lang=*) LANG_CHOICE="${1#*=}"; shift ;;
    --mode) MODE="${2:-}"; shift 2 ;;
    --mode=*) MODE="${1#*=}"; shift ;;
    --playbook) PLAYBOOK="${2:-}"; shift 2 ;;
    --playbook=*) PLAYBOOK="${1#*=}"; shift ;;
    --create) MODE="create"; shift ;;
    --update|-u) MODE="update"; shift ;;
    --register-only) MODE="register-only"; shift ;;
    --list) MODE="list"; shift ;;
    -h|--help)
      cat <<'EOF'
Usage: ./provisioner.sh [--mode create|update|register-only|list] [--playbook web|mtls|client|acme|scep|sshpop|custom] [--lang ru|en] [--yes]
EOF
      exit 0
      ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ -t 1 ]]; then
  C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
  C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'; C_CYAN=$'\033[36m'
else
  C_RESET=''; C_BOLD=''; C_DIM=''; C_RED=''; C_GREEN=''; C_YELLOW=''; C_BLUE=''; C_CYAN=''
fi

normalize_lang() {
  case "${1,,}" in
    ru|rus|russian|рус|русский) echo "ru" ;;
    en|eng|english) echo "en" ;;
    *) echo "" ;;
  esac
}

LANG_CHOICE="$(normalize_lang "$LANG_CHOICE")"
if [[ -z "$LANG_CHOICE" ]]; then
  if [[ -t 0 && "$ASSUME_YES" != "1" ]]; then
    printf "%s\n" "Select language / Выберите язык:"
    printf "  ${C_BOLD}1${C_RESET}) Русский\n"
    printf "  ${C_BOLD}2${C_RESET}) English\n"
    read -r -p "$(printf "${C_CYAN}?${C_RESET} Language [1]: ")" lang_reply
    case "${lang_reply:-1}" in
      2|en|EN) LANG_CHOICE="en" ;;
      *) LANG_CHOICE="ru" ;;
    esac
  else
    LANG_CHOICE="ru"
  fi
fi

t() {
  local key="$1"
  case "$LANG_CHOICE:$key" in
    ru:banner) echo "Step-CA UI — управление провизионерами" ;;
    en:banner) echo "Step-CA UI — provisioner playbooks" ;;
    ru:mode_prompt) echo "Режим" ;;
    en:mode_prompt) echo "Mode" ;;
    ru:mode_create) echo "Создать провизионер в step-ca (и зарегистрировать в UI для JWK)" ;;
    en:mode_create) echo "Create provisioner in step-ca (and register in UI for JWK)" ;;
    ru:mode_update) echo "Обновить существующий провизионер в step-ca (и в UI)" ;;
    en:mode_update) echo "Update an existing provisioner in step-ca (and in UI)" ;;
    ru:mode_register) echo "Только зарегистрировать уже созданный JWK в UI" ;;
    en:mode_register) echo "Register an already created JWK in the UI only" ;;
    ru:mode_list) echo "Показать провизионеры, зарегистрированные в UI" ;;
    en:mode_list) echo "List provisioners registered in the UI" ;;
    ru:playbook_prompt) echo "Рецепт (класс провизионера)" ;;
    en:playbook_prompt) echo "Playbook (provisioner class)" ;;
    ru:type_prompt) echo "Тип провизионера (JWK/ACME/SCEP/SSHPOP)" ;;
    en:type_prompt) echo "Provisioner type (JWK/ACME/SCEP/SSHPOP)" ;;
    ru:name_prompt) echo "Имя провизионера" ;;
    en:name_prompt) echo "Provisioner name" ;;
    ru:default_dur) echo "Срок по умолчанию" ;;
    en:default_dur) echo "Default duration" ;;
    ru:max_dur) echo "Максимальный срок" ;;
    en:max_dur) echo "Maximum duration" ;;
    ru:duration_hint) echo "номер 1-4 или срок: 720h, 4380h, 8760h, 87600h (суффикс h можно не писать)" ;;
    en:duration_hint) echo "number 1-4 or duration: 720h, 4380h, 8760h, 87600h (the h suffix is optional)" ;;
    ru:allowed_domains_prompt) echo "Разрешенные домены SAN (например: corp.local, internal.net; пусто = без ограничений)" ;;
    en:allowed_domains_prompt) echo "Allowed SAN domains (e.g. corp.local, internal.net; empty = unrestricted)" ;;
    ru:challenges_prompt) echo "Разрешенные ACME challenges" ;;
    en:challenges_prompt) echo "Allowed ACME challenges" ;;
    ru:scep_challenge_prompt) echo "SCEP challenge секрет (пусто = сгенерировать)" ;;
    en:scep_challenge_prompt) echo "SCEP challenge secret (empty = generate)" ;;
    ru:password_prompt) echo "Пароль JWK" ;;
    en:password_prompt) echo "JWK password" ;;
    ru:password_gen) echo "Сгенерировать" ;;
    en:password_gen) echo "Generate" ;;
    ru:password_enter) echo "Ввести вручную" ;;
    en:password_enter) echo "Enter manually" ;;
    ru:enter_password) echo "Пароль (мин. 8 символов)" ;;
    en:enter_password) echo "Password (min 8 characters)" ;;
    ru:confirm) echo "Создать провизионер с этими параметрами?" ;;
    en:confirm) echo "Create the provisioner with these settings?" ;;
    ru:confirm_update) echo "Обновить провизионер с этими параметрами?" ;;
    en:confirm_update) echo "Update the provisioner with these settings?" ;;
    ru:confirm_register) echo "Зарегистрировать провизионер в UI?" ;;
    en:confirm_register) echo "Register this provisioner in the UI?" ;;
    ru:need_env) echo "Нет файла .env. Сначала выполните ./install.sh" ;;
    en:need_env) echo "Missing .env. Run ./install.sh first" ;;
    ru:need_compose) echo "Docker Compose недоступен" ;;
    en:need_compose) echo "Docker Compose is not available" ;;
    ru:need_ui) echo "Контейнер step-ui не запущен" ;;
    en:need_ui) echo "step-ui container is not running" ;;
    ru:need_ca) echo "Контейнер step-ca не запущен" ;;
    en:need_ca) echo "step-ca container is not running" ;;
    ru:need_step) echo "На хосте нет утилиты step. Установите Smallstep CLI." ;;
    en:need_step) echo "The step CLI is not installed on this host" ;;
    ru:need_ca_json) echo "Не найден ca.json" ;;
    en:need_ca_json) echo "ca.json not found" ;;
    ru:ca_path_prompt) echo "Каталог нативного step-ca" ;;
    en:ca_path_prompt) echo "Native step-ca directory" ;;
    ru:reload_failed) echo "Не удалось перезагрузить unit step-ca" ;;
    en:reload_failed) echo "Failed to reload the step-ca systemd unit" ;;
    ru:need_sudo) echo "Нужны права root или sudo, чтобы изменить ca.json" ;;
    en:need_sudo) echo "root or sudo is required to modify ca.json" ;;
    ru:bad_name) echo "Недопустимое имя провизионера" ;;
    en:bad_name) echo "Invalid provisioner name" ;;
    ru:system_name) echo "Системный провизионер нельзя перезаписать через CLI" ;;
    en:system_name) echo "The system provisioner cannot be overwritten via CLI" ;;
    ru:bad_dur) echo "Срок должен быть 720h, 4380h, 8760h или 87600h" ;;
    en:bad_dur) echo "Duration must be 720h, 4380h, 8760h, or 87600h" ;;
    ru:max_lt_default) echo "Максимальный срок должен быть не меньше срока по умолчанию" ;;
    en:max_lt_default) echo "Maximum duration must be greater than or equal to the default" ;;
    ru:short_pw) echo "Пароль слишком короткий (минимум 8 символов)" ;;
    en:short_pw) echo "Password is too short (minimum 8 characters)" ;;
    ru:creating) echo "Создание провизионера в step-ca" ;;
    en:creating) echo "Creating provisioner in step-ca" ;;
    ru:updating) echo "Обновление провизионера в step-ca" ;;
    en:updating) echo "Updating provisioner in step-ca" ;;
    ru:reload) echo "Перезагрузка step-ca (SIGHUP)" ;;
    en:reload) echo "Reloading step-ca (SIGHUP)" ;;
    ru:registering) echo "Регистрация в UI" ;;
    en:registering) echo "Registering in UI" ;;
    ru:updating_ui) echo "Обновление в UI" ;;
    en:updating_ui) echo "Updating in UI" ;;
    ru:done) echo "Готово" ;;
    en:done) echo "Done" ;;
    ru:save_pw) echo "Сохраните пароль. Он больше не будет показан." ;;
    en:save_pw) echo "Store this password. It will not be shown again." ;;
    ru:aborted) echo "Отменено" ;;
    en:aborted) echo "Aborted" ;;
    ru:exists_hint) echo "Провизионер уже есть в CA. Используйте --mode update или --mode register-only" ;;
    en:exists_hint) echo "Provisioner already exists on the CA. Use --mode update or --mode register-only" ;;
    ru:not_found_hint) echo "Провизионер не найден в CA. Сначала создайте его через --mode create" ;;
    en:not_found_hint) echo "Provisioner not found in CA. Create it first using --mode create" ;;
    ru:password_update_prompt) echo "Пароль и ключ JWK" ;;
    en:password_update_prompt) echo "JWK password and key" ;;
    ru:password_keep) echo "Оставить текущие (без изменения ключа и пароля)" ;;
    en:password_keep) echo "Keep current (do not change key or password)" ;;
    ru:password_gen_new) echo "Сгенерировать новый ключ и пароль" ;;
    en:password_gen_new) echo "Generate new key and password" ;;
    ru:password_enter_new) echo "Ввести новый пароль и сгенерировать новый ключ" ;;
    en:password_enter_new) echo "Enter new password and generate new key" ;;
    ru:san_update_hint) echo "Разрешенные домены SAN (например: corp.local, internal.net; пусто = снять ограничения)" ;;
    en:san_update_hint) echo "Allowed SAN domains (e.g. corp.local, internal.net; empty = remove restrictions)" ;;
    ru:non_jwk_register_err) echo "Режим register-only предназначен только для JWK с паролем (для веб-выпуска). Провизионеры ACME, SCEP и SSHPOP работают по протоколам." ;;
    en:non_jwk_register_err) echo "register-only mode is only for password-protected JWK provisioners. ACME, SCEP, and SSHPOP operate directly via their protocols." ;;
    ru:ui_skip_non_jwk) echo "Провизионер %s не требует пароля в UI и работает напрямую через свой протокол." ;;
    en:ui_skip_non_jwk) echo "Provisioner %s does not require a UI password and operates directly via its protocol." ;;
    *) echo "$key" ;;
  esac
}

say_step() { printf "${C_BOLD}${C_BLUE}▸${C_RESET} %s" "$*"; }
say_ok()   { printf " ${C_GREEN}✓${C_RESET}\n"; }
say_fail() { printf " ${C_RED}✗${C_RESET}\n"; }
say_warn() { printf "\n  ${C_YELLOW}⚠${C_RESET} %s\n" "$*"; }
say_info() { printf "  ${C_DIM}%s${C_RESET}\n" "$*"; }

die() {
  printf "\n${C_RED}${C_BOLD}✗ %s${C_RESET}\n" "$*" >&2
  exit 1
}

ask() {
  local prompt="$1" default="${2:-}" reply
  if [[ "$ASSUME_YES" == "1" || ! -t 0 ]]; then
    echo "$default"
    return
  fi
  if [[ -n "$default" ]]; then
    read -r -p "$(printf "${C_CYAN}?${C_RESET} %s ${C_DIM}[%s]${C_RESET}: " "$prompt" "$default")" reply
    echo "${reply:-$default}"
  else
    read -r -p "$(printf "${C_CYAN}?${C_RESET} %s: " "$prompt")" reply
    echo "$reply"
  fi
}

confirm() {
  local prompt="$1" default="${2:-N}" reply
  [[ "$ASSUME_YES" == "1" ]] && return 0
  local hint="[y/N]"; [[ "${default^^}" == "Y" ]] && hint="[Y/n]"
  read -r -p "$(printf "${C_CYAN}?${C_RESET} %s ${C_DIM}%s${C_RESET}: " "$prompt" "$hint")" reply
  reply="${reply:-$default}"
  [[ "${reply^^}" =~ ^Y(ES)?$ || "${reply^^}" =~ ^Д(А)?$ ]]
}

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"
PLAYBOOK_DIR="$PROJECT_DIR/playbooks/provisioners"
ALLOWED_DURS=(720h 4380h 8760h 87600h)

DOCKER_SUDO=""
COMPOSE_CMD=()

docker_cmd() {
  $DOCKER_SUDO docker "$@"
}

compose() {
  $DOCKER_SUDO "${COMPOSE_CMD[@]}" "$@"
}

host_sudo() {
  if [[ $EUID -eq 0 ]]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    die "$(t need_sudo)"
  fi
}

resolve_native_ca_root() {
  local path
  path="$(get_env_value CA_HOST_PATH)"
  path="${path%\"}"
  path="${path#\"}"
  path="${path%\'}"
  path="${path#\'}"
  [[ -n "$path" ]] || path="/etc/step-ca"
  path="$(ask "$(t ca_path_prompt)" "$path")"
  path="${path%/}"
  if [[ ! -f "$path/config/ca.json" ]]; then
    die "$(t need_ca_json): $path/config/ca.json"
  fi
  printf '%s\n' "$path"
}

reload_native_ca() {
  say_step "$(t reload)"
  if host_sudo systemctl reload step-ca >/dev/null 2>&1; then
    say_ok
    return
  fi
  if host_sudo systemctl kill -s HUP step-ca >/dev/null 2>&1; then
    say_ok
    return
  fi
  if host_sudo systemctl restart step-ca >/dev/null 2>&1; then
    say_ok
    return
  fi
  say_fail
  die "$(t reload_failed)"
}

native_ca_url() {
  local ca_root="$1" defaults="$1/config/defaults.json" url=""
  if [[ -f "$defaults" ]]; then
    url="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("ca-url") or "")' "$defaults" 2>/dev/null || true)"
  fi
  if [[ -z "$url" ]]; then
    url="$(get_env_value CA_URL)"
  fi
  printf '%s' "$url"
}

build_san_template() {
  local domains="$1"
  local -a parts=()
  local item clean
  IFS=", " read -r -a raw_parts <<< "$domains"
  for item in "${raw_parts[@]}"; do
    clean="${item//[[:space:]]/}"
    clean="${clean#\*.}"
    clean="${clean#.}"
    [[ -n "$clean" ]] || continue
    clean="${clean//\./\\.}"
    parts+=("$clean")
  done
  if [[ ${#parts[@]} -eq 0 ]]; then
    return 0
  fi
  local regex
  if [[ ${#parts[@]} -eq 1 ]]; then
    regex="(^|\\.)(${parts[0]})\$"
  else
    local joined
    joined="$(IFS="|"; echo "${parts[*]}")"
    regex="(^|\\.)(${joined})\$"
  fi

  cat <<EOF
{
  {{- range .SANs }}
  {{- if not (and (eq .Type "dns") (regexMatch \`${regex}\` .Value)) }}
    {{- fail (printf "SAN %s is not permitted by this provisioner (allowed: ${domains})" .Value) }}
  {{- end }}
  {{- end }}
  "subject": {{ toJson .Subject }},
  "sans": {{ toJson .SANs }},
{{- if typeIs "*rsa.PublicKey" .Insecure.CR.PublicKey }}
  "keyUsage": ["keyEncipherment", "digitalSignature"],
{{- else }}
  "keyUsage": ["digitalSignature"],
{{- end }}
  "extKeyUsage": ["serverAuth"]
}
EOF
}

create_on_native_ca() {
  local ca_root ca_config root_cert ca_url out rc=0
  command -v step >/dev/null 2>&1 || die "$(t need_step)"
  ca_root="$(resolve_native_ca_root)"
  ca_config="${ca_root}/config/ca.json"
  root_cert="${ca_root}/certs/root_ca.crt"
  ca_url="$(native_ca_url "$ca_root")"

  say_step "$(t creating)"
  set +e
  case "$TYPE" in
    JWK)
      local pwfile tplfile extra=()
      pwfile="$(mktemp)"
      chmod 600 "$pwfile"
      printf '%s' "$PROV_PASSWORD" > "$pwfile"
      if [[ -n "${ALLOWED_DOMAINS:-}" ]]; then
        tplfile="$(mktemp)"
        build_san_template "$ALLOWED_DOMAINS" > "$tplfile"
        extra+=(--x509-template "$tplfile")
      fi
      out="$(host_sudo env STEPPATH="$ca_root" step ca provisioner add "$PROV_NAME" --type JWK --create \
        --password-file "$pwfile" \
        --x509-default-dur "$DEFAULT_DURATION" \
        --x509-max-dur "$MAX_DURATION" \
        "${extra[@]}" \
        --ca-config "$ca_config" 2>&1)"
      rc=$?
      rm -f "$pwfile" "${tplfile:-}"
      ;;
    ACME)
      local extra=()
      IFS="," read -r -a ch_list <<< "$CHALLENGES"
      for c in "${ch_list[@]}"; do
        c="$(echo "$c" | tr -d "[:space:]")"
        [[ -n "$c" ]] && extra+=(--challenge "$c")
      done
      [[ "$FORCE_CN" == "true" ]] && extra+=(--force-cn)
      out="$(host_sudo env STEPPATH="$ca_root" step ca provisioner add "$PROV_NAME" --type ACME \
        --x509-default-dur "$DEFAULT_DURATION" \
        --x509-max-dur "$MAX_DURATION" \
        "${extra[@]}" \
        --ca-config "$ca_config" 2>&1)"
      rc=$?
      ;;
    SCEP)
      local extra=(--encryption-algorithm-identifier "$ENCRYPTION_ALGORITHM_IDENTIFIER" --min-public-key-length "$MIN_PUBLIC_KEY_LENGTH")
      [[ -n "$CHALLENGE" ]] && extra+=(--challenge "$CHALLENGE")
      [[ "$FORCE_CN" == "true" ]] && extra+=(--force-cn)
      out="$(host_sudo env STEPPATH="$ca_root" step ca provisioner add "$PROV_NAME" --type SCEP \
        "${extra[@]}" \
        --ca-config "$ca_config" 2>&1)"
      rc=$?
      ;;
    SSHPOP)
      out="$(host_sudo env STEPPATH="$ca_root" step ca provisioner add "$PROV_NAME" --type SSHPOP \
        --ca-config "$ca_config" 2>&1)"
      rc=$?
      ;;
    *)
      die "Unsupported provisioner type: $TYPE"
      ;;
  esac
  set -e
  if [[ $rc -ne 0 ]]; then
    say_fail
    if echo "$out" | grep -qiE 'already exists|already been added'; then
      die "$(t exists_hint)"
    fi
    die "$out"
  fi
  say_ok
  reload_native_ca
}

update_on_native_ca() {
  local ca_root ca_config root_cert ca_url out rc=0
  command -v step >/dev/null 2>&1 || die "$(t need_step)"
  ca_root="$(resolve_native_ca_root)"
  ca_config="${ca_root}/config/ca.json"
  root_cert="${ca_root}/certs/root_ca.crt"
  ca_url="$(native_ca_url "$ca_root")"

  say_step "$(t updating)"
  set +e
  case "$TYPE" in
    JWK)
      local pwfile="" tplfile="" extra=()
      if [[ -n "${PROV_PASSWORD:-}" ]]; then
        pwfile="$(mktemp)"
        chmod 600 "$pwfile"
        printf '%s' "$PROV_PASSWORD" > "$pwfile"
        extra+=(--create --password-file "$pwfile")
      fi
      if [[ -n "${ALLOWED_DOMAINS:-}" ]]; then
        tplfile="$(mktemp)"
        build_san_template "$ALLOWED_DOMAINS" > "$tplfile"
        extra+=(--x509-template "$tplfile")
      else
        extra+=(--x509-template "")
      fi
      out="$(host_sudo env STEPPATH="$ca_root" step ca provisioner update "$PROV_NAME" \
        --x509-default-dur "$DEFAULT_DURATION" \
        --x509-max-dur "$MAX_DURATION" \
        "${extra[@]}" \
        --ca-config "$ca_config" 2>&1)"
      rc=$?
      [[ -n "$pwfile" ]] && rm -f "$pwfile"
      [[ -n "$tplfile" ]] && rm -f "$tplfile"
      ;;
    ACME)
      local extra=()
      IFS="," read -r -a ch_list <<< "$CHALLENGES"
      for c in "${ch_list[@]}"; do
        c="$(echo "$c" | tr -d "[:space:]")"
        [[ -n "$c" ]] && extra+=(--challenge "$c")
      done
      [[ "$FORCE_CN" == "true" ]] && extra+=(--force-cn)
      out="$(host_sudo env STEPPATH="$ca_root" step ca provisioner update "$PROV_NAME" \
        --x509-default-dur "$DEFAULT_DURATION" \
        --x509-max-dur "$MAX_DURATION" \
        "${extra[@]}" \
        --ca-config "$ca_config" 2>&1)"
      rc=$?
      ;;
    SCEP)
      local extra=(--encryption-algorithm-identifier "$ENCRYPTION_ALGORITHM_IDENTIFIER" --minimum-public-key-length "$MIN_PUBLIC_KEY_LENGTH")
      [[ -n "$CHALLENGE" ]] && extra+=(--challenge "$CHALLENGE")
      [[ "$FORCE_CN" == "true" ]] && extra+=(--force-cn)
      out="$(host_sudo env STEPPATH="$ca_root" step ca provisioner update "$PROV_NAME" \
        "${extra[@]}" \
        --ca-config "$ca_config" 2>&1)"
      rc=$?
      ;;
    SSHPOP)
      out="SSHPOP provisioner has no configurable parameters to update"
      rc=0
      ;;
    *)
      die "Unsupported provisioner type: $TYPE"
      ;;
  esac
  set -e
  if [[ $rc -ne 0 ]]; then
    say_fail
    if echo "$out" | grep -qiE 'not found'; then
      die "$(t not_found_hint)"
    fi
    die "$out"
  fi
  say_ok
  reload_native_ca
}

setup_docker() {
  if docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD=(docker compose)
  elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_CMD=(docker-compose)
  else
    die "$(t need_compose)"
  fi
  if docker info >/dev/null 2>&1; then
    DOCKER_SUDO=""
  elif command -v sudo >/dev/null 2>&1 && sudo docker info >/dev/null 2>&1; then
    DOCKER_SUDO="sudo"
  else
    die "$(t need_compose)"
  fi
}

get_env_value() {
  local key="$1"
  [[ -f .env ]] || return 0
  grep -E "^${key}=" .env | tail -n1 | cut -d= -f2- || true
}

duration_hours() {
  local d="$1"
  echo "${d%h}"
}

is_allowed_dur() {
  local d="$1" x
  for x in "${ALLOWED_DURS[@]}"; do
    [[ "$d" == "$x" ]] && return 0
  done
  return 1
}

normalize_duration_input() {
  local r="$1"
  r="${r//[[:space:]]/}"
  r="${r,,}"
  [[ "$r" =~ ^[0-9]+$ ]] && r="${r}h"
  case "$r" in
    1|720h) echo "720h" ;;
    2|4380h) echo "4380h" ;;
    3|8760h) echo "8760h" ;;
    4|87600h) echo "87600h" ;;
    *) echo "$r" ;;
  esac
}

pick_duration() {
  local prompt="$1" current="$2" reply normalized
  if [[ "$ASSUME_YES" == "1" || ! -t 0 ]]; then
    echo "$current"
    return
  fi
  printf "  ${C_BOLD}%s${C_RESET} ${C_DIM}(%s)${C_RESET}\n" "$prompt" "$(t duration_hint)" >&2
  printf "    ${C_BOLD}[1]${C_RESET} 720h   — 30 days / 30 дней\n" >&2
  printf "    ${C_BOLD}[2]${C_RESET} 4380h  — 6 months / 6 месяцев\n" >&2
  printf "    ${C_BOLD}[3]${C_RESET} 8760h  — 1 year / 1 год\n" >&2
  printf "    ${C_BOLD}[4]${C_RESET} 87600h — 10 years / 10 лет\n" >&2
  reply="$(ask "$prompt" "$current")"
  normalized="$(normalize_duration_input "$reply")"
  if is_allowed_dur "$normalized"; then
    echo "$normalized"
  else
    echo "$current"
  fi
}

valid_name() {
  local n="$1"
  [[ "$n" =~ ^[A-Za-z0-9][A-Za-z0-9._@-]{0,62}$ ]]
}

load_playbook() {
  local file="$1" line key val
  NAME=""
  TYPE="JWK"
  DEFAULT_DURATION="8760h"
  MAX_DURATION="8760h"
  DESCRIPTION=""
  ALLOWED_DOMAINS=""
  CHALLENGES="http-01,dns-01,tls-alpn-01"
  FORCE_CN="true"
  CHALLENGE=""
  MIN_PUBLIC_KEY_LENGTH="2048"
  ENCRYPTION_ALGORITHM_IDENTIFIER="2"

  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ -z "${line//[[:space:]]/}" ]] && continue
    [[ "$line" == *=* ]] || continue
    key="${line%%=*}"
    val="${line#*=}"
    key="${key%"${key##*[![:space:]]}"}"
    key="${key#"${key%%[![:space:]]*}"}"
    val="${val%\"}"
    val="${val#\"}"
    val="${val%\'}"
    val="${val#\'}"
    case "$key" in
      NAME) NAME="$val" ;;
      TYPE) TYPE="${val^^}" ;;
      DEFAULT_DURATION) DEFAULT_DURATION="$val" ;;
      MAX_DURATION) MAX_DURATION="$val" ;;
      DESCRIPTION) DESCRIPTION="$val" ;;
      ALLOWED_DOMAINS) ALLOWED_DOMAINS="$val" ;;
      CHALLENGES) CHALLENGES="$val" ;;
      FORCE_CN) FORCE_CN="${val,,}" ;;
      CHALLENGE) CHALLENGE="$val" ;;
      MIN_PUBLIC_KEY_LENGTH) MIN_PUBLIC_KEY_LENGTH="$val" ;;
      ENCRYPTION_ALGORITHM_IDENTIFIER) ENCRYPTION_ALGORITHM_IDENTIFIER="$val" ;;
    esac
  done < "$file"
}

list_playbooks() {
  local f base
  PLAYBOOK_FILES=()
  PLAYBOOK_IDS=()
  for f in "$PLAYBOOK_DIR"/*.conf; do
    [[ -f "$f" ]] || continue
    base="$(basename "$f" .conf)"
    PLAYBOOK_FILES+=("$f")
    PLAYBOOK_IDS+=("$base")
  done
}

choose_mode() {
  MODE="$(echo "$MODE" | tr '[:upper:]' '[:lower:]')"
  if [[ "$MODE" != "create" && "$MODE" != "update" && "$MODE" != "register-only" && "$MODE" != "list" ]]; then
    if [[ "$ASSUME_YES" == "1" || ! -t 0 ]]; then
      MODE="create"
    else
      printf "\n${C_BOLD}${C_BLUE}▸${C_RESET} %s\n" "$(t mode_prompt)"
      printf "  ${C_BOLD}1${C_RESET}) %s\n" "$(t mode_create)"
      printf "  ${C_BOLD}2${C_RESET}) %s\n" "$(t mode_update)"
      printf "  ${C_BOLD}3${C_RESET}) %s\n" "$(t mode_register)"
      printf "  ${C_BOLD}4${C_RESET}) %s\n" "$(t mode_list)"
      local reply
      reply="$(ask "$(t mode_prompt)" "1")"
      case "$reply" in
        2|update) MODE="update" ;;
        3|register-only|register) MODE="register-only" ;;
        4|list) MODE="list" ;;
        *) MODE="create" ;;
      esac
    fi
  fi
}

choose_playbook() {
  list_playbooks
  [[ ${#PLAYBOOK_IDS[@]} -gt 0 ]] || die "No playbooks in $PLAYBOOK_DIR"
  if [[ -n "$PLAYBOOK" ]]; then
    local i
    for i in "${!PLAYBOOK_IDS[@]}"; do
      if [[ "${PLAYBOOK_IDS[$i]}" == "$PLAYBOOK" ]]; then
        load_playbook "${PLAYBOOK_FILES[$i]}"
        return
      fi
    done
    die "Unknown playbook: $PLAYBOOK"
  fi
  if [[ "$ASSUME_YES" == "1" || ! -t 0 ]]; then
    load_playbook "$PLAYBOOK_DIR/web.conf"
    PLAYBOOK="web"
    return
  fi
  printf "\n${C_BOLD}${C_BLUE}▸${C_RESET} %s\n" "$(t playbook_prompt)"
  local i
  for i in "${!PLAYBOOK_IDS[@]}"; do
    printf "  ${C_BOLD}%d${C_RESET}) %-8s ${C_DIM}%s${C_RESET}\n" "$((i+1))" "${PLAYBOOK_IDS[$i]}" "$(load_playbook "${PLAYBOOK_FILES[$i]}"; echo "[$TYPE] $DESCRIPTION")"
  done
  local reply idx
  reply="$(ask "$(t playbook_prompt)" "1")"
  if [[ "$reply" =~ ^[0-9]+$ ]]; then
    idx=$((reply-1))
  else
    idx=0
    for i in "${!PLAYBOOK_IDS[@]}"; do
      [[ "${PLAYBOOK_IDS[$i]}" == "$reply" ]] && idx=$i
    done
  fi
  [[ $idx -ge 0 && $idx -lt ${#PLAYBOOK_IDS[@]} ]] || idx=0
  PLAYBOOK="${PLAYBOOK_IDS[$idx]}"
  load_playbook "${PLAYBOOK_FILES[$idx]}"
}

prompt_params() {
  local system_name
  system_name="$(get_env_value PROVISIONER)"
  [[ -n "$system_name" ]] || system_name="admin"

  if [[ "$PLAYBOOK" == "custom" ]]; then
    printf "  ${C_BOLD}%s${C_RESET}\n" "$(t type_prompt)"
    printf "    ${C_BOLD}[1]${C_RESET} JWK    — Key-pair tokens (TLS, mTLS, UI)\n"
    printf "    ${C_BOLD}[2]${C_RESET} ACME   — Automated cert issuance (HTTP/DNS/TLS-ALPN)\n"
    printf "    ${C_BOLD}[3]${C_RESET} SCEP   — Network equipment & MDM\n"
    printf "    ${C_BOLD}[4]${C_RESET} SSHPOP — SSH host certificate renewal\n"
    local t_reply
    t_reply="$(ask "$(t type_prompt)" "1")"
    case "$t_reply" in
      2|ACME|acme) TYPE="ACME" ;;
      3|SCEP|scep) TYPE="SCEP" ;;
      4|SSHPOP|sshpop) TYPE="SSHPOP" ;;
      *) TYPE="JWK" ;;
    esac
  fi

  PROV_NAME="$(ask "$(t name_prompt)" "${NAME:-${TYPE,,}}")"
  valid_name "$PROV_NAME" || die "$(t bad_name)"
  if [[ "${PROV_NAME,,}" == "admin" || "${PROV_NAME,,}" == "${system_name,,}" ]]; then
    die "$(t system_name)"
  fi

  case "$TYPE" in
    JWK)
      DEFAULT_DURATION="$(pick_duration "$(t default_dur)" "${DEFAULT_DURATION:-8760h}")"
      MAX_DURATION="$(pick_duration "$(t max_dur)" "${MAX_DURATION:-8760h}")"
      is_allowed_dur "$DEFAULT_DURATION" || die "$(t bad_dur)"
      is_allowed_dur "$MAX_DURATION" || die "$(t bad_dur)"
      if (( $(duration_hours "$DEFAULT_DURATION") > $(duration_hours "$MAX_DURATION") )); then
        die "$(t max_lt_default)"
      fi

      if [[ "$MODE" == "update" ]]; then
        ALLOWED_DOMAINS="$(ask "$(t san_update_hint)" "${ALLOWED_DOMAINS:-}")"

        printf "  ${C_BOLD}%s${C_RESET}\n" "$(t password_update_prompt)"
        printf "    ${C_BOLD}[1]${C_RESET} %s\n" "$(t password_keep)"
        printf "    ${C_BOLD}[2]${C_RESET} %s\n" "$(t password_gen_new)"
        printf "    ${C_BOLD}[3]${C_RESET} %s\n" "$(t password_enter_new)"
        local pw_choice
        pw_choice="$(ask "$(t password_update_prompt)" "1")"
        case "$pw_choice" in
          2)
            PROV_PASSWORD="$(openssl rand -base64 32 2>/dev/null | tr -dc 'A-HJ-NP-Za-km-z2-9' | head -c 16)"
            ;;
          3)
            PROV_PASSWORD="$(ask "$(t enter_password)" "")"
            [[ ${#PROV_PASSWORD} -ge 8 ]] || die "$(t short_pw)"
            ;;
          *)
            PROV_PASSWORD=""
            ;;
        esac
      else
        ALLOWED_DOMAINS="$(ask "$(t allowed_domains_prompt)" "${ALLOWED_DOMAINS:-}")"

        printf "  ${C_BOLD}%s${C_RESET}\n" "$(t password_prompt)"
        printf "    ${C_BOLD}[1]${C_RESET} %s\n" "$(t password_gen)"
        printf "    ${C_BOLD}[2]${C_RESET} %s\n" "$(t password_enter)"
        local pw_choice
        pw_choice="$(ask "$(t password_prompt)" "1")"
        if [[ "$pw_choice" == "2" ]]; then
          PROV_PASSWORD="$(ask "$(t enter_password)" "")"
        else
          PROV_PASSWORD="$(openssl rand -base64 32 2>/dev/null | tr -dc 'A-HJ-NP-Za-km-z2-9' | head -c 16)"
        fi
        [[ ${#PROV_PASSWORD} -ge 8 ]] || die "$(t short_pw)"
      fi
      ;;

    ACME)
      DEFAULT_DURATION="$(pick_duration "$(t default_dur)" "${DEFAULT_DURATION:-720h}")"
      MAX_DURATION="$(pick_duration "$(t max_dur)" "${MAX_DURATION:-2160h}")"
      CHALLENGES="$(ask "$(t challenges_prompt)" "${CHALLENGES:-http-01,dns-01,tls-alpn-01}")"
      FORCE_CN="${FORCE_CN:-true}"
      PROV_PASSWORD=""
      ;;

    SCEP)
      local gen_secret=""
      [[ "$MODE" != "update" ]] && gen_secret="$(openssl rand -base64 24 2>/dev/null | tr -dc 'A-Za-z0-9' | head -c 16)"
      CHALLENGE="$(ask "$(t scep_challenge_prompt)" "${CHALLENGE:-$gen_secret}")"
      MIN_PUBLIC_KEY_LENGTH="${MIN_PUBLIC_KEY_LENGTH:-2048}"
      ENCRYPTION_ALGORITHM_IDENTIFIER="${ENCRYPTION_ALGORITHM_IDENTIFIER:-2}"
      FORCE_CN="${FORCE_CN:-true}"
      PROV_PASSWORD=""
      ;;

    SSHPOP)
      PROV_PASSWORD=""
      ;;

    *)
      die "Unknown provisioner type: $TYPE"
      ;;
  esac
}

ui_register() {
  local name="$1" def_dur="$2" max_dur="$3" password="$4"
  say_step "$(t registering)"
  if ! printf '%s' "$password" | compose exec -T step-ui /opt/step-ui/step-ui provisioner-register \
    --name "$name" --type JWK --default-dur "$def_dur" --max-dur "$max_dur" --password-file -; then
    say_fail
    die "provisioner-register failed"
  fi
  say_ok
}

ui_update() {
  local name="$1" def_dur="$2" max_dur="$3" password="${4:-}"
  say_step "$(t updating_ui)"
  if [[ -n "$password" ]]; then
    if ! printf '%s' "$password" | compose exec -T step-ui /opt/step-ui/step-ui provisioner-update \
      --name "$name" --default-dur "$def_dur" --max-dur "$max_dur" --password-file - 2>/dev/null; then
      # Fallback to provisioner-register
      if ! printf '%s' "$password" | compose exec -T step-ui /opt/step-ui/step-ui provisioner-register \
        --name "$name" --type JWK --default-dur "$def_dur" --max-dur "$max_dur" --password-file -; then
        say_fail
        die "provisioner update in UI failed"
      fi
    fi
  else
    if ! compose exec -T step-ui /opt/step-ui/step-ui provisioner-update \
      --name "$name" --default-dur "$def_dur" --max-dur "$max_dur" 2>/dev/null; then
      # Fallback to postgres psql directly if older binary without provisioner-update
      if ! compose exec -T postgres psql -U stepui -d stepui -c \
        "UPDATE ca_provisioners SET default_duration='$def_dur', max_duration='$max_dur' WHERE name='$name';" >/dev/null 2>&1; then
        say_warn "Could not update durations in UI database. Re-register via --mode register-only if needed."
        return 0
      fi
    fi
  fi
  say_ok
}

create_on_ca() {
  say_step "$(t creating)"
  local out rc=0
  set +e
  case "$TYPE" in
    JWK)
      local tpl_content=""
      if [[ -n "${ALLOWED_DOMAINS:-}" ]]; then
        tpl_content="$(build_san_template "$ALLOWED_DOMAINS")"
      fi
      out="$(printf '%s\n---TPL_DELIMITER---\n%s' "$PROV_PASSWORD" "$tpl_content" | compose exec -T step-ca sh -c '
        set -e
        name="$1"; def_dur="$2"; max_dur="$3"
        awk "/---TPL_DELIMITER---/{exit} {print}" > /tmp/step-ui-prov.pw
        awk "found{print} /---TPL_DELIMITER---/{found=1}" > /tmp/step-ui-prov.tpl
        chmod 600 /tmp/step-ui-prov.pw
        extra=()
        if [ -s /tmp/step-ui-prov.tpl ]; then
          extra+=(--x509-template /tmp/step-ui-prov.tpl)
        fi
        step ca provisioner add "$name" --type JWK --create \
          --password-file /tmp/step-ui-prov.pw \
          --x509-default-dur "$def_dur" \
          --x509-max-dur "$max_dur" \
          "${extra[@]}" \
          --ca-config /home/step/config/ca.json
        rm -f /tmp/step-ui-prov.pw /tmp/step-ui-prov.tpl
      ' sh "$PROV_NAME" "$DEFAULT_DURATION" "$MAX_DURATION" 2>&1)"
      rc=$?
      ;;

    ACME)
      out="$(compose exec -T step-ca sh -c '
        set -e
        name="$1"; def_dur="$2"; max_dur="$3"; challenges="$4"; force_cn="$5"
        extra=()
        IFS="," read -r -a ch_list <<< "$challenges"
        for c in "${ch_list[@]}"; do
          c="$(echo "$c" | tr -d "[:space:]")"
          [ -n "$c" ] && extra+=(--challenge "$c")
        done
        [ "$force_cn" = "true" ] && extra+=(--force-cn)
        step ca provisioner add "$name" --type ACME \
          --x509-default-dur "$def_dur" \
          --x509-max-dur "$max_dur" \
          "${extra[@]}" \
          --ca-config /home/step/config/ca.json
      ' sh "$PROV_NAME" "$DEFAULT_DURATION" "$MAX_DURATION" "$CHALLENGES" "$FORCE_CN" 2>&1)"
      rc=$?
      ;;

    SCEP)
      out="$(compose exec -T step-ca sh -c '
        set -e
        name="$1"; challenge="$2"; enc_id="$3"; min_key="$4"; force_cn="$5"
        extra=(--encryption-algorithm-identifier "$enc_id" --min-public-key-length "$min_key")
        [ -n "$challenge" ] && extra+=(--challenge "$challenge")
        [ "$force_cn" = "true" ] && extra+=(--force-cn)
        step ca provisioner add "$name" --type SCEP \
          "${extra[@]}" \
          --ca-config /home/step/config/ca.json
      ' sh "$PROV_NAME" "$CHALLENGE" "$ENCRYPTION_ALGORITHM_IDENTIFIER" "$MIN_PUBLIC_KEY_LENGTH" "$FORCE_CN" 2>&1)"
      rc=$?
      ;;

    SSHPOP)
      out="$(compose exec -T step-ca sh -c '
        set -e
        step ca provisioner add "$1" --type SSHPOP --ca-config /home/step/config/ca.json
      ' sh "$PROV_NAME" 2>&1)"
      rc=$?
      ;;

    *)
      die "Unsupported provisioner type: $TYPE"
      ;;
  esac
  set -e

  if [[ $rc -ne 0 ]]; then
    say_fail
    if echo "$out" | grep -qiE 'already exists|already been added'; then
      die "$(t exists_hint)"
    fi
    die "$out"
  fi
  say_ok

  say_step "$(t reload)"
  docker_cmd kill -s HUP step-ca >/dev/null
  local i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    if compose exec -T step-ca curl -sk https://127.0.0.1:9443/health >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  say_ok
}

update_on_ca() {
  say_step "$(t updating)"
  local out rc=0
  set +e
  case "$TYPE" in
    JWK)
      local tpl_content=""
      if [[ -n "${ALLOWED_DOMAINS:-}" ]]; then
        tpl_content="$(build_san_template "$ALLOWED_DOMAINS")"
      fi
      out="$(printf '%s\n---TPL_DELIMITER---\n%s' "${PROV_PASSWORD:-}" "$tpl_content" | compose exec -T step-ca sh -c '
        set -e
        name="$1"; def_dur="$2"; max_dur="$3"
        awk "/---TPL_DELIMITER---/{exit} {print}" > /tmp/step-ui-prov.pw
        awk "found{print} /---TPL_DELIMITER---/{found=1}" > /tmp/step-ui-prov.tpl
        chmod 600 /tmp/step-ui-prov.pw
        extra=()
        if [ -s /tmp/step-ui-prov.tpl ]; then
          extra+=(--x509-template /tmp/step-ui-prov.tpl)
        else
          extra+=(--x509-template "")
        fi
        if [ -s /tmp/step-ui-prov.pw ]; then
          extra+=(--create --password-file /tmp/step-ui-prov.pw)
        fi
        step ca provisioner update "$name" \
          --x509-default-dur "$def_dur" \
          --x509-max-dur "$max_dur" \
          "${extra[@]}" \
          --ca-config /home/step/config/ca.json
        rm -f /tmp/step-ui-prov.pw /tmp/step-ui-prov.tpl
      ' sh "$PROV_NAME" "$DEFAULT_DURATION" "$MAX_DURATION" 2>&1)"
      rc=$?
      ;;

    ACME)
      out="$(compose exec -T step-ca sh -c '
        set -e
        name="$1"; def_dur="$2"; max_dur="$3"; challenges="$4"; force_cn="$5"
        extra=()
        IFS="," read -r -a ch_list <<< "$challenges"
        for c in "${ch_list[@]}"; do
          c="$(echo "$c" | tr -d "[:space:]")"
          [ -n "$c" ] && extra+=(--challenge "$c")
        done
        [ "$force_cn" = "true" ] && extra+=(--force-cn)
        step ca provisioner update "$name" \
          --x509-default-dur "$def_dur" \
          --x509-max-dur "$max_dur" \
          "${extra[@]}" \
          --ca-config /home/step/config/ca.json
      ' sh "$PROV_NAME" "$DEFAULT_DURATION" "$MAX_DURATION" "$CHALLENGES" "$FORCE_CN" 2>&1)"
      rc=$?
      ;;

    SCEP)
      out="$(compose exec -T step-ca sh -c '
        set -e
        name="$1"; challenge="$2"; enc_id="$3"; min_key="$4"; force_cn="$5"
        extra=(--encryption-algorithm-identifier "$enc_id" --minimum-public-key-length "$min_key")
        [ -n "$challenge" ] && extra+=(--challenge "$challenge")
        [ "$force_cn" = "true" ] && extra+=(--force-cn)
        step ca provisioner update "$name" \
          "${extra[@]}" \
          --ca-config /home/step/config/ca.json
      ' sh "$PROV_NAME" "$CHALLENGE" "$ENCRYPTION_ALGORITHM_IDENTIFIER" "$MIN_PUBLIC_KEY_LENGTH" "$FORCE_CN" 2>&1)"
      rc=$?
      ;;

    SSHPOP)
      out="SSHPOP provisioner does not require CA configuration updates"
      rc=0
      ;;

    *)
      die "Unsupported provisioner type: $TYPE"
      ;;
  esac
  set -e

  if [[ $rc -ne 0 ]]; then
    say_fail
    if echo "$out" | grep -qiE 'not found'; then
      die "$(t not_found_hint)"
    fi
    die "$out"
  fi
  say_ok

  say_step "$(t reload)"
  docker_cmd kill -s HUP step-ca >/dev/null
  local i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    if compose exec -T step-ca curl -sk https://127.0.0.1:9443/health >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  say_ok
}

print_summary() {
  local ca_host
  ca_host="$(get_env_value IP)"
  [[ -n "$ca_host" ]] || ca_host="127.0.0.1"

  printf "\n  name:    ${C_BOLD}%s${C_RESET}\n" "$PROV_NAME"
  printf "  type:    ${C_BOLD}%s${C_RESET}\n" "$TYPE"

  case "$TYPE" in
    JWK)
      printf "  default: %s\n" "$DEFAULT_DURATION"
      printf "  max:     %s\n" "$MAX_DURATION"
      if [[ -n "${ALLOWED_DOMAINS:-}" ]]; then
        printf "  SAN policy: %s (regex: %s)\n" "${C_GREEN}${ALLOWED_DOMAINS}${C_RESET}" "(^|\\.)(${ALLOWED_DOMAINS//[[:space:],]/|})\$"
      else
        printf "  SAN policy: %s\n" "${C_DIM}unrestricted${C_RESET}"
      fi
      if [[ -n "${PROV_PASSWORD:-}" ]]; then
        printf "  password:${C_BOLD} %s${C_RESET}\n" "$PROV_PASSWORD"
        say_warn "$(t save_pw)"
      elif [[ "$MODE" == "update" ]]; then
        printf "  password: %s\n" "${C_DIM}unchanged${C_RESET}"
      fi
      ;;

    ACME)
      printf "  default: %s\n" "$DEFAULT_DURATION"
      printf "  max:     %s\n" "$MAX_DURATION"
      printf "  challenges: %s\n" "$CHALLENGES"
      printf "\n  ${C_BOLD}ACME Directory:${C_RESET} https://%s:9443/acme/%s/directory\n" "$ca_host" "$PROV_NAME"
      printf "  ${C_DIM}Certbot: certbot certonly --standalone -d myserver.corp.local --server https://%s:9443/acme/%s/directory${C_RESET}\n" "$ca_host" "$PROV_NAME"
      printf "  ${C_DIM}Caddy:   acme_ca https://%s:9443/acme/%s/directory${C_RESET}\n" "$ca_host" "$PROV_NAME"
      ;;

    SCEP)
      printf "  challenge: ${C_BOLD}%s${C_RESET}\n" "$CHALLENGE"
      printf "  min key:   %s RSA\n" "$MIN_PUBLIC_KEY_LENGTH"
      printf "\n  ${C_BOLD}SCEP URL:${C_RESET}  http://%s:8080/scep/%s\n" "$ca_host" "$PROV_NAME"
      say_warn "SCEP requires an RSA Intermediate CA and 'insecureAddress: \":8080\"' in ca.json if clients use HTTP."
      ;;

    SSHPOP)
      printf "  purpose:   host SSH cert renewal / rekey / revoke\n"
      printf "  ${C_DIM}Renew command: step ssh renew /etc/ssh/ssh_host_ecdsa_key-cert.pub /etc/ssh/ssh_host_ecdsa_key --provisioner %s${C_RESET}\n" "$PROV_NAME"
      ;;
  esac
}

ui_list() {
  compose exec -T step-ui /opt/step-ui/step-ui provisioner-list
}

[[ -f .env ]] || die "$(t need_env)"
setup_docker

printf "\n${C_BOLD}%s${C_RESET}\n" "$(t banner)"
choose_mode

if [[ "$MODE" == "list" ]]; then
  docker_cmd ps --format '{{.Names}}' | grep -qx step-ui || die "$(t need_ui)"
  ui_list
  exit 0
fi

choose_playbook
prompt_params

if [[ "$MODE" == "create" ]]; then
  local_ca_mode="$(get_env_value CA_MODE)"
  [[ -n "$local_ca_mode" ]] || local_ca_mode="bundled"
  docker_cmd ps --format '{{.Names}}' | grep -qx step-ui || die "$(t need_ui)"
  if [[ "$local_ca_mode" == "bundled" ]]; then
    docker_cmd ps --format '{{.Names}}' | grep -qx step-ca || die "$(t need_ca)"
  fi
  printf "\n"
  print_summary
  confirm "$(t confirm)" "Y" || die "$(t aborted)"
  if [[ "$local_ca_mode" == "bundled" ]]; then
    create_on_ca
  else
    create_on_native_ca
  fi
  if [[ "$TYPE" == "JWK" ]]; then
    ui_register "$PROV_NAME" "$DEFAULT_DURATION" "$MAX_DURATION" "$PROV_PASSWORD"
  else
    say_info "$(printf "$(t ui_skip_non_jwk)" "$TYPE")"
  fi
  printf "\n${C_GREEN}%s${C_RESET}\n" "$(t done)"
  print_summary
  exit 0
fi

if [[ "$MODE" == "update" ]]; then
  local_ca_mode="$(get_env_value CA_MODE)"
  [[ -n "$local_ca_mode" ]] || local_ca_mode="bundled"
  docker_cmd ps --format '{{.Names}}' | grep -qx step-ui || die "$(t need_ui)"
  if [[ "$local_ca_mode" == "bundled" ]]; then
    docker_cmd ps --format '{{.Names}}' | grep -qx step-ca || die "$(t need_ca)"
  fi
  printf "\n"
  print_summary
  confirm "$(t confirm_update)" "Y" || die "$(t aborted)"
  if [[ "$local_ca_mode" == "bundled" ]]; then
    update_on_ca
  else
    update_on_native_ca
  fi
  if [[ "$TYPE" == "JWK" ]]; then
    ui_update "$PROV_NAME" "$DEFAULT_DURATION" "$MAX_DURATION" "${PROV_PASSWORD:-}"
  else
    say_info "$(printf "$(t ui_skip_non_jwk)" "$TYPE")"
  fi
  printf "\n${C_GREEN}%s${C_RESET}\n" "$(t done)"
  print_summary
  exit 0
fi

# register-only mode
if [[ "$TYPE" != "JWK" ]]; then
  die "$(t non_jwk_register_err)"
fi

docker_cmd ps --format '{{.Names}}' | grep -qx step-ui || die "$(t need_ui)"
printf "\n"
print_summary
confirm "$(t confirm_register)" "Y" || die "$(t aborted)"
ui_register "$PROV_NAME" "$DEFAULT_DURATION" "$MAX_DURATION" "$PROV_PASSWORD"
printf "\n${C_GREEN}%s${C_RESET}\n" "$(t done)"
print_summary
