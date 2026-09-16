#!/usr/bin/env bash
# Step-CA UI — JWK provisioner playbook CLI
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
    --register-only) MODE="register-only"; shift ;;
    --list) MODE="list"; shift ;;
    -h|--help)
      cat <<'EOF'
Usage: ./provisioner.sh [--mode create|register-only|list] [--playbook web|mtls|client|custom] [--lang ru|en] [--yes]
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
    ru:banner) echo "Step-CA UI — провизионеры" ;;
    en:banner) echo "Step-CA UI — provisioner playbooks" ;;
    ru:mode_prompt) echo "Режим" ;;
    en:mode_prompt) echo "Mode" ;;
    ru:mode_create) echo "Создать JWK в step-ca и зарегистрировать в UI" ;;
    en:mode_create) echo "Create JWK in step-ca and register in UI" ;;
    ru:mode_register) echo "Только зарегистрировать уже созданный JWK в UI" ;;
    en:mode_register) echo "Register an already created JWK in the UI only" ;;
    ru:mode_list) echo "Показать провизионеры, зарегистрированные в UI" ;;
    en:mode_list) echo "List provisioners registered in the UI" ;;
    ru:playbook_prompt) echo "Рецепт (класс провизионера)" ;;
    en:playbook_prompt) echo "Playbook (provisioner class)" ;;
    ru:name_prompt) echo "Имя провизионера" ;;
    en:name_prompt) echo "Provisioner name" ;;
    ru:default_dur) echo "Срок по умолчанию" ;;
    en:default_dur) echo "Default duration" ;;
    ru:max_dur) echo "Максимальный срок" ;;
    en:max_dur) echo "Maximum duration" ;;
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
    ru:reload) echo "Перезагрузка step-ca (SIGHUP)" ;;
    en:reload) echo "Reloading step-ca (SIGHUP)" ;;
    ru:registering) echo "Регистрация в UI" ;;
    en:registering) echo "Registering in UI" ;;
    ru:done) echo "Готово" ;;
    en:done) echo "Done" ;;
    ru:save_pw) echo "Сохраните пароль. Он больше не будет показан." ;;
    en:save_pw) echo "Store this password. It will not be shown again." ;;
    ru:aborted) echo "Отменено" ;;
    en:aborted) echo "Aborted" ;;
    ru:exists_hint) echo "Провизионер уже есть в CA. Используйте --mode register-only" ;;
    en:exists_hint) echo "Provisioner already exists on the CA. Use --mode register-only" ;;
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

create_on_native_ca() {
  local name="$1" def_dur="$2" max_dur="$3" password="$4"
  local ca_root ca_config pwfile out rc=0
  command -v step >/dev/null 2>&1 || die "$(t need_step)"
  ca_root="$(resolve_native_ca_root)"
  ca_config="${ca_root}/config/ca.json"

  say_step "$(t creating)"
  pwfile="$(mktemp)"
  chmod 600 "$pwfile"
  printf '%s' "$password" > "$pwfile"
  set +e
  out="$(host_sudo step ca provisioner add "$name" --type JWK --create \
    --password-file "$pwfile" \
    --x509-default-dur "$def_dur" \
    --x509-max-dur "$max_dur" \
    --ca-config "$ca_config" 2>&1)"
  rc=$?
  set -e
  rm -f "$pwfile"
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

pick_duration() {
  local prompt="$1" current="$2" i reply
  if [[ "$ASSUME_YES" == "1" || ! -t 0 ]]; then
    echo "$current"
    return
  fi
  printf "  ${C_BOLD}%s${C_RESET}\n" "$prompt"
  printf "    ${C_BOLD}[1]${C_RESET} 720h  (30 days / 30 дней)\n"
  printf "    ${C_BOLD}[2]${C_RESET} 4380h (6 months / 6 месяцев)\n"
  printf "    ${C_BOLD}[3]${C_RESET} 8760h (1 year / 1 год)\n"
  printf "    ${C_BOLD}[4]${C_RESET} 87600h (10 years / 10 лет)\n"
  local def_idx=3
  case "$current" in
    720h) def_idx=1 ;;
    4380h) def_idx=2 ;;
    8760h) def_idx=3 ;;
    87600h) def_idx=4 ;;
  esac
  reply="$(ask "$prompt" "$def_idx")"
  case "$reply" in
    1|720h) echo "720h" ;;
    2|4380h) echo "4380h" ;;
    3|8760h) echo "8760h" ;;
    4|87600h) echo "87600h" ;;
    *) echo "$current" ;;
  esac
}

valid_name() {
  local n="$1"
  [[ "$n" =~ ^[A-Za-z0-9][A-Za-z0-9._@-]{0,62}$ ]]
}

load_playbook() {
  local file="$1"
  NAME=""
  TYPE="JWK"
  DEFAULT_DURATION="8760h"
  MAX_DURATION="8760h"
  DESCRIPTION=""
  # shellcheck disable=SC1090
  source "$file"
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
  if [[ "$MODE" != "create" && "$MODE" != "register-only" && "$MODE" != "list" ]]; then
    if [[ "$ASSUME_YES" == "1" || ! -t 0 ]]; then
      MODE="create"
    else
      printf "\n${C_BOLD}${C_BLUE}▸${C_RESET} %s\n" "$(t mode_prompt)"
      printf "  ${C_BOLD}1${C_RESET}) %s\n" "$(t mode_create)"
      printf "  ${C_BOLD}2${C_RESET}) %s\n" "$(t mode_register)"
      printf "  ${C_BOLD}3${C_RESET}) %s\n" "$(t mode_list)"
      local reply
      reply="$(ask "$(t mode_prompt)" "1")"
      case "$reply" in
        2|register-only|register) MODE="register-only" ;;
        3|list) MODE="list" ;;
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
    printf "  ${C_BOLD}%d${C_RESET}) %s\n" "$((i+1))" "${PLAYBOOK_IDS[$i]}"
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

  PROV_NAME="$(ask "$(t name_prompt)" "${NAME:-}")"
  valid_name "$PROV_NAME" || die "$(t bad_name)"
  if [[ "${PROV_NAME,,}" == "admin" || "${PROV_NAME,,}" == "${system_name,,}" ]]; then
    die "$(t system_name)"
  fi

  DEFAULT_DURATION="$(pick_duration "$(t default_dur)" "${DEFAULT_DURATION:-8760h}")"
  MAX_DURATION="$(pick_duration "$(t max_dur)" "${MAX_DURATION:-8760h}")"
  is_allowed_dur "$DEFAULT_DURATION" || die "$(t bad_dur)"
  is_allowed_dur "$MAX_DURATION" || die "$(t bad_dur)"
  if (( $(duration_hours "$DEFAULT_DURATION") > $(duration_hours "$MAX_DURATION") )); then
    die "$(t max_lt_default)"
  fi

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

create_on_ca() {
  local name="$1" def_dur="$2" max_dur="$3" password="$4"
  say_step "$(t creating)"
  local out rc=0
  set +e
  out="$(printf '%s' "$password" | compose exec -T step-ca sh -c '
    set -e
    cat > /tmp/step-ui-prov.pw
    chmod 600 /tmp/step-ui-prov.pw
    step ca provisioner add "$1" --type JWK --create \
      --password-file /tmp/step-ui-prov.pw \
      --x509-default-dur "$2" \
      --x509-max-dur "$3" \
      --ca-config /home/step/config/ca.json
    rm -f /tmp/step-ui-prov.pw
  ' sh "$name" "$def_dur" "$max_dur" 2>&1)"
  rc=$?
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

print_summary() {
  printf "\n  name:    ${C_BOLD}%s${C_RESET}\n" "$PROV_NAME"
  printf "  type:    JWK\n"
  printf "  default: %s\n" "$DEFAULT_DURATION"
  printf "  max:     %s\n" "$MAX_DURATION"
  printf "  password:${C_BOLD} %s${C_RESET}\n" "$PROV_PASSWORD"
  say_warn "$(t save_pw)"
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
    create_on_ca "$PROV_NAME" "$DEFAULT_DURATION" "$MAX_DURATION" "$PROV_PASSWORD"
  else
    create_on_native_ca "$PROV_NAME" "$DEFAULT_DURATION" "$MAX_DURATION" "$PROV_PASSWORD"
  fi
  ui_register "$PROV_NAME" "$DEFAULT_DURATION" "$MAX_DURATION" "$PROV_PASSWORD"
  printf "\n${C_GREEN}%s${C_RESET}\n" "$(t done)"
  print_summary
  exit 0
fi

docker_cmd ps --format '{{.Names}}' | grep -qx step-ui || die "$(t need_ui)"
printf "\n"
print_summary
confirm "$(t confirm_register)" "Y" || die "$(t aborted)"
ui_register "$PROV_NAME" "$DEFAULT_DURATION" "$MAX_DURATION" "$PROV_PASSWORD"
printf "\n${C_GREEN}%s${C_RESET}\n" "$(t done)"
print_summary
