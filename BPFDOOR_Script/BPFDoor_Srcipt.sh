#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PATH="$SCRIPT_DIR:$PATH"

LOG_FILE="PIOLINK_scan_$(date +%Y%m%d_%H%M%S).log"
C2_IP="165.232.174.130"

declare -A MALWARE_HASHES=(
    ["c7f693f7f85b01a8c0e561bd369845f40bff423b0743c7aa0f4c323d9133b5d4"]="hpasmmld"
    ["3f6f108db37d18519f47c5e4182e5e33cc795564f286ae770aa03372133d15c4"]="smartadm"
    ["95fd8a70c4b18a9a669fec6eb82dac0ba6a9236ac42a5ecde270330b66f51595"]="hald-addon-volume"
    ["aa779e83ff5271d3f2d270eaed16751a109eb722fca61465d86317e03bbf49e4"]="dbus-srv-bin.txt"
    ["925ec4e617adc81d6fcee60876f6b878e0313a11f25526179716a90c3b743173"]="dbus-srv"
    ["29564c19a15b06dd5be2a73d7543288f5b4e9e6668bbd5e48d3093fb6ddf1fdb"]="inode262394"
    ["be7d952d37812b7482c1d770433a499372fde7254981ce2e8e974a67f6a088b5"]="dbus-srv"
    ["027b1fed1b8213b86d8faebf51879ccc9b1afec7176e31354fbac695e8daf416"]="dbus-srv"
    ["a2ea82b3f5be30916c4a00a7759aa6ec1ae6ddadc4d82b3481640d8f6a325d59"]="dbus-srv"
    ["e04586672874685b019e9120fcd1509d68af6f9bc513e739575fc73edefd511d"]="File_in_Inode"
    ["adfdd11d69f4e971c87ca5b2073682d90118c0b3a3a9f5fbbda872ab1fb335c6"]="gm"
    ["7c39f3c3120e35b8ab89181f191f01e2556ca558475a2803cb1f02c05c830423"]="rad"
)

SUSPICIOUS_NAMES_PATHS=(
    "hpasmmld"
    "smartadm"
    "hald-addon-volume"
    "dbus-srv"
    "gm"
    "rad"
    "/dev/shm/."
    "/tmp/."    
)

gen_log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

progress_bar() {
    local current=$1 total=$2 width=40 filled empty
    filled=$(( current * width / total ))
    empty=$(( width - filled ))
    printf "\r["
    printf "%0.s#" $(seq 1 $filled)
    printf "%0.s-" $(seq 1 $empty)
    printf "] %d/%d" "$current" "$total"
}

check_files_by_hash() {
    gen_log "INFO: Start File Hash Check..."
    local found_suspicious_file=false
    local SEARCH_PATHS=("/bin" "/sbin" "/usr/bin" "/usr/sbin" "/lib" "/usr/lib" "/etc" "/tmp" "/var/tmp" "/dev/shm" "/opt" "/home")
    local total=${#SEARCH_PATHS[@]} idx=0

    for search_dir in "${SEARCH_PATHS[@]}"; do
        ((idx++))
        progress_bar "$idx" "$total"
        if [ ! -d "$search_dir" ]; then
            gen_log "WARN(Search Path): '$search_dir' Not Found..."
            continue
        fi
        find "$search_dir" -type f -print0 2>/dev/null | while IFS= read -r -d $'\0' file_path; do
            [ ! -r "$file_path" ] && continue
            current_sha256=$(sha256sum "$file_path" 2>/dev/null | awk '{print $1}')
            [ -z "$current_sha256" ] && continue
            for hash_val in "${!MALWARE_HASHES[@]}"; do
                if [[ "$current_sha256" == "$hash_val" ]]; then
                    gen_log "  CRITICAL: Found Suspicious File Hash"
                    gen_log "  Suspicious FileName: ${MALWARE_HASHES[$hash_val]}"
                    gen_log "  File Path: $file_path"
                    gen_log "  SHA256: $current_sha256"
                    found_suspicious_file=true
                fi
            done
        done
    done
    printf "\n"

    if [ "$found_suspicious_file" = false ]; then
        gen_log "INFO: No files matching known malicious file hashes were found."
    fi
}

check_suspicious_processes_and_files() {
    gen_log "INFO: Starting to scan for suspicious processes and filenames/paths..."
    local found_suspicious_item=false
    for pattern in "${SUSPICIOUS_NAMES_PATHS[@]}"; do
        if pgrep -fli "$pattern" &>/dev/null; then
            gen_log "WARN: Suspicious Pattern '$pattern' Found a process that includes !"
            pgrep -fli "$pattern" | while read -r line; do gen_log "  Process: $line"; done
            found_suspicious_item=true
        fi
        local LIMITED_SEARCH_PATHS=("/tmp" "/var/tmp" "/dev/shm" "/etc" "/run" "/usr/local/bin" "/usr/local/sbin")
        for s_path in "${LIMITED_SEARCH_PATHS[@]}"; do
            [ ! -d "$s_path" ] && continue
            find "$s_path" -name "$pattern" -print0 2>/dev/null | while IFS= read -r -d $'\0' found_file; do
                gen_log "WARN: Suspicious File/Directory '$pattern' Found items matching the pattern: $found_file"
                found_suspicious_item=true
            done
        done
    done
    if [ "$found_suspicious_item" = false ]; then
        gen_log "INFO: No suspicious processes or filename/path patterns found."
    fi
}

check_network_connections() {
    gen_log "INFO: Starting network connectivity check (C2 IP: $C2_IP)..."
    local found_c2_connection=false
    if command -v ss &>/dev/null; then
        if ss -ntp | grep -q "$C2_IP"; then
            gen_log "CRITICAL: C2 IP ($C2_IP) Network connectivity to address is suspect!"
            ss -ntp | grep "$C2_IP" | while read -r line; do gen_log "  Connection: $line"; done
            found_c2_connection=true
        fi
    elif command -v netstat &>/dev/null; then
        if netstat -ntp | grep -q "$C2_IP"; then
            gen_log "CRITICAL: C2 IP ($C2_IP) Network connectivity to the address is suspect!"
            netstat -ntp | grep "$C2_IP" | while read -r line; do gen_log "  Connection: $line"; done
            found_c2_connection=true
        fi
    else
        gen_log "WARN: Skip network connectivity check because 'ss' or 'netstat' command not found."
    fi
    [ "$found_c2_connection" = false ] && gen_log "INFO: No active connection found to C2 IP ($C2_IP)"
}

check_bpf_programs() {
    gen_log "INFO: Trying to check loaded BPF program (requires bpftool)..."
    if command -v bpftool &>/dev/null; then
        gen_log "INFO: bpftool prog show execution result:"
        bpftool prog show >> "$LOG_FILE" 2>&1
        if bpftool prog show | grep -q "name <unknown>"; then
            gen_log "WARN: An unnamed BPF program is loaded. Check for possible BPFDoor related issues.."
            bpftool prog show | grep -q "name <unknown>" >> "$LOG_FILE"
        fi
    else
        gen_log "WARN: Skipping BPF program detail check because 'bpftool' is not installed."
    fi
}

check_persistence_mechanisms() {
    gen_log "INFO: Check general persistence..."
    local found=false
    gen_log "INFO: Check the contents of Crontab."
    [ -f "/etc/crontab" ] && { gen_log "--- /etc/crontab ---"; cat /etc/crontab >> "$LOG_FILE"; }
    for file in /etc/crontab /var/spool/cron/* /var/spool/cron/crontabs/*; do
        [ -f "$file" ] && {
            grep -E "$(IFS='|'; echo "${SUSPICIOUS_NAMES_PATHS[*]}")" "$file" &>/dev/null && { gen_log "WARN: Suspicious pattern found in $file!"; found=true; }
        }
    done
    gen_log "INFO: Check the list of systemd services for suspicious services."
    for dir in /etc/systemd/system /usr/lib/systemd/system /run/systemd/system; do
        grep -rliE "$(IFS='|'; echo "${SUSPICIOUS_NAMES_PATHS[*]}")" "$dir" 2>/dev/null && { gen_log "WARN: Systemd Suspicious pattern found in systemd service file: $dir"; found=true; }
    done
    for rc in /etc/rc.local /etc/init.d/; do
        [ -e "$rc" ] && grep -rliE "$(IFS='|'; echo "${SUSPICIOUS_NAMES_PATHS[*]}")" "$rc" 2>/dev/null && { gen_log "WARN: Suspicious pattern found in RC script: $rc"; found=true; }
    done
    [ -f "/etc/ld.so.preload" ] && { gen_log "INFO: /etc/ld.so.preload Contents:"; cat /etc/ld.so.preload >> "$LOG_FILE"; }
    [ -n "$LD_PRELOAD" ] && { gen_log "WARN: LD_PRELOAD environment variable set: $LD_PRELOAD"; found=true; }
    [ "$found" = false ] && gen_log "INFO: No persistence related suspects found."
}

 gen_log "========== Start scanning for PIOLINK BPFDoor malware =========="
 gen_log " 
 ____ ___ ___  _     ___ _   _ _  __
|  _ \_ _/ _ \| |   |_ _| \ | | |/ /
| |_) | | | | | |    | ||  \| | ' / 
|  __/| | |_| | |___ | || |\  | . \ 
|_|  |___\___/|_____|___|_| \_|_|\_\ "
 gen_log "The results are saved to '$LOG_FILE'."
 [ "$(id -u)" -ne 0 ] && gen_log "WARN: No root privileges. Some checks may be limited."
 echo >> "$LOG_FILE"
 check_files_by_hash; echo >> "$LOG_FILE"
 check_suspicious_processes_and_files; echo >> "$LOG_FILE"
 check_network_connections; echo >> "$LOG_FILE"
 check_bpf_programs; echo >> "$LOG_FILE"
 check_persistence_mechanisms; echo >> "$LOG_FILE"
 gen_log "========== PIOLINK BPFDoor Malware Scan Completed =========="
 echo "Scan completed. Log: $LOG_FILE"
