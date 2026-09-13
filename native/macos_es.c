#include "macos_es.h"
#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <mach/mach.h>
#include <sys/sysctl.h>
#include <string.h>

static tf_es_string string_token(es_string_token_t token) {
    return (tf_es_string){(const uint8_t *)token.data, token.length};
}

static tf_es_identity identity(audit_token_t token) {
    return (tf_es_identity){
        (uint32_t)audit_token_to_pid(token), (uint32_t)audit_token_to_pidversion(token),
        audit_token_to_euid(token), audit_token_to_ruid(token),
        audit_token_to_egid(token), audit_token_to_rgid(token),
        audit_token_to_auid(token), (uint32_t)audit_token_to_asid(token)
    };
}

static tf_es_file file_info(const es_file_t *file) {
    if (!file) return (tf_es_file){0};
    return (tf_es_file){string_token(file->path), file->stat.st_ino,
        file->stat.st_dev, file->stat.st_mode, file->path_truncated, 1};
}

static tf_es_process process_info(const es_process_t *process, uint32_t version) {
    tf_es_process out = {0};
    if (!process) return out;
    out.present = 1;
    out.identity = identity(process->audit_token);
    out.executable = file_info(process->executable);
    out.signing_id = string_token(process->signing_id);
    out.team_id = string_token(process->team_id);
    memcpy(out.cdhash, process->cdhash, sizeof(out.cdhash));
    out.ppid = (uint32_t)process->ppid;
    out.original_ppid = (uint32_t)process->original_ppid;
    out.codesigning_flags = process->codesigning_flags;
    out.is_platform_binary = process->is_platform_binary;
    out.is_es_client = process->is_es_client;
    if (version >= 3) {
        out.has_start_time = 1;
        out.start_seconds = process->start_time.tv_sec;
        out.start_microseconds = process->start_time.tv_usec;
    }
    if (version >= 4) {
        out.has_parent = 1;
        out.parent = identity(process->parent_audit_token);
        out.responsible = identity(process->responsible_audit_token);
    }
    return out;
}

static void emit(tf_es_callback callback, void *context, const es_message_t *message) {
    // This collector subscribes exclusively to NOTIFY events, never AUTH.
    if (message->action_type != ES_ACTION_TYPE_NOTIFY) return;
    tf_es_record out = {0};
    out.abi_version = 1;
    out.message_version = message->version;
    out.native_event_type = message->event_type;
    out.seconds = message->time.tv_sec;
    out.nanoseconds = message->time.tv_nsec;
    out.mach_time = message->mach_time;
    out.actor = process_info(message->process, message->version);
    out.result_type = message->action.notify.result_type;
    if (message->action.notify.result_type == ES_RESULT_TYPE_AUTH)
        out.result_value = message->action.notify.result.auth;
    else if (message->action.notify.result_type == ES_RESULT_TYPE_FLAGS)
        out.result_value = message->action.notify.result.flags;
    if (message->version >= 2) {
        out.has_seq_num = 1;
        out.seq_num = message->seq_num;
    }
    if (message->version >= 4) {
        out.has_global_seq_num = 1;
        out.global_seq_num = message->global_seq_num;
    }
    switch (message->event_type) {
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            out.kind = 1;
            out.target = process_info(message->event.exec.target, message->version);
            break;
        case ES_EVENT_TYPE_NOTIFY_FORK:
            out.kind = 2;
            out.target = process_info(message->event.fork.child, message->version);
            break;
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            out.kind = 3;
            out.exit_status = message->event.exit.stat;
            break;
        case ES_EVENT_TYPE_NOTIFY_CREATE:
            out.kind = 4;
            if (message->event.create.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE)
                out.file = file_info(message->event.create.destination.existing_file);
            else if (message->event.create.destination_type == ES_DESTINATION_TYPE_NEW_PATH) {
                out.destination_is_new_path = 1;
                out.destination = file_info(message->event.create.destination.new_path.dir);
                out.destination_name = string_token(message->event.create.destination.new_path.filename);
            }
            break;
        case ES_EVENT_TYPE_NOTIFY_RENAME:
            out.kind = 5;
            out.file = file_info(message->event.rename.source);
            if (message->event.rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE)
                out.destination = file_info(message->event.rename.destination.existing_file);
            else if (message->event.rename.destination_type == ES_DESTINATION_TYPE_NEW_PATH) {
                out.destination_is_new_path = 1;
                out.destination = file_info(message->event.rename.destination.new_path.dir);
                out.destination_name = string_token(message->event.rename.destination.new_path.filename);
            }
            break;
        case ES_EVENT_TYPE_NOTIFY_UNLINK:
            out.kind = 6;
            out.file = file_info(message->event.unlink.target);
            break;
        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            out.kind = 7;
            out.file = file_info(message->event.close.target);
            out.modified = message->event.close.modified;
            if (message->version >= 6) {
                out.has_mapped_writable = 1;
                out.mapped_writable = message->event.close.was_mapped_writable;
            }
            break;
        case ES_EVENT_TYPE_NOTIFY_WRITE:
            out.kind = 8;
            out.file = file_info(message->event.write.target);
            break;
        default: break; // A future unexpected type is reported as a decode failure.
    }
    // No file IO, network, content scanning, env/argv access or retained messages.
    callback(context, &out);
}

int tf_es_boot_uuid(char *out, size_t capacity) {
    size_t length = capacity;
    if (sysctlbyname("kern.bootsessionuuid", out, &length, NULL, 0) != 0) return -1;
    if (length == 0 || length > capacity || out[length - 1] != '\0') return -1;
    return 0;
}

int tf_es_open(void **handle, tf_es_callback callback, void *context) {
    *handle = NULL;
    es_client_t *client = NULL;
    es_new_client_result_t result = es_new_client(&client,
        ^(es_client_t *unused, const es_message_t *message) {
            (void)unused;
            emit(callback, context, message);
        });
    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) return (int)result;
    *handle = client;
    // Suppress our own output IO using the native identity, not a path/PID rule.
    // Retain Apple's default mute set; never unmute system-critical processes.
    audit_token_t self;
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    if (task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)&self, &count) != KERN_SUCCESS
        || es_mute_process(client, &self) != ES_RETURN_SUCCESS) return 1001;
    const es_event_type_t events[] = {
        ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXIT,
        ES_EVENT_TYPE_NOTIFY_CREATE, ES_EVENT_TYPE_NOTIFY_RENAME, ES_EVENT_TYPE_NOTIFY_UNLINK,
        ES_EVENT_TYPE_NOTIFY_CLOSE, ES_EVENT_TYPE_NOTIFY_WRITE
    };
    if (es_subscribe(client, events, sizeof(events) / sizeof(events[0])) != ES_RETURN_SUCCESS)
        return 1002;
    return 0;
}

int tf_es_close(void *handle) {
    // Destruction disconnects the client and frees its handler resources.
    return (int)es_delete_client((es_client_t *)handle);
}

// Explicit opt-in diagnostic: creates/deletes a client, never subscribes.
int tf_es_permission_probe(void) {
    es_client_t *client = NULL;
    es_new_client_result_t result = es_new_client(&client,
        ^(es_client_t *unused, const es_message_t *message) { (void)unused; (void)message; });
    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) return (int)result;
    return es_delete_client(client) == ES_RETURN_SUCCESS ? 0 : 1003;
}

void tf_es_test_fixture(tf_es_callback callback, void *context, uint32_t kind, uint32_t version) {
    // Fabricated evidence solely for bridge/ABI regression tests. No ES client.
    es_file_t file = {0};
    file.path = (es_string_token_t){sizeof("/tmp/ThreatFalcon-日本語") - 1, "/tmp/ThreatFalcon-日本語"};
    file.stat.st_ino = 42;
    file.stat.st_dev = 7;
    file.stat.st_mode = 0100600;
    es_process_t actor = {0}, target = {0};
    // audit_token_t layout is used only to fabricate fixtures, never to decode.
    actor.audit_token.val[5] = 123;
    actor.audit_token.val[7] = 9;
    actor.executable = &file;
    actor.start_time.tv_sec = 1700000000;
    target = actor;
    target.audit_token.val[7] = 10;
    if (kind == 2) target.audit_token.val[5] = 124;
    es_message_t message = {0};
    message.version = version;
    message.time.tv_sec = 1700000001;
    message.time.tv_nsec = 123456789;
    message.mach_time = 900;
    message.seq_num = 5;
    message.global_seq_num = 12;
    message.process = &actor;
    message.action_type = ES_ACTION_TYPE_NOTIFY;
    message.action.notify.result_type = ES_RESULT_TYPE_AUTH;
    message.action.notify.result.auth = ES_AUTH_RESULT_ALLOW;
    switch (kind) {
        case 1: message.event_type = ES_EVENT_TYPE_NOTIFY_EXEC; message.event.exec.target = &target; break;
        case 2: message.event_type = ES_EVENT_TYPE_NOTIFY_FORK; message.event.fork.child = &target; break;
        case 3: message.event_type = ES_EVENT_TYPE_NOTIFY_EXIT; message.event.exit.stat = 256; break;
        case 4:
            message.event_type = ES_EVENT_TYPE_NOTIFY_CREATE;
            message.event.create.destination_type = ES_DESTINATION_TYPE_EXISTING_FILE;
            message.event.create.destination.existing_file = &file;
            break;
        case 5:
            message.event_type = ES_EVENT_TYPE_NOTIFY_RENAME;
            message.event.rename.source = &file;
            message.event.rename.destination_type = ES_DESTINATION_TYPE_NEW_PATH;
            message.event.rename.destination.new_path.dir = &file;
            message.event.rename.destination.new_path.filename = (es_string_token_t){5, "moved"};
            break;
        case 6: message.event_type = ES_EVENT_TYPE_NOTIFY_UNLINK; message.event.unlink.target = &file; break;
        case 7:
            message.event_type = ES_EVENT_TYPE_NOTIFY_CLOSE;
            message.event.close.target = &file;
            message.event.close.modified = true;
            message.event.close.was_mapped_writable = true;
            break;
        case 8: message.event_type = ES_EVENT_TYPE_NOTIFY_WRITE; message.event.write.target = &file; break;
        case 9: // Denied CREATE notification: no observed created file.
            message.event_type = ES_EVENT_TYPE_NOTIFY_CREATE;
            message.action.notify.result.auth = ES_AUTH_RESULT_DENY;
            message.event.create.destination_type = ES_DESTINATION_TYPE_NEW_PATH;
            message.event.create.destination.new_path.dir = &file;
            message.event.create.destination.new_path.filename = (es_string_token_t){6, "denied"};
            break;
        case 10: // Rename over an existing destination.
            message.event_type = ES_EVENT_TYPE_NOTIFY_RENAME;
            message.event.rename.source = &file;
            message.event.rename.destination_type = ES_DESTINATION_TYPE_EXISTING_FILE;
            message.event.rename.destination.existing_file = &file;
            break;
        default: return;
    }
    emit(callback, context, &message);
}

size_t tf_es_record_size(void) { return sizeof(tf_es_record); }
size_t tf_es_record_alignment(void) { return _Alignof(tf_es_record); }
