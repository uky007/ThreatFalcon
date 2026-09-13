// Private, version-controlled bridge ABI. All borrowed strings live only during
// the synchronous callback; Rust must copy them before returning.
#ifndef THREATFALCON_MACOS_ES_H
#define THREATFALCON_MACOS_ES_H
#include <stddef.h>
#include <stdint.h>

typedef struct { const uint8_t *data; size_t length; } tf_es_string;
typedef struct {
    uint32_t pid, pidversion, euid, ruid, egid, rgid, auid, asid;
} tf_es_identity;
typedef struct {
    tf_es_string path;
    uint64_t inode;
    int32_t device;
    uint32_t mode, path_truncated, present;
} tf_es_file;
typedef struct {
    tf_es_identity identity, parent, responsible;
    tf_es_file executable;
    tf_es_string signing_id, team_id;
    uint8_t cdhash[20];
    uint32_t ppid, original_ppid, codesigning_flags;
    uint32_t is_platform_binary, is_es_client, has_parent, has_start_time, present;
    int64_t start_seconds, start_microseconds;
} tf_es_process;
typedef struct {
    uint32_t abi_version, message_version, native_event_type, kind;
    int64_t seconds, nanoseconds;
    uint64_t mach_time, seq_num, global_seq_num;
    uint32_t has_seq_num, has_global_seq_num;
    tf_es_process actor, target;
    tf_es_file file, destination;
    tf_es_string destination_name;
    uint32_t destination_is_new_path, modified, has_mapped_writable, mapped_writable;
    int32_t exit_status;
    uint32_t result_type, result_value;
} tf_es_record;

typedef void (*tf_es_callback)(void *, const tf_es_record *);
int tf_es_boot_uuid(char *, size_t);
// open and close MUST execute on the same OS thread.
// On setup failure, a non-null handle still needs to be closed.
int tf_es_open(void **, tf_es_callback, void *);
int tf_es_close(void *);
// Synthetic SDK-struct fixture. Does not connect to Endpoint Security.
void tf_es_test_fixture(tf_es_callback, void *, uint32_t, uint32_t);
size_t tf_es_record_size(void);
size_t tf_es_record_alignment(void);
#endif
