/* Portable, allocation-bounded nonblocking framing used by the Darwin broker
 * and its ordinary helper. This is transport, never containment evidence.
 * All callers retain their own work, cleanup, and lifecycle deadlines.
 */
#ifndef KNOWLEDGE_DARWIN_TRANSPORT_H
#define KNOWLEDGE_DARWIN_TRANSPORT_H

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define KVT_MAX_BODY (12u * 1024u * 1024u)
#define KVT_QUEUE_LIMIT (16u * 1024u * 1024u)
#define KVT_TURN_BYTES (128u * 1024u)
#define KVT_TURN_CALLS 32u
#define KVT_DEFAULT_TRANSPORT_MS 30000ull
#define KVT_DEFAULT_LIFECYCLE_MS 120000ull

enum KVTResult { KVT_ERROR = -1, KVT_INVALID = -2, KVT_EOF = -3,
    KVT_LIMIT = -4, KVT_WAIT = 0, KVT_READY = 1 };

struct KVTBuffer { unsigned char *bytes; size_t offset, length, capacity; };
struct KVTReader {
    unsigned char header[5];
    size_t header_used, body_used, body_length;
    unsigned char *body;
    uint64_t last_progress_ms;
    bool decoded, ready;
};

static inline struct pollfd kvtPollSlot(int fd, short events) {
    /* events=0 does not disable POLLHUP/POLLNVAL. Negative fd does. */
    struct pollfd slot = { events ? fd : -1, events, 0 }; return slot;
}

static inline bool kvtNonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL);
    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}
static inline uint64_t kvtDeadline(uint64_t started, uint64_t duration) {
    return UINT64_MAX - started < duration ? UINT64_MAX : started + duration;
}
static inline bool kvtExpired(uint64_t now, uint64_t started, uint64_t duration) {
    return now >= started && now - started >= duration;
}
static inline void kvtBufferClear(struct KVTBuffer *buffer) {
    free(buffer->bytes); memset(buffer, 0, sizeof(*buffer));
}
static inline bool kvtReserve(struct KVTBuffer *buffer, size_t extra, size_t limit) {
    if (extra > limit || buffer->length > limit - extra) return false;
    size_t needed = buffer->length + extra;
    if (needed <= buffer->capacity) {
        if (buffer->offset && buffer->capacity - buffer->offset < needed) {
            memmove(buffer->bytes, buffer->bytes + buffer->offset, buffer->length);
            buffer->offset = 0;
        }
        return true;
    }
    size_t capacity = buffer->capacity ? buffer->capacity : 4096;
    while (capacity < needed) {
        if (capacity > limit / 2) { capacity = limit; break; }
        capacity *= 2;
    }
    if (capacity > limit) capacity = limit;
    unsigned char *replacement = malloc(capacity);
    if (!replacement) return false;
    if (buffer->length) memcpy(replacement, buffer->bytes + buffer->offset, buffer->length);
    free(buffer->bytes); buffer->bytes = replacement; buffer->capacity = capacity; buffer->offset = 0;
    return true;
}
static inline bool kvtAppend(struct KVTBuffer *buffer, const void *bytes, size_t length, size_t limit) {
    if (!kvtReserve(buffer, length, limit)) return false;
    if (length) memcpy(buffer->bytes + buffer->offset + buffer->length, bytes, length);
    buffer->length += length; return true;
}
static inline bool kvtQueueFrame(struct KVTBuffer *buffer, unsigned char type,
                                 const void *body, size_t length, bool response) {
    size_t header = response ? 5 : 4;
    if (length > KVT_MAX_BODY || (!response && !length) ||
        !kvtReserve(buffer, header + length, KVT_QUEUE_LIMIT)) return false;
    unsigned char *target = buffer->bytes + buffer->offset + buffer->length;
    if (response) *target++ = type;
    uint32_t wire = htonl((uint32_t)length); memcpy(target, &wire, 4);
    if (length) memcpy(target + 4, body, length);
    buffer->length += header + length; return true;
}
static inline int kvtFlush(int fd, struct KVTBuffer *buffer, size_t budget, bool socket,
                           uint64_t now, uint64_t *last_progress) {
    for (unsigned calls = 0; buffer->length && budget && calls < KVT_TURN_CALLS; calls++) {
        size_t amount = buffer->length < budget ? buffer->length : budget;
        ssize_t written;
        if (socket) {
            int flags = MSG_DONTWAIT;
#ifdef MSG_NOSIGNAL
            flags |= MSG_NOSIGNAL;
#endif
            written = send(fd, buffer->bytes + buffer->offset, amount, flags);
        } else written = write(fd, buffer->bytes + buffer->offset, amount);
        if (written < 0 && errno == EINTR) continue;
        if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return KVT_WAIT;
        if (written <= 0) return KVT_ERROR;
        buffer->offset += (size_t)written; buffer->length -= (size_t)written; budget -= (size_t)written;
        if (last_progress) *last_progress = now;
    }
    if (!buffer->length) { buffer->offset = 0; return KVT_READY; }
    return KVT_WAIT;
}
static inline void kvtReaderClear(struct KVTReader *reader) {
    free(reader->body); memset(reader, 0, sizeof(*reader));
}
static inline int kvtRead(int fd, struct KVTReader *reader, bool response, size_t budget, uint64_t now) {
    if (reader->ready) return KVT_READY;
    const size_t header_size = response ? 5 : 4;
    for (unsigned calls = 0; budget && calls < KVT_TURN_CALLS; calls++) {
        if (reader->header_used == header_size && !reader->decoded) {
            uint32_t wire; memcpy(&wire, reader->header + (response ? 1 : 0), 4);
            reader->body_length = ntohl(wire); reader->decoded = true;
            if (reader->body_length > KVT_MAX_BODY || (!response && !reader->body_length)) return KVT_INVALID;
            if (response && reader->header[0] != 'J' && reader->header[0] != 'O' && reader->header[0] != 'E') return KVT_INVALID;
            if (reader->body_length) {
                reader->body = malloc(reader->body_length);
                if (!reader->body) return KVT_LIMIT;
            }
        }
        if (reader->decoded && reader->body_used == reader->body_length) { reader->ready = true; return KVT_READY; }
        unsigned char *target; size_t remaining;
        if (reader->header_used < header_size) {
            target = reader->header + reader->header_used; remaining = header_size - reader->header_used;
        } else { target = reader->body + reader->body_used; remaining = reader->body_length - reader->body_used; }
        if (remaining > budget) remaining = budget;
        ssize_t received = recv(fd, target, remaining, MSG_DONTWAIT);
        if (received < 0 && errno == EINTR) continue;
        if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return KVT_WAIT;
        if (received < 0) return KVT_ERROR;
        if (!received) return KVT_EOF;
        if (reader->header_used < header_size) reader->header_used += (size_t)received;
        else reader->body_used += (size_t)received;
        budget -= (size_t)received; reader->last_progress_ms = now;
    }
    return KVT_WAIT;
}

#endif
