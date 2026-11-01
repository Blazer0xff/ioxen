// Minimal libxpc stand-in for exercising agent/ios_script.js on Linux.
//
// It implements the subset of the public libxpc C API the ioxen iOS agent
// calls, with the same calling conventions and block-based handlers (built
// with clang -fblocks against libBlocksRuntime). "Remote" peers are
// simulated: sent messages are printed as "SENT <message>", replies and
// incoming messages are delivered to the registered blocks.
//
// Build: clang -fblocks -shared -fPIC mock_libxpc.c -o libmockxpc.so -lBlocksRuntime -lpthread

#include <Block.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct xpc_type { const char *name; };

const struct xpc_type _xpc_type_dictionary = { "dictionary" };
const struct xpc_type _xpc_type_array = { "array" };
const struct xpc_type _xpc_type_string = { "string" };
const struct xpc_type _xpc_type_int64 = { "int64" };
const struct xpc_type _xpc_type_uint64 = { "uint64" };
const struct xpc_type _xpc_type_bool = { "bool" };
const struct xpc_type _xpc_type_double = { "double" };
const struct xpc_type _xpc_type_data = { "data" };
const struct xpc_type _xpc_type_null = { "null" };
const struct xpc_type _xpc_type_error = { "error" };
const struct xpc_type _xpc_type_connection = { "connection" };

#define MAX_ITEMS 64

typedef struct xobj xobj;
typedef void (^xpc_handler_t)(xobj *);

struct xobj {
  const struct xpc_type *type;
  int count;
  char *keys[MAX_ITEMS];
  xobj *values[MAX_ITEMS];
  char *str;
  int64_t i64;
  uint64_t u64;
  double dbl;
  bool boolean;
  uint8_t *bytes;
  size_t length;
  // connections
  char *name;
  xpc_handler_t handler;
  int cancelled;
};

xobj _xpc_bool_true = { .type = &_xpc_type_bool, .boolean = true };
xobj _xpc_bool_false = { .type = &_xpc_type_bool, .boolean = false };
xobj _xpc_error_connection_interrupted = { .type = &_xpc_type_error, .str = "Connection interrupted" };
xobj _xpc_error_connection_invalid = { .type = &_xpc_type_error, .str = "Connection invalid" };

static xobj *new_obj(const struct xpc_type *type) {
  xobj *o = calloc(1, sizeof(xobj));
  o->type = type;
  return o;
}

const void *xpc_get_type(xobj *o) { return o->type; }
xobj *xpc_retain(xobj *o) { return o; }
void xpc_release(xobj *o) { (void)o; }

xobj *xpc_dictionary_create(const char *const *keys, xobj *const *values, size_t count) {
  (void)keys; (void)values; (void)count;
  return new_obj(&_xpc_type_dictionary);
}

static int dict_index(xobj *d, const char *key) {
  for (int i = 0; i < d->count; i++) {
    if (strcmp(d->keys[i], key) == 0) return i;
  }
  return -1;
}

void xpc_dictionary_set_value(xobj *d, const char *key, xobj *value) {
  int i = dict_index(d, key);
  if (value == NULL) {
    if (i < 0) return;
    free(d->keys[i]);
    for (int j = i; j < d->count - 1; j++) {
      d->keys[j] = d->keys[j + 1];
      d->values[j] = d->values[j + 1];
    }
    d->count--;
    return;
  }
  if (i >= 0) {
    d->values[i] = value;
    return;
  }
  if (d->count >= MAX_ITEMS) return;
  d->keys[d->count] = strdup(key);
  d->values[d->count] = value;
  d->count++;
}

xobj *xpc_dictionary_get_value(xobj *d, const char *key) {
  int i = dict_index(d, key);
  return i < 0 ? NULL : d->values[i];
}

bool xpc_dictionary_apply(xobj *d, bool (^applier)(const char *, xobj *)) {
  for (int i = 0; i < d->count; i++) {
    if (!applier(d->keys[i], d->values[i])) return false;
  }
  return true;
}

xobj *xpc_string_create(const char *s) { xobj *o = new_obj(&_xpc_type_string); o->str = strdup(s); return o; }
xobj *xpc_int64_create(int64_t v) { xobj *o = new_obj(&_xpc_type_int64); o->i64 = v; return o; }
xobj *xpc_uint64_create(uint64_t v) { xobj *o = new_obj(&_xpc_type_uint64); o->u64 = v; return o; }
xobj *xpc_double_create(double v) { xobj *o = new_obj(&_xpc_type_double); o->dbl = v; return o; }
xobj *xpc_bool_create(bool v) { return v ? &_xpc_bool_true : &_xpc_bool_false; }
xobj *xpc_data_create(const void *bytes, size_t length) {
  xobj *o = new_obj(&_xpc_type_data);
  o->bytes = malloc(length ? length : 1);
  memcpy(o->bytes, bytes, length);
  o->length = length;
  return o;
}

void xpc_dictionary_set_string(xobj *d, const char *k, const char *v) { xpc_dictionary_set_value(d, k, xpc_string_create(v)); }
void xpc_dictionary_set_int64(xobj *d, const char *k, int64_t v) { xpc_dictionary_set_value(d, k, xpc_int64_create(v)); }
void xpc_dictionary_set_uint64(xobj *d, const char *k, uint64_t v) { xpc_dictionary_set_value(d, k, xpc_uint64_create(v)); }
void xpc_dictionary_set_bool(xobj *d, const char *k, bool v) { xpc_dictionary_set_value(d, k, xpc_bool_create(v)); }
void xpc_dictionary_set_double(xobj *d, const char *k, double v) { xpc_dictionary_set_value(d, k, xpc_double_create(v)); }
void xpc_dictionary_set_data(xobj *d, const char *k, const void *b, size_t n) { xpc_dictionary_set_value(d, k, xpc_data_create(b, n)); }

const char *xpc_dictionary_get_string(xobj *d, const char *k) {
  xobj *v = xpc_dictionary_get_value(d, k);
  return v && v->type == &_xpc_type_string ? v->str : NULL;
}

xobj *xpc_array_create(xobj *const *objects, size_t count) { (void)objects; (void)count; return new_obj(&_xpc_type_array); }
void xpc_array_append_value(xobj *a, xobj *v) { if (a->count < MAX_ITEMS) a->values[a->count++] = v; }
size_t xpc_array_get_count(xobj *a) { return (size_t)a->count; }
xobj *xpc_array_get_value(xobj *a, size_t i) { return (int)i < a->count ? a->values[i] : NULL; }

const char *xpc_string_get_string_ptr(xobj *o) { return o->str; }
int64_t xpc_int64_get_value(xobj *o) { return o->i64; }
uint64_t xpc_uint64_get_value(xobj *o) { return o->u64; }
bool xpc_bool_get_value(xobj *o) { return o->boolean; }
double xpc_double_get_value(xobj *o) { return o->dbl; }
size_t xpc_data_get_length(xobj *o) { return o->length; }
const void *xpc_data_get_bytes_ptr(xobj *o) { return o->bytes; }

static void describe(xobj *o, char *buf, size_t size) {
  size_t used = strlen(buf);
  if (used >= size - 1) return;
  char *p = buf + used;
  size_t left = size - used;
  if (o == NULL) { snprintf(p, left, "NULL"); return; }
  if (o->type == &_xpc_type_dictionary) {
    snprintf(p, left, "{");
    for (int i = 0; i < o->count; i++) {
      size_t l = strlen(buf);
      snprintf(buf + l, size - l, "%s%s=", i ? "," : "", o->keys[i]);
      describe(o->values[i], buf, size);
    }
    size_t l = strlen(buf);
    snprintf(buf + l, size - l, "}");
  } else if (o->type == &_xpc_type_array) {
    snprintf(p, left, "[");
    for (int i = 0; i < o->count; i++) {
      size_t l = strlen(buf);
      if (i) snprintf(buf + l, size - l, ",");
      describe(o->values[i], buf, size);
    }
    size_t l = strlen(buf);
    snprintf(buf + l, size - l, "]");
  } else if (o->type == &_xpc_type_string) snprintf(p, left, "'%s'", o->str);
  else if (o->type == &_xpc_type_int64) snprintf(p, left, "i%lld", (long long)o->i64);
  else if (o->type == &_xpc_type_uint64) snprintf(p, left, "u%llu", (unsigned long long)o->u64);
  else if (o->type == &_xpc_type_bool) snprintf(p, left, o->boolean ? "true" : "false");
  else if (o->type == &_xpc_type_double) snprintf(p, left, "d%g", o->dbl);
  else if (o->type == &_xpc_type_data) {
    snprintf(p, left, "<");
    for (size_t i = 0; i < o->length && i < 16; i++) {
      size_t l = strlen(buf);
      snprintf(buf + l, size - l, "%02x", o->bytes[i]);
    }
    size_t l = strlen(buf);
    snprintf(buf + l, size - l, ">");
  } else if (o->type == &_xpc_type_error) snprintf(p, left, "error:%s", o->str);
  else if (o->type == &_xpc_type_connection) snprintf(p, left, "connection:%s", o->name ? o->name : "peer");
  else snprintf(p, left, "?");
}

void mock_describe(xobj *o, char *buf, size_t size) {
  buf[0] = 0;
  describe(o, buf, size);
}

char *xpc_copy_description(xobj *o) {
  char *buf = calloc(1, 4096);
  describe(o, buf, 4096);
  return buf;
}

// --- Connections -------------------------------------------------------------

xobj *xpc_connection_create_mach_service(const char *name, void *queue, uint64_t flags) {
  (void)queue; (void)flags;
  xobj *c = new_obj(&_xpc_type_connection);
  c->name = name ? strdup(name) : NULL;
  return c;
}

xobj *xpc_connection_create(const char *name, void *queue) {
  return xpc_connection_create_mach_service(name, queue, 0);
}

const char *xpc_connection_get_name(xobj *c) { return c->name; }
int xpc_connection_get_pid(xobj *c) { (void)c; return 1; }
unsigned int xpc_connection_get_euid(xobj *c) { (void)c; return 501; }
void xpc_connection_resume(xobj *c) { (void)c; }

void xpc_connection_cancel(xobj *c) {
  c->cancelled = 1;
  printf("CANCELLED %s\n", c->name ? c->name : "peer");
  fflush(stdout);
}

void xpc_connection_set_event_handler(xobj *c, xpc_handler_t handler) {
  c->handler = Block_copy(handler);
}

static void print_sent(xobj *msg) {
  char buf[4096];
  mock_describe(msg, buf, sizeof(buf));
  printf("SENT %s\n", buf);
  fflush(stdout);
}

static xobj *make_reply(xobj *msg) {
  xobj *reply = xpc_dictionary_create(NULL, NULL, 0);
  xpc_dictionary_set_string(reply, "reply", "pong");
  xobj *n = xpc_dictionary_get_value(msg, "n");
  if (n != NULL) xpc_dictionary_set_value(reply, "echo", n);
  return reply;
}

void xpc_connection_send_message(xobj *c, xobj *msg) {
  (void)c;
  print_sent(msg);
}

struct reply_job { xpc_handler_t handler; xobj *reply; };

static void *reply_thread(void *arg) {
  struct reply_job *job = arg;
  job->handler(job->reply);
  Block_release(job->handler);
  free(job);
  return NULL;
}

// Replies are delivered asynchronously, like libxpc does on the target queue.
void xpc_connection_send_message_with_reply(xobj *c, xobj *msg, void *queue, xpc_handler_t handler) {
  (void)c; (void)queue;
  print_sent(msg);
  struct reply_job *job = malloc(sizeof(*job));
  job->handler = Block_copy(handler);
  job->reply = make_reply(msg);
  pthread_t thread;
  pthread_create(&thread, NULL, reply_thread, job);
  pthread_detach(thread);
}

xobj *xpc_connection_send_message_with_reply_sync(xobj *c, xobj *msg) {
  (void)c;
  print_sent(msg);
  return make_reply(msg);
}

// Test hook: deliver an incoming event to the connection's handler.
void mock_deliver(xobj *c, xobj *event) {
  if (c->handler) c->handler(event);
}
