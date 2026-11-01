// Test client for tests/test_ios_agent_xpc.py: runs XPC operations against
// the mock libxpc when asked on stdin, one command per line.
//
// Build: clang -fblocks xpc_driver.c -o xpc_driver -L. -lmockxpc -lBlocksRuntime -Wl,-rpath,'$ORIGIN'

#include <Block.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

typedef struct xobj xobj;
typedef void (^xpc_handler_t)(xobj *);

xobj *xpc_dictionary_create(const char *const *keys, xobj *const *values, size_t count);
void xpc_dictionary_set_string(xobj *d, const char *k, const char *v);
void xpc_dictionary_set_int64(xobj *d, const char *k, int64_t v);
void xpc_dictionary_set_bool(xobj *d, const char *k, bool v);
void xpc_dictionary_set_value(xobj *d, const char *k, xobj *v);
void xpc_dictionary_set_data(xobj *d, const char *k, const void *b, size_t n);
xobj *xpc_array_create(xobj *const *objects, size_t count);
void xpc_array_append_value(xobj *a, xobj *v);
xobj *xpc_string_create(const char *s);
xobj *xpc_uint64_create(uint64_t v);
xobj *xpc_connection_create_mach_service(const char *name, void *queue, uint64_t flags);
void xpc_connection_set_event_handler(xobj *c, xpc_handler_t handler);
void xpc_connection_resume(xobj *c);
void xpc_connection_send_message(xobj *c, xobj *msg);
void xpc_connection_send_message_with_reply(xobj *c, xobj *msg, void *queue, xpc_handler_t handler);
xobj *xpc_connection_send_message_with_reply_sync(xobj *c, xobj *msg);
void mock_deliver(xobj *c, xobj *event);
void mock_describe(xobj *o, char *buf, size_t size);

static void print_obj(const char *tag, xobj *o) {
  char buf[4096];
  mock_describe(o, buf, sizeof(buf));
  printf("%s %s\n", tag, buf);
  fflush(stdout);
}

static xobj *request(void) {
  static const char nsxpc[] = "bplist16\x00\x01ping:\x00\x02NSString";
  xobj *d = xpc_dictionary_create(NULL, NULL, 0);
  xpc_dictionary_set_string(d, "op", "ping");
  xpc_dictionary_set_int64(d, "n", 7);
  xobj *nested = xpc_dictionary_create(NULL, NULL, 0);
  xpc_dictionary_set_bool(nested, "flag", true);
  xpc_dictionary_set_value(d, "nested", nested);
  xobj *list = xpc_array_create(NULL, 0);
  xpc_array_append_value(list, xpc_string_create("a"));
  xpc_array_append_value(list, xpc_uint64_create(2));
  xpc_dictionary_set_value(d, "list", list);
  xpc_dictionary_set_data(d, "root", nsxpc, sizeof(nsxpc) - 1);
  return d;
}

int main(void) {
  char line[128];
  xobj *conn = NULL;
  xobj *listener = NULL;
  setvbuf(stdout, NULL, _IOLBF, 0);
  printf("STARTED\n");
  fflush(stdout);

  while (fgets(line, sizeof(line), stdin) != NULL) {
    line[strcspn(line, "\n")] = 0;
    if (strcmp(line, "setup") == 0) {
      conn = xpc_connection_create_mach_service("com.example.svc", NULL, 0);
      xpc_connection_set_event_handler(conn, ^(xobj *event) { print_obj("HANDLER", event); });
      xpc_connection_resume(conn);
      listener = xpc_connection_create_mach_service("com.example.listener", NULL, 1);
      xpc_connection_set_event_handler(listener, ^(xobj *peer) { print_obj("PEER", peer); });
    } else if (strcmp(line, "send") == 0) {
      xpc_connection_send_message(conn, request());
    } else if (strcmp(line, "reply") == 0) {
      xpc_connection_send_message_with_reply(conn, request(), NULL, ^(xobj *reply) { print_obj("REPLY", reply); });
    } else if (strcmp(line, "sync") == 0) {
      print_obj("SYNC", xpc_connection_send_message_with_reply_sync(conn, request()));
    } else if (strcmp(line, "incoming") == 0) {
      xobj *event = xpc_dictionary_create(NULL, NULL, 0);
      xpc_dictionary_set_string(event, "cmd", "hello");
      mock_deliver(conn, event);
    } else if (strcmp(line, "peer") == 0) {
      mock_deliver(listener, xpc_connection_create_mach_service(NULL, NULL, 0));
    } else if (strcmp(line, "quit") == 0) {
      break;
    }
    printf("DONE %s\n", line);
    fflush(stdout);
  }
  return 0;
}
