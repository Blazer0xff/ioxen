(() => {
  // node_modules/frida-objc-bridge/lib/api.js
  var cachedApi = null;
  var defaultInvocationOptions = {
    exceptions: "propagate"
  };
  function getApi() {
    if (cachedApi !== null) {
      return cachedApi;
    }
    const temporaryApi = {};
    const pending = [
      {
        module: "libsystem_malloc.dylib",
        functions: {
          "free": ["void", ["pointer"]]
        }
      },
      {
        module: "libobjc.A.dylib",
        functions: {
          "objc_msgSend": function(address) {
            this.objc_msgSend = address;
          },
          "objc_msgSend_stret": function(address) {
            this.objc_msgSend_stret = address;
          },
          "objc_msgSend_fpret": function(address) {
            this.objc_msgSend_fpret = address;
          },
          "objc_msgSendSuper": function(address) {
            this.objc_msgSendSuper = address;
          },
          "objc_msgSendSuper_stret": function(address) {
            this.objc_msgSendSuper_stret = address;
          },
          "objc_msgSendSuper_fpret": function(address) {
            this.objc_msgSendSuper_fpret = address;
          },
          "objc_getClassList": ["int", ["pointer", "int"]],
          "objc_lookUpClass": ["pointer", ["pointer"]],
          "objc_allocateClassPair": ["pointer", ["pointer", "pointer", "pointer"]],
          "objc_disposeClassPair": ["void", ["pointer"]],
          "objc_registerClassPair": ["void", ["pointer"]],
          "class_isMetaClass": ["bool", ["pointer"]],
          "class_getName": ["pointer", ["pointer"]],
          "class_getImageName": ["pointer", ["pointer"]],
          "class_copyProtocolList": ["pointer", ["pointer", "pointer"]],
          "class_copyMethodList": ["pointer", ["pointer", "pointer"]],
          "class_getClassMethod": ["pointer", ["pointer", "pointer"]],
          "class_getInstanceMethod": ["pointer", ["pointer", "pointer"]],
          "class_getSuperclass": ["pointer", ["pointer"]],
          "class_addProtocol": ["bool", ["pointer", "pointer"]],
          "class_addMethod": ["bool", ["pointer", "pointer", "pointer", "pointer"]],
          "class_copyIvarList": ["pointer", ["pointer", "pointer"]],
          "objc_getProtocol": ["pointer", ["pointer"]],
          "objc_copyProtocolList": ["pointer", ["pointer"]],
          "objc_allocateProtocol": ["pointer", ["pointer"]],
          "objc_registerProtocol": ["void", ["pointer"]],
          "protocol_getName": ["pointer", ["pointer"]],
          "protocol_copyMethodDescriptionList": ["pointer", ["pointer", "bool", "bool", "pointer"]],
          "protocol_copyPropertyList": ["pointer", ["pointer", "pointer"]],
          "protocol_copyProtocolList": ["pointer", ["pointer", "pointer"]],
          "protocol_addProtocol": ["void", ["pointer", "pointer"]],
          "protocol_addMethodDescription": ["void", ["pointer", "pointer", "pointer", "bool", "bool"]],
          "ivar_getName": ["pointer", ["pointer"]],
          "ivar_getTypeEncoding": ["pointer", ["pointer"]],
          "ivar_getOffset": ["pointer", ["pointer"]],
          "object_isClass": ["bool", ["pointer"]],
          "object_getClass": ["pointer", ["pointer"]],
          "object_getClassName": ["pointer", ["pointer"]],
          "method_getName": ["pointer", ["pointer"]],
          "method_getTypeEncoding": ["pointer", ["pointer"]],
          "method_getImplementation": ["pointer", ["pointer"]],
          "method_setImplementation": ["pointer", ["pointer", "pointer"]],
          "property_getName": ["pointer", ["pointer"]],
          "property_copyAttributeList": ["pointer", ["pointer", "pointer"]],
          "sel_getName": ["pointer", ["pointer"]],
          "sel_registerName": ["pointer", ["pointer"]],
          "class_getInstanceSize": ["pointer", ["pointer"]]
        },
        optionals: {
          "objc_msgSend_stret": "ABI",
          "objc_msgSend_fpret": "ABI",
          "objc_msgSendSuper_stret": "ABI",
          "objc_msgSendSuper_fpret": "ABI",
          "object_isClass": "iOS8"
        }
      },
      {
        module: "libdispatch.dylib",
        functions: {
          "dispatch_async_f": ["void", ["pointer", "pointer", "pointer"]]
        },
        variables: {
          "_dispatch_main_q": function(address) {
            this._dispatch_main_q = address;
          }
        }
      }
    ];
    let remaining = 0;
    pending.forEach(function(api2) {
      const functions = api2.functions || {};
      const variables = api2.variables || {};
      const optionals = api2.optionals || {};
      remaining += Object.keys(functions).length + Object.keys(variables).length;
      const exportByName = (Process.findModuleByName(api2.module)?.enumerateExports() ?? []).reduce(function(result, exp) {
        result[exp.name] = exp;
        return result;
      }, {});
      Object.keys(functions).forEach(function(name) {
        const exp = exportByName[name];
        if (exp !== void 0 && exp.type === "function") {
          const signature2 = functions[name];
          if (typeof signature2 === "function") {
            signature2.call(temporaryApi, exp.address);
          } else {
            temporaryApi[name] = new NativeFunction(exp.address, signature2[0], signature2[1], defaultInvocationOptions);
          }
          remaining--;
        } else {
          const optional = optionals[name];
          if (optional)
            remaining--;
        }
      });
      Object.keys(variables).forEach(function(name) {
        const exp = exportByName[name];
        if (exp !== void 0 && exp.type === "variable") {
          const handler = variables[name];
          handler.call(temporaryApi, exp.address);
          remaining--;
        }
      });
    });
    if (remaining === 0) {
      if (!temporaryApi.objc_msgSend_stret)
        temporaryApi.objc_msgSend_stret = temporaryApi.objc_msgSend;
      if (!temporaryApi.objc_msgSend_fpret)
        temporaryApi.objc_msgSend_fpret = temporaryApi.objc_msgSend;
      if (!temporaryApi.objc_msgSendSuper_stret)
        temporaryApi.objc_msgSendSuper_stret = temporaryApi.objc_msgSendSuper;
      if (!temporaryApi.objc_msgSendSuper_fpret)
        temporaryApi.objc_msgSendSuper_fpret = temporaryApi.objc_msgSendSuper;
      cachedApi = temporaryApi;
    }
    return cachedApi;
  }

  // node_modules/frida-objc-bridge/lib/fastpaths.js
  var code = `#include <glib.h>
#include <ptrauth.h>

#define KERN_SUCCESS 0
#define MALLOC_PTR_IN_USE_RANGE_TYPE 1
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
# define OBJC_ISA_MASK 0x7ffffffffff8ULL
#elif defined (HAVE_ARM64)
# define OBJC_ISA_MASK 0xffffffff8ULL
#endif

typedef struct _ChooseContext ChooseContext;

typedef struct _malloc_zone_t malloc_zone_t;
typedef struct _malloc_introspection_t malloc_introspection_t;
typedef struct _vm_range_t vm_range_t;

typedef gpointer Class;
typedef int kern_return_t;
typedef guint mach_port_t;
typedef mach_port_t task_t;
typedef guintptr vm_offset_t;
typedef guintptr vm_size_t;
typedef vm_offset_t vm_address_t;

struct _ChooseContext
{
  GHashTable * classes;
  GArray * matches;
};

struct _malloc_zone_t
{
  void * reserved1;
  void * reserved2;
  size_t (* size) (struct _malloc_zone_t * zone, const void * ptr);
  void * (* malloc) (struct _malloc_zone_t * zone, size_t size);
  void * (* calloc) (struct _malloc_zone_t * zone, size_t num_items, size_t size);
  void * (* valloc) (struct _malloc_zone_t * zone, size_t size);
  void (* free) (struct _malloc_zone_t * zone, void * ptr);
  void * (* realloc) (struct _malloc_zone_t * zone, void * ptr, size_t size);
  void (* destroy) (struct _malloc_zone_t * zone);
  const char * zone_name;

  unsigned (* batch_malloc) (struct _malloc_zone_t * zone, size_t size, void ** results, unsigned num_requested);
  void (* batch_free) (struct _malloc_zone_t * zone, void ** to_be_freed, unsigned num_to_be_freed);

  malloc_introspection_t * introspect;
};

typedef kern_return_t (* memory_reader_t) (task_t remote_task, vm_address_t remote_address, vm_size_t size, void ** local_memory);
typedef void (* vm_range_recorder_t) (task_t task, void * user_data, unsigned type, vm_range_t * ranges, unsigned count);
typedef kern_return_t (* enumerator_func) (task_t task, void * user_data, unsigned type_mask, vm_address_t zone_address, memory_reader_t reader,
      vm_range_recorder_t recorder);

struct _malloc_introspection_t
{
  enumerator_func enumerator;
};

struct _vm_range_t
{
  vm_address_t address;
  vm_size_t size;
};

extern int objc_getClassList (Class * buffer, int buffer_count);
extern Class class_getSuperclass (Class cls);
extern size_t class_getInstanceSize (Class cls);
extern kern_return_t malloc_get_all_zones (task_t task, memory_reader_t reader, vm_address_t ** addresses, unsigned * count);

static void collect_subclasses (Class klass, GHashTable * result);
static void collect_matches_in_ranges (task_t task, void * user_data, unsigned type, vm_range_t * ranges, unsigned count);
static kern_return_t read_local_memory (task_t remote_task, vm_address_t remote_address, vm_size_t size, void ** local_memory);

extern mach_port_t selfTask;

gpointer *
choose (Class * klass,
        gboolean consider_subclasses,
        guint * count)
{
  ChooseContext ctx;
  GHashTable * classes;
  vm_address_t * malloc_zone_addresses;
  unsigned malloc_zone_count, i;

  classes = g_hash_table_new_full (NULL, NULL, NULL, NULL);
  ctx.classes = classes;
  ctx.matches = g_array_new (FALSE, FALSE, sizeof (gpointer));
  if (consider_subclasses)
    collect_subclasses (klass, classes);
  else
    g_hash_table_insert (classes, klass, GSIZE_TO_POINTER (class_getInstanceSize (klass)));

  malloc_zone_count = 0;
  malloc_get_all_zones (selfTask, read_local_memory, &malloc_zone_addresses, &malloc_zone_count);

  for (i = 0; i != malloc_zone_count; i++)
  {
    vm_address_t zone_address = malloc_zone_addresses[i];
    malloc_zone_t * zone = (malloc_zone_t *) zone_address;
    enumerator_func enumerator;

    if (zone != NULL && zone->introspect != NULL &&
        (enumerator = (ptrauth_strip (zone->introspect, ptrauth_key_asda))->enumerator) != NULL)
    {
      enumerator = ptrauth_sign_unauthenticated (
          ptrauth_strip (enumerator, ptrauth_key_asia),
          ptrauth_key_asia, 0);

      enumerator (selfTask, &ctx, MALLOC_PTR_IN_USE_RANGE_TYPE, zone_address, read_local_memory,
          collect_matches_in_ranges);
    }
  }

  g_hash_table_unref (classes);

  *count = ctx.matches->len;

  return (gpointer *) g_array_free (ctx.matches, FALSE);
}

void
destroy (gpointer mem)
{
  g_free (mem);
}

static void
collect_subclasses (Class klass,
                    GHashTable * result)
{
  Class * classes;
  int buffer_count, count, i;

  buffer_count = objc_getClassList (NULL, 0);
  classes = g_malloc (buffer_count * sizeof (gpointer));
  count = objc_getClassList (classes, buffer_count);
  if (count > buffer_count)
    count = buffer_count;

  for (i = 0; i != count; i++)
  {
    Class candidate = classes[i];
    Class c;

    c = candidate;
    do
    {
      if (c == klass)
      {
        g_hash_table_insert (result, candidate, GSIZE_TO_POINTER (class_getInstanceSize (candidate)));
        break;
      }

      c = class_getSuperclass (c);
    }
    while (c != NULL);
  }

  g_free (classes);
}

static void
collect_matches_in_ranges (task_t task,
                           void * user_data,
                           unsigned type,
                           vm_range_t * ranges,
                           unsigned count)
{
  ChooseContext * ctx = user_data;
  GHashTable * classes = ctx->classes;
  unsigned i;

  for (i = 0; i != count; i++)
  {
    const vm_range_t * range = &ranges[i];
    gconstpointer candidate = GSIZE_TO_POINTER (range->address);
    gconstpointer isa;
    guint instance_size;

    isa = *(gconstpointer *) candidate;
#ifdef OBJC_ISA_MASK
    isa = GSIZE_TO_POINTER (GPOINTER_TO_SIZE (isa) & OBJC_ISA_MASK);
#endif

    instance_size = GPOINTER_TO_UINT (g_hash_table_lookup (classes, isa));
    if (instance_size != 0 && range->size >= instance_size)
    {
      g_array_append_val (ctx->matches, candidate);
    }
  }
}

static kern_return_t
read_local_memory (task_t remote_task,
                   vm_address_t remote_address,
                   vm_size_t size,
                   void ** local_memory)
{
  *local_memory = (void *) remote_address;

  return KERN_SUCCESS;
}
`;
  var { pointerSize: pointerSize2 } = Process;
  var cachedModule = null;
  function get() {
    if (cachedModule === null)
      cachedModule = compileModule();
    return cachedModule;
  }
  function compileModule() {
    const {
      objc_getClassList,
      class_getSuperclass,
      class_getInstanceSize
    } = getApi();
    const selfTask = Memory.alloc(4);
    selfTask.writeU32(Module.getGlobalExportByName("mach_task_self_").readU32());
    const cm = new CModule(code, {
      objc_getClassList,
      class_getSuperclass,
      class_getInstanceSize,
      malloc_get_all_zones: Process.getModuleByName("/usr/lib/system/libsystem_malloc.dylib").getExportByName("malloc_get_all_zones"),
      selfTask
    });
    const _choose = new NativeFunction(cm.choose, "pointer", ["pointer", "bool", "pointer"]);
    const _destroy = new NativeFunction(cm.destroy, "void", ["pointer"]);
    return {
      handle: cm,
      choose(klass, considerSubclasses) {
        const result = [];
        const countPtr = Memory.alloc(4);
        const matches = _choose(klass, considerSubclasses ? 1 : 0, countPtr);
        try {
          const count = countPtr.readU32();
          for (let i = 0; i !== count; i++)
            result.push(matches.add(i * pointerSize2).readPointer());
        } finally {
          _destroy(matches);
        }
        return result;
      }
    };
  }

  // node_modules/frida-objc-bridge/index.js
  function Runtime() {
    const pointerSize = Process.pointerSize;
    let api = null;
    let apiError = null;
    const realizedClasses = /* @__PURE__ */ new Set();
    const classRegistry = new ClassRegistry();
    const protocolRegistry = new ProtocolRegistry();
    const replacedMethods = /* @__PURE__ */ new Map();
    const scheduledWork = /* @__PURE__ */ new Map();
    let nextId = 1;
    let workCallback = null;
    let NSAutoreleasePool = null;
    const bindings = /* @__PURE__ */ new Map();
    let readObjectIsa = null;
    const msgSendBySignatureId = /* @__PURE__ */ new Map();
    const msgSendSuperBySignatureId = /* @__PURE__ */ new Map();
    let cachedNSString = null;
    let cachedNSStringCtor = null;
    let cachedNSNumber = null;
    let cachedNSNumberCtor = null;
    let singularTypeById = null;
    let modifiers = null;
    try {
      tryInitialize();
    } catch (e) {
    }
    function tryInitialize() {
      if (api !== null)
        return true;
      if (apiError !== null)
        throw apiError;
      try {
        api = getApi();
      } catch (e) {
        apiError = e;
        throw e;
      }
      return api !== null;
    }
    function dispose() {
      for (const [rawMethodHandle, impls] of replacedMethods.entries()) {
        const methodHandle = ptr(rawMethodHandle);
        const [oldImp, newImp] = impls;
        if (api.method_getImplementation(methodHandle).equals(newImp))
          api.method_setImplementation(methodHandle, oldImp);
      }
      replacedMethods.clear();
    }
    Script.bindWeak(this, dispose);
    Object.defineProperty(this, "available", {
      enumerable: true,
      get() {
        return tryInitialize();
      }
    });
    Object.defineProperty(this, "api", {
      enumerable: true,
      get() {
        return getApi();
      }
    });
    Object.defineProperty(this, "classes", {
      enumerable: true,
      value: classRegistry
    });
    Object.defineProperty(this, "protocols", {
      enumerable: true,
      value: protocolRegistry
    });
    Object.defineProperty(this, "Object", {
      enumerable: true,
      value: ObjCObject
    });
    Object.defineProperty(this, "Protocol", {
      enumerable: true,
      value: ObjCProtocol
    });
    Object.defineProperty(this, "Block", {
      enumerable: true,
      value: Block
    });
    Object.defineProperty(this, "mainQueue", {
      enumerable: true,
      get() {
        return api?._dispatch_main_q ?? null;
      }
    });
    Object.defineProperty(this, "registerProxy", {
      enumerable: true,
      value: registerProxy
    });
    Object.defineProperty(this, "registerClass", {
      enumerable: true,
      value: registerClass
    });
    Object.defineProperty(this, "registerProtocol", {
      enumerable: true,
      value: registerProtocol
    });
    Object.defineProperty(this, "bind", {
      enumerable: true,
      value: bind
    });
    Object.defineProperty(this, "unbind", {
      enumerable: true,
      value: unbind
    });
    Object.defineProperty(this, "getBoundData", {
      enumerable: true,
      value: getBoundData
    });
    Object.defineProperty(this, "enumerateLoadedClasses", {
      enumerable: true,
      value: enumerateLoadedClasses
    });
    Object.defineProperty(this, "enumerateLoadedClassesSync", {
      enumerable: true,
      value: enumerateLoadedClassesSync
    });
    Object.defineProperty(this, "choose", {
      enumerable: true,
      value: choose
    });
    Object.defineProperty(this, "chooseSync", {
      enumerable: true,
      value(specifier) {
        const instances = [];
        choose(specifier, {
          onMatch(i) {
            instances.push(i);
          },
          onComplete() {
          }
        });
        return instances;
      }
    });
    this.schedule = function(queue, work) {
      const id = ptr(nextId++);
      scheduledWork.set(id.toString(), work);
      if (workCallback === null) {
        workCallback = new NativeCallback(performScheduledWorkItem, "void", ["pointer"]);
      }
      Script.pin();
      api.dispatch_async_f(queue, id, workCallback);
    };
    function performScheduledWorkItem(rawId) {
      const id = rawId.toString();
      const work = scheduledWork.get(id);
      scheduledWork.delete(id);
      if (NSAutoreleasePool === null)
        NSAutoreleasePool = classRegistry.NSAutoreleasePool;
      const pool = NSAutoreleasePool.alloc().init();
      let pendingException = null;
      try {
        work();
      } catch (e) {
        pendingException = e;
      }
      pool.release();
      setImmediate(performScheduledWorkCleanup, pendingException);
    }
    function performScheduledWorkCleanup(pendingException) {
      Script.unpin();
      if (pendingException !== null) {
        throw pendingException;
      }
    }
    this.implement = function(method2, fn) {
      return new NativeCallback(fn, method2.returnType, method2.argumentTypes);
    };
    this.selector = selector;
    this.selectorAsString = selectorAsString;
    function selector(name) {
      return api.sel_registerName(Memory.allocUtf8String(name));
    }
    function selectorAsString(sel2) {
      return api.sel_getName(sel2).readCString();
    }
    const registryBuiltins = /* @__PURE__ */ new Set([
      "prototype",
      "constructor",
      "hasOwnProperty",
      "toJSON",
      "toString",
      "valueOf"
    ]);
    function ClassRegistry() {
      const cachedClasses = /* @__PURE__ */ new Map();
      let numCachedClasses = 0;
      const registry = new Proxy(this, {
        has(target, property) {
          return hasProperty(property);
        },
        get(target, property, receiver) {
          switch (property) {
            case "prototype":
              return target.prototype;
            case "constructor":
              return target.constructor;
            case "hasOwnProperty":
              return hasProperty;
            case "toJSON":
              return toJSON;
            case "toString":
              return toString;
            case "valueOf":
              return valueOf;
            default:
              const klass = findClass(property);
              return klass !== null ? klass : void 0;
          }
        },
        set(target, property, value, receiver) {
          return false;
        },
        ownKeys(target) {
          if (api === null)
            return [];
          let numClasses = api.objc_getClassList(NULL, 0);
          if (numClasses !== numCachedClasses) {
            const bufferSize = numClasses;
            const classHandles = Memory.alloc(bufferSize * pointerSize);
            numClasses = api.objc_getClassList(classHandles, bufferSize);
            if (numClasses > bufferSize)
              numClasses = bufferSize;
            for (let i = 0; i !== numClasses; i++) {
              const handle2 = classHandles.add(i * pointerSize).readPointer();
              const name = api.class_getName(handle2).readCString();
              cachedClasses.set(name, handle2);
            }
            numCachedClasses = numClasses;
          }
          return Array.from(cachedClasses.keys());
        },
        getOwnPropertyDescriptor(target, property) {
          return {
            writable: false,
            configurable: true,
            enumerable: true
          };
        }
      });
      function hasProperty(name) {
        if (registryBuiltins.has(name))
          return true;
        return findClass(name) !== null;
      }
      function getClass(name) {
        const cls = findClass(name);
        if (cls === null)
          throw new Error("Unable to find class '" + name + "'");
        return cls;
      }
      function findClass(name) {
        let handle2 = cachedClasses.get(name);
        if (handle2 === void 0) {
          handle2 = api.objc_lookUpClass(Memory.allocUtf8String(name));
          if (handle2.isNull())
            return null;
          cachedClasses.set(name, handle2);
          numCachedClasses++;
        }
        return new ObjCObject(handle2, void 0, true);
      }
      function toJSON() {
        return Object.keys(registry).reduce(function(r, name) {
          r[name] = getClass(name).toJSON();
          return r;
        }, {});
      }
      function toString() {
        return "ClassRegistry";
      }
      function valueOf() {
        return "ClassRegistry";
      }
      return registry;
    }
    function ProtocolRegistry() {
      const cachedProtocols = /* @__PURE__ */ new Map();
      let numCachedProtocols = 0;
      const registry = new Proxy(this, {
        has(target, property) {
          return hasProperty(property);
        },
        get(target, property, receiver) {
          switch (property) {
            case "prototype":
              return target.prototype;
            case "constructor":
              return target.constructor;
            case "hasOwnProperty":
              return hasProperty;
            case "toJSON":
              return toJSON;
            case "toString":
              return toString;
            case "valueOf":
              return valueOf;
            default:
              const proto = findProtocol(property);
              return proto !== null ? proto : void 0;
          }
        },
        set(target, property, value, receiver) {
          return false;
        },
        ownKeys(target) {
          if (api === null)
            return [];
          const numProtocolsBuf = Memory.alloc(pointerSize);
          const protocolHandles = api.objc_copyProtocolList(numProtocolsBuf);
          try {
            const numProtocols = numProtocolsBuf.readUInt();
            if (numProtocols !== numCachedProtocols) {
              cachedProtocols.clear();
              for (let i = 0; i !== numProtocols; i++) {
                const handle2 = protocolHandles.add(i * pointerSize).readPointer();
                const name = api.protocol_getName(handle2).readCString();
                cachedProtocols.set(name, handle2);
              }
              numCachedProtocols = numProtocols;
            }
          } finally {
            api.free(protocolHandles);
          }
          return Array.from(cachedProtocols.keys());
        },
        getOwnPropertyDescriptor(target, property) {
          return {
            writable: false,
            configurable: true,
            enumerable: true
          };
        }
      });
      function hasProperty(name) {
        if (registryBuiltins.has(name))
          return true;
        return findProtocol(name) !== null;
      }
      function findProtocol(name) {
        let handle2 = cachedProtocols.get(name);
        if (handle2 === void 0) {
          handle2 = api.objc_getProtocol(Memory.allocUtf8String(name));
          if (handle2.isNull())
            return null;
          cachedProtocols.set(name, handle2);
          numCachedProtocols++;
        }
        return new ObjCProtocol(handle2);
      }
      function toJSON() {
        return Object.keys(registry).reduce(function(r, name) {
          r[name] = { handle: cachedProtocols.get(name) };
          return r;
        }, {});
      }
      function toString() {
        return "ProtocolRegistry";
      }
      function valueOf() {
        return "ProtocolRegistry";
      }
      return registry;
    }
    const objCObjectBuiltins = /* @__PURE__ */ new Set([
      "prototype",
      "constructor",
      "handle",
      "hasOwnProperty",
      "toJSON",
      "toString",
      "valueOf",
      "equals",
      "$kind",
      "$super",
      "$superClass",
      "$class",
      "$className",
      "$moduleName",
      "$protocols",
      "$methods",
      "$ownMethods",
      "$ivars"
    ]);
    function ObjCObject(handle2, protocol, cachedIsClass, superSpecifier2) {
      let cachedClassHandle = null;
      let cachedKind = null;
      let cachedSuper = null;
      let cachedSuperClass = null;
      let cachedClass = null;
      let cachedClassName = null;
      let cachedModuleName = null;
      let cachedProtocols = null;
      let cachedMethodNames = null;
      let cachedProtocolMethods = null;
      let respondsToSelector = null;
      const cachedMethods = /* @__PURE__ */ new Map();
      let cachedNativeMethodNames = null;
      let cachedOwnMethodNames = null;
      let cachedIvars = null;
      handle2 = getHandle(handle2);
      if (cachedIsClass === void 0) {
        const klass = api.object_getClass(handle2);
        const key = klass.toString();
        if (!realizedClasses.has(key)) {
          api.objc_lookUpClass(api.class_getName(klass));
          realizedClasses.add(key);
        }
      }
      const self = new Proxy(this, {
        has(target, property) {
          return hasProperty(property);
        },
        get(target, property, receiver) {
          switch (property) {
            case "handle":
              return handle2;
            case "prototype":
              return target.prototype;
            case "constructor":
              return target.constructor;
            case "hasOwnProperty":
              return hasProperty;
            case "toJSON":
              return toJSON;
            case "toString":
            case "valueOf":
              const descriptionImpl = receiver.description;
              if (descriptionImpl !== void 0) {
                const description = descriptionImpl.call(receiver);
                if (description !== null)
                  return description.UTF8String.bind(description);
              }
              return function() {
                return receiver.$className;
              };
            case "equals":
              return equals;
            case "$kind":
              if (cachedKind === null) {
                if (isClass())
                  cachedKind = api.class_isMetaClass(handle2) ? "meta-class" : "class";
                else
                  cachedKind = "instance";
              }
              return cachedKind;
            case "$super":
              if (cachedSuper === null) {
                const superHandle = api.class_getSuperclass(classHandle());
                if (!superHandle.isNull()) {
                  const specifier = Memory.alloc(2 * pointerSize);
                  specifier.writePointer(handle2);
                  specifier.add(pointerSize).writePointer(superHandle);
                  cachedSuper = [new ObjCObject(handle2, void 0, cachedIsClass, specifier)];
                } else {
                  cachedSuper = [null];
                }
              }
              return cachedSuper[0];
            case "$superClass":
              if (cachedSuperClass === null) {
                const superClassHandle = api.class_getSuperclass(classHandle());
                if (!superClassHandle.isNull()) {
                  cachedSuperClass = [new ObjCObject(superClassHandle)];
                } else {
                  cachedSuperClass = [null];
                }
              }
              return cachedSuperClass[0];
            case "$class":
              if (cachedClass === null)
                cachedClass = new ObjCObject(api.object_getClass(handle2), void 0, true);
              return cachedClass;
            case "$className":
              if (cachedClassName === null) {
                if (superSpecifier2)
                  cachedClassName = api.class_getName(superSpecifier2.add(pointerSize).readPointer()).readCString();
                else if (isClass())
                  cachedClassName = api.class_getName(handle2).readCString();
                else
                  cachedClassName = api.object_getClassName(handle2).readCString();
              }
              return cachedClassName;
            case "$moduleName":
              if (cachedModuleName === null) {
                cachedModuleName = api.class_getImageName(classHandle()).readCString();
              }
              return cachedModuleName;
            case "$protocols":
              if (cachedProtocols === null) {
                cachedProtocols = {};
                const numProtocolsBuf = Memory.alloc(pointerSize);
                const protocolHandles = api.class_copyProtocolList(classHandle(), numProtocolsBuf);
                if (!protocolHandles.isNull()) {
                  try {
                    const numProtocols = numProtocolsBuf.readUInt();
                    for (let i = 0; i !== numProtocols; i++) {
                      const protocolHandle = protocolHandles.add(i * pointerSize).readPointer();
                      const p = new ObjCProtocol(protocolHandle);
                      cachedProtocols[p.name] = p;
                    }
                  } finally {
                    api.free(protocolHandles);
                  }
                }
              }
              return cachedProtocols;
            case "$methods":
              if (cachedNativeMethodNames === null) {
                const klass = superSpecifier2 ? superSpecifier2.add(pointerSize).readPointer() : classHandle();
                const meta = api.object_getClass(klass);
                const names = /* @__PURE__ */ new Set();
                let cur = meta;
                do {
                  for (let methodName of collectMethodNames(cur, "+ "))
                    names.add(methodName);
                  cur = api.class_getSuperclass(cur);
                } while (!cur.isNull());
                cur = klass;
                do {
                  for (let methodName of collectMethodNames(cur, "- "))
                    names.add(methodName);
                  cur = api.class_getSuperclass(cur);
                } while (!cur.isNull());
                cachedNativeMethodNames = Array.from(names);
              }
              return cachedNativeMethodNames;
            case "$ownMethods":
              if (cachedOwnMethodNames === null) {
                const klass = superSpecifier2 ? superSpecifier2.add(pointerSize).readPointer() : classHandle();
                const meta = api.object_getClass(klass);
                const classMethods = collectMethodNames(meta, "+ ");
                const instanceMethods = collectMethodNames(klass, "- ");
                cachedOwnMethodNames = classMethods.concat(instanceMethods);
              }
              return cachedOwnMethodNames;
            case "$ivars":
              if (cachedIvars === null) {
                if (isClass())
                  cachedIvars = {};
                else
                  cachedIvars = new ObjCIvars(self, classHandle());
              }
              return cachedIvars;
            default:
              if (typeof property === "symbol") {
                return target[property];
              }
              if (protocol) {
                const details = findProtocolMethod(property);
                if (details === null || !details.implemented)
                  return void 0;
              }
              const wrapper = findMethodWrapper(property);
              if (wrapper === null)
                return void 0;
              return wrapper;
          }
        },
        set(target, property, value, receiver) {
          return false;
        },
        ownKeys(target) {
          if (cachedMethodNames === null) {
            if (!protocol) {
              const jsNames = {};
              const nativeNames = {};
              let cur = api.object_getClass(handle2);
              do {
                const numMethodsBuf = Memory.alloc(pointerSize);
                const methodHandles = api.class_copyMethodList(cur, numMethodsBuf);
                const fullNamePrefix = isClass() ? "+ " : "- ";
                try {
                  const numMethods = numMethodsBuf.readUInt();
                  for (let i = 0; i !== numMethods; i++) {
                    const methodHandle = methodHandles.add(i * pointerSize).readPointer();
                    const sel2 = api.method_getName(methodHandle);
                    const nativeName = api.sel_getName(sel2).readCString();
                    if (nativeNames[nativeName] !== void 0)
                      continue;
                    nativeNames[nativeName] = nativeName;
                    const jsName = jsMethodName(nativeName);
                    let serial = 2;
                    let name = jsName;
                    while (jsNames[name] !== void 0) {
                      serial++;
                      name = jsName + serial;
                    }
                    jsNames[name] = true;
                    const fullName = fullNamePrefix + nativeName;
                    if (!cachedMethods.has(fullName)) {
                      const details = {
                        sel: sel2,
                        handle: methodHandle,
                        wrapper: null
                      };
                      cachedMethods.set(fullName, details);
                      cachedMethods.set(name, details);
                    }
                  }
                } finally {
                  api.free(methodHandles);
                }
                cur = api.class_getSuperclass(cur);
              } while (!cur.isNull());
              cachedMethodNames = Object.keys(jsNames);
            } else {
              const methodNames = [];
              const protocolMethods = allProtocolMethods();
              Object.keys(protocolMethods).forEach(function(methodName) {
                if (methodName[0] !== "+" && methodName[0] !== "-") {
                  const details = protocolMethods[methodName];
                  if (details.implemented) {
                    methodNames.push(methodName);
                  }
                }
              });
              cachedMethodNames = methodNames;
            }
          }
          return ["handle"].concat(cachedMethodNames);
        },
        getOwnPropertyDescriptor(target, property) {
          return {
            writable: false,
            configurable: true,
            enumerable: true
          };
        }
      });
      if (protocol) {
        respondsToSelector = !isClass() ? findMethodWrapper("- respondsToSelector:") : null;
      }
      return self;
      function hasProperty(name) {
        if (objCObjectBuiltins.has(name))
          return true;
        if (protocol) {
          const details = findProtocolMethod(name);
          return !!(details !== null && details.implemented);
        }
        return findMethod(name) !== null;
      }
      function classHandle() {
        if (cachedClassHandle === null)
          cachedClassHandle = isClass() ? handle2 : api.object_getClass(handle2);
        return cachedClassHandle;
      }
      function isClass() {
        if (cachedIsClass === void 0) {
          if (api.object_isClass)
            cachedIsClass = !!api.object_isClass(handle2);
          else
            cachedIsClass = !!api.class_isMetaClass(api.object_getClass(handle2));
        }
        return cachedIsClass;
      }
      function findMethod(rawName) {
        let method2 = cachedMethods.get(rawName);
        if (method2 !== void 0)
          return method2;
        const tokens = parseMethodName(rawName);
        const fullName = tokens[2];
        method2 = cachedMethods.get(fullName);
        if (method2 !== void 0) {
          cachedMethods.set(rawName, method2);
          return method2;
        }
        const kind = tokens[0];
        const name = tokens[1];
        const sel2 = selector(name);
        const defaultKind = isClass() ? "+" : "-";
        if (protocol) {
          const details = findProtocolMethod(fullName);
          if (details !== null) {
            method2 = {
              sel: sel2,
              types: details.types,
              wrapper: null,
              kind
            };
          }
        }
        if (method2 === void 0) {
          const methodHandle = kind === "+" ? api.class_getClassMethod(classHandle(), sel2) : api.class_getInstanceMethod(classHandle(), sel2);
          if (!methodHandle.isNull()) {
            method2 = {
              sel: sel2,
              handle: methodHandle,
              wrapper: null,
              kind
            };
          } else {
            if (isClass() || kind !== "-" || name === "forwardingTargetForSelector:" || name === "methodSignatureForSelector:") {
              return null;
            }
            let target = self;
            if ("- forwardingTargetForSelector:" in self) {
              const forwardingTarget = self.forwardingTargetForSelector_(sel2);
              if (forwardingTarget !== null && forwardingTarget.$kind === "instance") {
                target = forwardingTarget;
              } else {
                return null;
              }
            } else {
              return null;
            }
            const methodHandle2 = api.class_getInstanceMethod(api.object_getClass(target.handle), sel2);
            if (methodHandle2.isNull()) {
              return null;
            }
            let types2 = api.method_getTypeEncoding(methodHandle2).readCString();
            if (types2 === null || types2 === "") {
              types2 = stealTypesFromProtocols(target, fullName);
              if (types2 === null)
                types2 = stealTypesFromProtocols(self, fullName);
              if (types2 === null)
                return null;
            }
            method2 = {
              sel: sel2,
              types: types2,
              wrapper: null,
              kind
            };
          }
        }
        cachedMethods.set(fullName, method2);
        cachedMethods.set(rawName, method2);
        if (kind === defaultKind)
          cachedMethods.set(jsMethodName(name), method2);
        return method2;
      }
      function stealTypesFromProtocols(klass, fullName) {
        const candidates = Object.keys(klass.$protocols).map((protocolName) => flatProtocolMethods({}, klass.$protocols[protocolName])).reduce((allMethods, methods) => {
          Object.assign(allMethods, methods);
          return allMethods;
        }, {});
        const method2 = candidates[fullName];
        if (method2 === void 0) {
          return null;
        }
        return method2.types;
      }
      function flatProtocolMethods(result, protocol2) {
        if (protocol2.methods !== void 0) {
          Object.assign(result, protocol2.methods);
        }
        if (protocol2.protocol !== void 0) {
          flatProtocolMethods(result, protocol2.protocol);
        }
        return result;
      }
      function findProtocolMethod(rawName) {
        const protocolMethods = allProtocolMethods();
        const details = protocolMethods[rawName];
        return details !== void 0 ? details : null;
      }
      function allProtocolMethods() {
        if (cachedProtocolMethods === null) {
          const methods = {};
          const protocols = collectProtocols(protocol);
          const defaultKind = isClass() ? "+" : "-";
          Object.keys(protocols).forEach(function(name) {
            const p = protocols[name];
            const m2 = p.methods;
            Object.keys(m2).forEach(function(fullMethodName) {
              const method2 = m2[fullMethodName];
              const methodName = fullMethodName.substr(2);
              const kind = fullMethodName[0];
              let didCheckImplemented = false;
              let implemented = false;
              const details = {
                types: method2.types
              };
              Object.defineProperty(details, "implemented", {
                get() {
                  if (!didCheckImplemented) {
                    if (method2.required) {
                      implemented = true;
                    } else {
                      implemented = respondsToSelector !== null && respondsToSelector.call(self, selector(methodName));
                    }
                    didCheckImplemented = true;
                  }
                  return implemented;
                }
              });
              methods[fullMethodName] = details;
              if (kind === defaultKind)
                methods[jsMethodName(methodName)] = details;
            });
          });
          cachedProtocolMethods = methods;
        }
        return cachedProtocolMethods;
      }
      function findMethodWrapper(name) {
        const method2 = findMethod(name);
        if (method2 === null)
          return null;
        let wrapper = method2.wrapper;
        if (wrapper === null) {
          wrapper = makeMethodInvocationWrapper(method2, self, superSpecifier2, defaultInvocationOptions);
          method2.wrapper = wrapper;
        }
        return wrapper;
      }
      function parseMethodName(rawName) {
        const match = /([+\-])\s(\S+)/.exec(rawName);
        let name, kind;
        if (match === null) {
          kind = isClass() ? "+" : "-";
          name = objcMethodName(rawName);
        } else {
          kind = match[1];
          name = match[2];
        }
        const fullName = [kind, name].join(" ");
        return [kind, name, fullName];
      }
      function toJSON() {
        return {
          handle: handle2.toString()
        };
      }
      function equals(ptr2) {
        return handle2.equals(getHandle(ptr2));
      }
    }
    function getReplacementMethodImplementation(methodHandle) {
      const existingEntry = replacedMethods.get(methodHandle.toString());
      if (existingEntry === void 0)
        return null;
      const [, newImp] = existingEntry;
      return newImp;
    }
    function replaceMethodImplementation(methodHandle, imp) {
      const key = methodHandle.toString();
      let oldImp;
      const existingEntry = replacedMethods.get(key);
      if (existingEntry !== void 0)
        [oldImp] = existingEntry;
      else
        oldImp = api.method_getImplementation(methodHandle);
      if (!imp.equals(oldImp))
        replacedMethods.set(key, [oldImp, imp]);
      else
        replacedMethods.delete(key);
      api.method_setImplementation(methodHandle, imp);
    }
    function collectMethodNames(klass, prefix) {
      const names = [];
      const numMethodsBuf = Memory.alloc(pointerSize);
      const methodHandles = api.class_copyMethodList(klass, numMethodsBuf);
      try {
        const numMethods = numMethodsBuf.readUInt();
        for (let i = 0; i !== numMethods; i++) {
          const methodHandle = methodHandles.add(i * pointerSize).readPointer();
          const sel2 = api.method_getName(methodHandle);
          const nativeName = api.sel_getName(sel2).readCString();
          names.push(prefix + nativeName);
        }
      } finally {
        api.free(methodHandles);
      }
      return names;
    }
    function ObjCProtocol(handle2) {
      let cachedName = null;
      let cachedProtocols = null;
      let cachedProperties = null;
      let cachedMethods = null;
      Object.defineProperty(this, "handle", {
        value: handle2,
        enumerable: true
      });
      Object.defineProperty(this, "name", {
        get() {
          if (cachedName === null)
            cachedName = api.protocol_getName(handle2).readCString();
          return cachedName;
        },
        enumerable: true
      });
      Object.defineProperty(this, "protocols", {
        get() {
          if (cachedProtocols === null) {
            cachedProtocols = {};
            const numProtocolsBuf = Memory.alloc(pointerSize);
            const protocolHandles = api.protocol_copyProtocolList(handle2, numProtocolsBuf);
            if (!protocolHandles.isNull()) {
              try {
                const numProtocols = numProtocolsBuf.readUInt();
                for (let i = 0; i !== numProtocols; i++) {
                  const protocolHandle = protocolHandles.add(i * pointerSize).readPointer();
                  const protocol = new ObjCProtocol(protocolHandle);
                  cachedProtocols[protocol.name] = protocol;
                }
              } finally {
                api.free(protocolHandles);
              }
            }
          }
          return cachedProtocols;
        },
        enumerable: true
      });
      Object.defineProperty(this, "properties", {
        get() {
          if (cachedProperties === null) {
            cachedProperties = {};
            const numBuf = Memory.alloc(pointerSize);
            const propertyHandles = api.protocol_copyPropertyList(handle2, numBuf);
            if (!propertyHandles.isNull()) {
              try {
                const numProperties = numBuf.readUInt();
                for (let i = 0; i !== numProperties; i++) {
                  const propertyHandle = propertyHandles.add(i * pointerSize).readPointer();
                  const propName = api.property_getName(propertyHandle).readCString();
                  const attributes = {};
                  const attributeEntries = api.property_copyAttributeList(propertyHandle, numBuf);
                  if (!attributeEntries.isNull()) {
                    try {
                      const numAttributeValues = numBuf.readUInt();
                      for (let j = 0; j !== numAttributeValues; j++) {
                        const attributeEntry = attributeEntries.add(j * (2 * pointerSize));
                        const name = attributeEntry.readPointer().readCString();
                        const value = attributeEntry.add(pointerSize).readPointer().readCString();
                        attributes[name] = value;
                      }
                    } finally {
                      api.free(attributeEntries);
                    }
                  }
                  cachedProperties[propName] = attributes;
                }
              } finally {
                api.free(propertyHandles);
              }
            }
          }
          return cachedProperties;
        },
        enumerable: true
      });
      Object.defineProperty(this, "methods", {
        get() {
          if (cachedMethods === null) {
            cachedMethods = {};
            const numBuf = Memory.alloc(pointerSize);
            collectMethods(cachedMethods, numBuf, { required: true, instance: false });
            collectMethods(cachedMethods, numBuf, { required: false, instance: false });
            collectMethods(cachedMethods, numBuf, { required: true, instance: true });
            collectMethods(cachedMethods, numBuf, { required: false, instance: true });
          }
          return cachedMethods;
        },
        enumerable: true
      });
      function collectMethods(methods, numBuf, spec) {
        const methodDescValues = api.protocol_copyMethodDescriptionList(handle2, spec.required ? 1 : 0, spec.instance ? 1 : 0, numBuf);
        if (methodDescValues.isNull())
          return;
        try {
          const numMethodDescValues = numBuf.readUInt();
          for (let i = 0; i !== numMethodDescValues; i++) {
            const methodDesc = methodDescValues.add(i * (2 * pointerSize));
            const name = (spec.instance ? "- " : "+ ") + selectorAsString(methodDesc.readPointer());
            const types2 = methodDesc.add(pointerSize).readPointer().readCString();
            methods[name] = {
              required: spec.required,
              types: types2
            };
          }
        } finally {
          api.free(methodDescValues);
        }
      }
    }
    const objCIvarsBuiltins = /* @__PURE__ */ new Set([
      "prototype",
      "constructor",
      "hasOwnProperty",
      "toJSON",
      "toString",
      "valueOf"
    ]);
    function ObjCIvars(instance, classHandle) {
      const ivars = {};
      let cachedIvarNames = null;
      let classHandles = [];
      let currentClassHandle = classHandle;
      do {
        classHandles.unshift(currentClassHandle);
        currentClassHandle = api.class_getSuperclass(currentClassHandle);
      } while (!currentClassHandle.isNull());
      const numIvarsBuf = Memory.alloc(pointerSize);
      classHandles.forEach((c) => {
        const ivarHandles = api.class_copyIvarList(c, numIvarsBuf);
        try {
          const numIvars = numIvarsBuf.readUInt();
          for (let i = 0; i !== numIvars; i++) {
            const handle2 = ivarHandles.add(i * pointerSize).readPointer();
            const name = api.ivar_getName(handle2).readCString();
            ivars[name] = [handle2, null];
          }
        } finally {
          api.free(ivarHandles);
        }
      });
      const self = new Proxy(this, {
        has(target, property) {
          return hasProperty(property);
        },
        get(target, property, receiver) {
          switch (property) {
            case "prototype":
              return target.prototype;
            case "constructor":
              return target.constructor;
            case "hasOwnProperty":
              return hasProperty;
            case "toJSON":
              return toJSON;
            case "toString":
              return toString;
            case "valueOf":
              return valueOf;
            default:
              const ivar = findIvar(property);
              if (ivar === null)
                return void 0;
              return ivar.get();
          }
        },
        set(target, property, value, receiver) {
          const ivar = findIvar(property);
          if (ivar === null)
            throw new Error("Unknown ivar");
          ivar.set(value);
          return true;
        },
        ownKeys(target) {
          if (cachedIvarNames === null)
            cachedIvarNames = Object.keys(ivars);
          return cachedIvarNames;
        },
        getOwnPropertyDescriptor(target, property) {
          return {
            writable: true,
            configurable: true,
            enumerable: true
          };
        }
      });
      return self;
      function findIvar(name) {
        const entry = ivars[name];
        if (entry === void 0)
          return null;
        let impl = entry[1];
        if (impl === null) {
          const ivar = entry[0];
          const offset = api.ivar_getOffset(ivar).toInt32();
          const address = instance.handle.add(offset);
          const type = parseType(api.ivar_getTypeEncoding(ivar).readCString());
          const fromNative = type.fromNative || identityTransform;
          const toNative = type.toNative || identityTransform;
          let read, write;
          if (name === "isa") {
            read = readObjectIsa;
            write = function() {
              throw new Error("Unable to set the isa instance variable");
            };
          } else {
            read = type.read;
            write = type.write;
          }
          impl = {
            get() {
              return fromNative.call(instance, read(address));
            },
            set(value) {
              write(address, toNative.call(instance, value));
            }
          };
          entry[1] = impl;
        }
        return impl;
      }
      function hasProperty(name) {
        if (objCIvarsBuiltins.has(name))
          return true;
        return ivars.hasOwnProperty(name);
      }
      function toJSON() {
        return Object.keys(self).reduce(function(result, name) {
          result[name] = self[name];
          return result;
        }, {});
      }
      function toString() {
        return "ObjCIvars";
      }
      function valueOf() {
        return "ObjCIvars";
      }
    }
    let blockDescriptorAllocSize, blockDescriptorDeclaredSize, blockDescriptorOffsets;
    let blockSize, blockOffsets;
    if (pointerSize === 4) {
      blockDescriptorAllocSize = 16;
      blockDescriptorDeclaredSize = 20;
      blockDescriptorOffsets = {
        reserved: 0,
        size: 4,
        rest: 8
      };
      blockSize = 20;
      blockOffsets = {
        isa: 0,
        flags: 4,
        reserved: 8,
        invoke: 12,
        descriptor: 16
      };
    } else {
      blockDescriptorAllocSize = 32;
      blockDescriptorDeclaredSize = 32;
      blockDescriptorOffsets = {
        reserved: 0,
        size: 8,
        rest: 16
      };
      blockSize = 32;
      blockOffsets = {
        isa: 0,
        flags: 8,
        reserved: 12,
        invoke: 16,
        descriptor: 24
      };
    }
    const BLOCK_HAS_COPY_DISPOSE = 1 << 25;
    const BLOCK_HAS_CTOR = 1 << 26;
    const BLOCK_IS_GLOBAL = 1 << 28;
    const BLOCK_HAS_STRET = 1 << 29;
    const BLOCK_HAS_SIGNATURE = 1 << 30;
    function Block(target, options = defaultInvocationOptions) {
      this._options = options;
      if (target instanceof NativePointer) {
        const descriptor = target.add(blockOffsets.descriptor).readPointer();
        this.handle = target;
        const flags = target.add(blockOffsets.flags).readU32();
        if ((flags & BLOCK_HAS_SIGNATURE) !== 0) {
          const signatureOffset = (flags & BLOCK_HAS_COPY_DISPOSE) !== 0 ? 2 : 0;
          this.types = descriptor.add(blockDescriptorOffsets.rest + signatureOffset * pointerSize).readPointer().readCString();
          this._signature = parseSignature(this.types);
        } else {
          this._signature = null;
        }
      } else {
        this.declare(target);
        const descriptor = Memory.alloc(blockDescriptorAllocSize + blockSize);
        const block2 = descriptor.add(blockDescriptorAllocSize);
        const typesStr = Memory.allocUtf8String(this.types);
        descriptor.add(blockDescriptorOffsets.reserved).writeULong(0);
        descriptor.add(blockDescriptorOffsets.size).writeULong(blockDescriptorDeclaredSize);
        descriptor.add(blockDescriptorOffsets.rest).writePointer(typesStr);
        block2.add(blockOffsets.isa).writePointer(classRegistry.__NSGlobalBlock__);
        block2.add(blockOffsets.flags).writeU32(BLOCK_HAS_SIGNATURE | BLOCK_IS_GLOBAL);
        block2.add(blockOffsets.reserved).writeU32(0);
        block2.add(blockOffsets.descriptor).writePointer(descriptor);
        this.handle = block2;
        this._storage = [descriptor, typesStr];
        this.implementation = target.implementation;
      }
    }
    Object.defineProperties(Block.prototype, {
      implementation: {
        enumerable: true,
        get() {
          const address = this.handle.add(blockOffsets.invoke).readPointer().strip();
          const signature2 = this._getSignature();
          return makeBlockInvocationWrapper(this, signature2, new NativeFunction(
            address.sign(),
            signature2.retType.type,
            signature2.argTypes.map(function(arg) {
              return arg.type;
            }),
            this._options
          ));
        },
        set(func) {
          const signature2 = this._getSignature();
          const callback = new NativeCallback(
            makeBlockImplementationWrapper(this, signature2, func),
            signature2.retType.type,
            signature2.argTypes.map(function(arg) {
              return arg.type;
            })
          );
          this._callback = callback;
          const location = this.handle.add(blockOffsets.invoke);
          const prot = Memory.queryProtection(location);
          const writable = prot.includes("w");
          if (!writable)
            Memory.protect(location, Process.pointerSize, "rw-");
          location.writePointer(callback.strip().sign("ia", location));
          if (!writable)
            Memory.protect(location, Process.pointerSize, prot);
        }
      },
      declare: {
        value(signature2) {
          let types2 = signature2.types;
          if (types2 === void 0) {
            types2 = unparseSignature(signature2.retType, ["block"].concat(signature2.argTypes));
          }
          this.types = types2;
          this._signature = parseSignature(types2);
        }
      },
      _getSignature: {
        value() {
          const signature2 = this._signature;
          if (signature2 === null)
            throw new Error("block is missing signature; call declare()");
          return signature2;
        }
      }
    });
    function collectProtocols(p, acc) {
      acc = acc || {};
      acc[p.name] = p;
      const parentProtocols = p.protocols;
      Object.keys(parentProtocols).forEach(function(name) {
        collectProtocols(parentProtocols[name], acc);
      });
      return acc;
    }
    function registerProxy(properties) {
      const protocols = properties.protocols || [];
      const methods = properties.methods || {};
      const events = properties.events || {};
      const supportedSelectors = new Set(
        Object.keys(methods).filter((m2) => /([+\-])\s(\S+)/.exec(m2) !== null).map((m2) => m2.split(" ")[1])
      );
      const proxyMethods = {
        "- dealloc": function() {
          const target = this.data.target;
          if ("- release" in target)
            target.release();
          unbind(this.self);
          this.super.dealloc();
          const callback = this.data.events.dealloc;
          if (callback !== void 0)
            callback.call(this);
        },
        "- respondsToSelector:": function(sel2) {
          const selector2 = selectorAsString(sel2);
          if (supportedSelectors.has(selector2))
            return true;
          return this.data.target.respondsToSelector_(sel2);
        },
        "- forwardingTargetForSelector:": function(sel2) {
          const callback = this.data.events.forward;
          if (callback !== void 0)
            callback.call(this, selectorAsString(sel2));
          return this.data.target;
        },
        "- methodSignatureForSelector:": function(sel2) {
          return this.data.target.methodSignatureForSelector_(sel2);
        },
        "- forwardInvocation:": function(invocation) {
          invocation.invokeWithTarget_(this.data.target);
        }
      };
      for (var key in methods) {
        if (methods.hasOwnProperty(key)) {
          if (proxyMethods.hasOwnProperty(key))
            throw new Error("The '" + key + "' method is reserved");
          proxyMethods[key] = methods[key];
        }
      }
      const ProxyClass = registerClass({
        name: properties.name,
        super: classRegistry.NSProxy,
        protocols,
        methods: proxyMethods
      });
      return function(target, data) {
        target = target instanceof NativePointer ? new ObjCObject(target) : target;
        data = data || {};
        const instance = ProxyClass.alloc().autorelease();
        const boundData = getBoundData(instance);
        boundData.target = "- retain" in target ? target.retain() : target;
        boundData.events = events;
        for (var key2 in data) {
          if (data.hasOwnProperty(key2)) {
            if (boundData.hasOwnProperty(key2))
              throw new Error("The '" + key2 + "' property is reserved");
            boundData[key2] = data[key2];
          }
        }
        this.handle = instance.handle;
      };
    }
    function registerClass(properties) {
      let name = properties.name;
      if (name === void 0)
        name = makeClassName();
      const superClass = properties.super !== void 0 ? properties.super : classRegistry.NSObject;
      const protocols = properties.protocols || [];
      const methods = properties.methods || {};
      const methodCallbacks = [];
      const classHandle = api.objc_allocateClassPair(superClass !== null ? superClass.handle : NULL, Memory.allocUtf8String(name), ptr("0"));
      if (classHandle.isNull())
        throw new Error("Unable to register already registered class '" + name + "'");
      const metaClassHandle = api.object_getClass(classHandle);
      try {
        protocols.forEach(function(protocol) {
          api.class_addProtocol(classHandle, protocol.handle);
        });
        Object.keys(methods).forEach(function(rawMethodName) {
          const match = /([+\-])\s(\S+)/.exec(rawMethodName);
          if (match === null)
            throw new Error("Invalid method name");
          const kind = match[1];
          const name2 = match[2];
          let method2;
          const value = methods[rawMethodName];
          if (typeof value === "function") {
            let types3 = null;
            if (rawMethodName in superClass) {
              types3 = superClass[rawMethodName].types;
            } else {
              for (let protocol of protocols) {
                const method3 = protocol.methods[rawMethodName];
                if (method3 !== void 0) {
                  types3 = method3.types;
                  break;
                }
              }
            }
            if (types3 === null)
              throw new Error("Unable to find '" + rawMethodName + "' in super-class or any of its protocols");
            method2 = {
              types: types3,
              implementation: value
            };
          } else {
            method2 = value;
          }
          const target = kind === "+" ? metaClassHandle : classHandle;
          let types2 = method2.types;
          if (types2 === void 0) {
            types2 = unparseSignature(method2.retType, [kind === "+" ? "class" : "object", "selector"].concat(method2.argTypes));
          }
          const signature2 = parseSignature(types2);
          const implementation2 = new NativeCallback(
            makeMethodImplementationWrapper(signature2, method2.implementation),
            signature2.retType.type,
            signature2.argTypes.map(function(arg) {
              return arg.type;
            })
          );
          methodCallbacks.push(implementation2);
          api.class_addMethod(target, selector(name2), implementation2, Memory.allocUtf8String(types2));
        });
      } catch (e) {
        api.objc_disposeClassPair(classHandle);
        throw e;
      }
      api.objc_registerClassPair(classHandle);
      classHandle._methodCallbacks = methodCallbacks;
      Script.bindWeak(classHandle, makeClassDestructor(ptr(classHandle)));
      return new ObjCObject(classHandle);
    }
    function makeClassDestructor(classHandle) {
      return function() {
        api.objc_disposeClassPair(classHandle);
      };
    }
    function registerProtocol(properties) {
      let name = properties.name;
      if (name === void 0)
        name = makeProtocolName();
      const protocols = properties.protocols || [];
      const methods = properties.methods || {};
      protocols.forEach(function(protocol) {
        if (!(protocol instanceof ObjCProtocol))
          throw new Error("Expected protocol");
      });
      const methodSpecs = Object.keys(methods).map(function(rawMethodName) {
        const method2 = methods[rawMethodName];
        const match = /([+\-])\s(\S+)/.exec(rawMethodName);
        if (match === null)
          throw new Error("Invalid method name");
        const kind = match[1];
        const name2 = match[2];
        let types2 = method2.types;
        if (types2 === void 0) {
          types2 = unparseSignature(method2.retType, [kind === "+" ? "class" : "object", "selector"].concat(method2.argTypes));
        }
        return {
          kind,
          name: name2,
          types: types2,
          optional: method2.optional
        };
      });
      const handle2 = api.objc_allocateProtocol(Memory.allocUtf8String(name));
      if (handle2.isNull())
        throw new Error("Unable to register already registered protocol '" + name + "'");
      protocols.forEach(function(protocol) {
        api.protocol_addProtocol(handle2, protocol.handle);
      });
      methodSpecs.forEach(function(spec) {
        const isRequiredMethod = spec.optional ? 0 : 1;
        const isInstanceMethod = spec.kind === "-" ? 1 : 0;
        api.protocol_addMethodDescription(handle2, selector(spec.name), Memory.allocUtf8String(spec.types), isRequiredMethod, isInstanceMethod);
      });
      api.objc_registerProtocol(handle2);
      return new ObjCProtocol(handle2);
    }
    function getHandle(obj) {
      if (obj instanceof NativePointer)
        return obj;
      else if (typeof obj === "object" && obj.hasOwnProperty("handle"))
        return obj.handle;
      else
        throw new Error("Expected NativePointer or ObjC.Object instance");
    }
    function bind(obj, data) {
      const handle2 = getHandle(obj);
      const self = obj instanceof ObjCObject ? obj : new ObjCObject(handle2);
      bindings.set(handle2.toString(), {
        self,
        super: self.$super,
        data
      });
    }
    function unbind(obj) {
      const handle2 = getHandle(obj);
      bindings.delete(handle2.toString());
    }
    function getBoundData(obj) {
      return getBinding(obj).data;
    }
    function getBinding(obj) {
      const handle2 = getHandle(obj);
      const key = handle2.toString();
      let binding = bindings.get(key);
      if (binding === void 0) {
        const self = obj instanceof ObjCObject ? obj : new ObjCObject(handle2);
        binding = {
          self,
          super: self.$super,
          data: {}
        };
        bindings.set(key, binding);
      }
      return binding;
    }
    function enumerateLoadedClasses(...args) {
      const allModules = new ModuleMap();
      let unfiltered = false;
      let callbacks;
      let modules;
      if (args.length === 1) {
        callbacks = args[0];
      } else {
        callbacks = args[1];
        const options = args[0];
        modules = options.ownedBy;
      }
      if (modules === void 0) {
        modules = allModules;
        unfiltered = true;
      }
      const classGetName = api.class_getName;
      const onMatch = callbacks.onMatch.bind(callbacks);
      const swiftNominalTypeDescriptorOffset = (pointerSize === 8 ? 8 : 11) * pointerSize;
      const numClasses = api.objc_getClassList(NULL, 0);
      const classHandles = Memory.alloc(numClasses * pointerSize);
      api.objc_getClassList(classHandles, numClasses);
      for (let i = 0; i !== numClasses; i++) {
        const classHandle = classHandles.add(i * pointerSize).readPointer();
        const rawName = classGetName(classHandle);
        let name = null;
        let modulePath = modules.findPath(rawName);
        const possiblySwift = modulePath === null && (unfiltered || allModules.findPath(rawName) === null);
        if (possiblySwift) {
          name = rawName.readCString();
          const probablySwift = name.indexOf(".") !== -1;
          if (probablySwift) {
            const nominalTypeDescriptor = classHandle.add(swiftNominalTypeDescriptorOffset).readPointer();
            modulePath = modules.findPath(nominalTypeDescriptor);
          }
        }
        if (modulePath !== null) {
          if (name === null)
            name = rawName.readCString();
          onMatch(name, modulePath);
        }
      }
      callbacks.onComplete();
    }
    function enumerateLoadedClassesSync(options = {}) {
      const result = {};
      enumerateLoadedClasses(options, {
        onMatch(name, owner2) {
          let group = result[owner2];
          if (group === void 0) {
            group = [];
            result[owner2] = group;
          }
          group.push(name);
        },
        onComplete() {
        }
      });
      return result;
    }
    function choose(specifier, callbacks) {
      let cls = specifier;
      let subclasses = true;
      if (!(specifier instanceof ObjCObject) && typeof specifier === "object") {
        cls = specifier.class;
        if (specifier.hasOwnProperty("subclasses"))
          subclasses = specifier.subclasses;
      }
      if (!(cls instanceof ObjCObject && (cls.$kind === "class" || cls.$kind === "meta-class")))
        throw new Error("Expected an ObjC.Object for a class or meta-class");
      const matches = get().choose(cls, subclasses).map((handle2) => new ObjCObject(handle2));
      for (const match of matches) {
        const result = callbacks.onMatch(match);
        if (result === "stop")
          break;
      }
      callbacks.onComplete();
    }
    function makeMethodInvocationWrapper(method, owner, superSpecifier, invocationOptions) {
      const sel = method.sel;
      let handle = method.handle;
      let types;
      if (handle === void 0) {
        handle = null;
        types = method.types;
      } else {
        types = api.method_getTypeEncoding(handle).readCString();
      }
      const signature = parseSignature(types);
      const retType = signature.retType;
      const argTypes = signature.argTypes.slice(2);
      const objc_msgSend = superSpecifier ? getMsgSendSuperImpl(signature, invocationOptions) : getMsgSendImpl(signature, invocationOptions);
      const argVariableNames = argTypes.map(function(t, i) {
        return "a" + (i + 1);
      });
      const callArgs = [
        superSpecifier ? "superSpecifier" : "this",
        "sel"
      ].concat(argTypes.map(function(t, i) {
        if (t.toNative) {
          return "argTypes[" + i + "].toNative.call(this, " + argVariableNames[i] + ")";
        }
        return argVariableNames[i];
      }));
      let returnCaptureLeft;
      let returnCaptureRight;
      if (retType.type === "void") {
        returnCaptureLeft = "";
        returnCaptureRight = "";
      } else if (retType.fromNative) {
        returnCaptureLeft = "return retType.fromNative.call(this, ";
        returnCaptureRight = ")";
      } else {
        returnCaptureLeft = "return ";
        returnCaptureRight = "";
      }
      const m = eval("var m = function (" + argVariableNames.join(", ") + ") { " + returnCaptureLeft + "objc_msgSend(" + callArgs.join(", ") + ")" + returnCaptureRight + "; }; m;");
      Object.defineProperty(m, "handle", {
        enumerable: true,
        get: getMethodHandle
      });
      m.selector = sel;
      Object.defineProperty(m, "implementation", {
        enumerable: true,
        get() {
          const h = getMethodHandle();
          const impl = new NativeFunction(api.method_getImplementation(h), m.returnType, m.argumentTypes, invocationOptions);
          const newImp = getReplacementMethodImplementation(h);
          if (newImp !== null)
            impl._callback = newImp;
          return impl;
        },
        set(imp) {
          replaceMethodImplementation(getMethodHandle(), imp);
        }
      });
      m.returnType = retType.type;
      m.argumentTypes = signature.argTypes.map((t) => t.type);
      m.types = types;
      Object.defineProperty(m, "symbol", {
        enumerable: true,
        get() {
          return `${method.kind}[${owner.$className} ${selectorAsString(sel)}]`;
        }
      });
      m.clone = function(options) {
        return makeMethodInvocationWrapper(method, owner, superSpecifier, options);
      };
      function getMethodHandle() {
        if (handle === null) {
          if (owner.$kind === "instance") {
            let cur = owner;
            do {
              if ("- forwardingTargetForSelector:" in cur) {
                const target = cur.forwardingTargetForSelector_(sel);
                if (target === null)
                  break;
                if (target.$kind !== "instance")
                  break;
                const h = api.class_getInstanceMethod(target.$class.handle, sel);
                if (!h.isNull())
                  handle = h;
                else
                  cur = target;
              } else {
                break;
              }
            } while (handle === null);
          }
          if (handle === null)
            throw new Error("Unable to find method handle of proxied function");
        }
        return handle;
      }
      return m;
    }
    function makeMethodImplementationWrapper(signature, implementation) {
      const retType = signature.retType;
      const argTypes = signature.argTypes;
      const argVariableNames = argTypes.map(function(t, i) {
        if (i === 0)
          return "handle";
        else if (i === 1)
          return "sel";
        else
          return "a" + (i - 1);
      });
      const callArgs = argTypes.slice(2).map(function(t, i) {
        const argVariableName = argVariableNames[2 + i];
        if (t.fromNative) {
          return "argTypes[" + (2 + i) + "].fromNative.call(self, " + argVariableName + ")";
        }
        return argVariableName;
      });
      let returnCaptureLeft;
      let returnCaptureRight;
      if (retType.type === "void") {
        returnCaptureLeft = "";
        returnCaptureRight = "";
      } else if (retType.toNative) {
        returnCaptureLeft = "return retType.toNative.call(self, ";
        returnCaptureRight = ")";
      } else {
        returnCaptureLeft = "return ";
        returnCaptureRight = "";
      }
      const m = eval("var m = function (" + argVariableNames.join(", ") + ") { var binding = getBinding(handle);var self = binding.self;" + returnCaptureLeft + "implementation.call(binding" + (callArgs.length > 0 ? ", " : "") + callArgs.join(", ") + ")" + returnCaptureRight + "; }; m;");
      return m;
    }
    function makeBlockInvocationWrapper(block, signature, implementation) {
      const retType = signature.retType;
      const argTypes = signature.argTypes.slice(1);
      const argVariableNames = argTypes.map(function(t, i) {
        return "a" + (i + 1);
      });
      const callArgs = argTypes.map(function(t, i) {
        if (t.toNative) {
          return "argTypes[" + i + "].toNative.call(this, " + argVariableNames[i] + ")";
        }
        return argVariableNames[i];
      });
      let returnCaptureLeft;
      let returnCaptureRight;
      if (retType.type === "void") {
        returnCaptureLeft = "";
        returnCaptureRight = "";
      } else if (retType.fromNative) {
        returnCaptureLeft = "return retType.fromNative.call(this, ";
        returnCaptureRight = ")";
      } else {
        returnCaptureLeft = "return ";
        returnCaptureRight = "";
      }
      const f = eval("var f = function (" + argVariableNames.join(", ") + ") { " + returnCaptureLeft + "implementation(this" + (callArgs.length > 0 ? ", " : "") + callArgs.join(", ") + ")" + returnCaptureRight + "; }; f;");
      return f.bind(block);
    }
    function makeBlockImplementationWrapper(block, signature, implementation) {
      const retType = signature.retType;
      const argTypes = signature.argTypes;
      const argVariableNames = argTypes.map(function(t, i) {
        if (i === 0)
          return "handle";
        else
          return "a" + i;
      });
      const callArgs = argTypes.slice(1).map(function(t, i) {
        const argVariableName = argVariableNames[1 + i];
        if (t.fromNative) {
          return "argTypes[" + (1 + i) + "].fromNative.call(this, " + argVariableName + ")";
        }
        return argVariableName;
      });
      let returnCaptureLeft;
      let returnCaptureRight;
      if (retType.type === "void") {
        returnCaptureLeft = "";
        returnCaptureRight = "";
      } else if (retType.toNative) {
        returnCaptureLeft = "return retType.toNative.call(this, ";
        returnCaptureRight = ")";
      } else {
        returnCaptureLeft = "return ";
        returnCaptureRight = "";
      }
      const f = eval("var f = function (" + argVariableNames.join(", ") + ") { if (!this.handle.equals(handle))this.handle = handle;" + returnCaptureLeft + "implementation.call(block" + (callArgs.length > 0 ? ", " : "") + callArgs.join(", ") + ")" + returnCaptureRight + "; }; f;");
      return f.bind(block);
    }
    function rawFridaType(t) {
      return t === "object" ? "pointer" : t;
    }
    function makeClassName() {
      for (let i = 1; true; i++) {
        const name = "FridaAnonymousClass" + i;
        if (!(name in classRegistry)) {
          return name;
        }
      }
    }
    function makeProtocolName() {
      for (let i = 1; true; i++) {
        const name = "FridaAnonymousProtocol" + i;
        if (!(name in protocolRegistry)) {
          return name;
        }
      }
    }
    function objcMethodName(name) {
      return name.replace(/_/g, ":");
    }
    function jsMethodName(name) {
      let result = name.replace(/:/g, "_");
      if (objCObjectBuiltins.has(result))
        result += "2";
      return result;
    }
    const isaMasks = {
      x64: "0x7ffffffffff8",
      arm64: "0xffffffff8"
    };
    const rawMask = isaMasks[Process.arch];
    if (rawMask !== void 0) {
      const mask = ptr(rawMask);
      readObjectIsa = function(p) {
        return p.readPointer().and(mask);
      };
    } else {
      readObjectIsa = function(p) {
        return p.readPointer();
      };
    }
    function getMsgSendImpl(signature2, invocationOptions2) {
      return resolveMsgSendImpl(msgSendBySignatureId, signature2, invocationOptions2, false);
    }
    function getMsgSendSuperImpl(signature2, invocationOptions2) {
      return resolveMsgSendImpl(msgSendSuperBySignatureId, signature2, invocationOptions2, true);
    }
    function resolveMsgSendImpl(cache, signature2, invocationOptions2, isSuper) {
      if (invocationOptions2 !== defaultInvocationOptions)
        return makeMsgSendImpl(signature2, invocationOptions2, isSuper);
      const { id } = signature2;
      let impl = cache.get(id);
      if (impl === void 0) {
        impl = makeMsgSendImpl(signature2, invocationOptions2, isSuper);
        cache.set(id, impl);
      }
      return impl;
    }
    function makeMsgSendImpl(signature2, invocationOptions2, isSuper) {
      const retType2 = signature2.retType.type;
      const argTypes2 = signature2.argTypes.map(function(t) {
        return t.type;
      });
      const components = ["objc_msgSend"];
      if (isSuper)
        components.push("Super");
      const returnsStruct = retType2 instanceof Array;
      if (returnsStruct && !typeFitsInRegisters(retType2))
        components.push("_stret");
      else if (retType2 === "float" || retType2 === "double")
        components.push("_fpret");
      const name = components.join("");
      return new NativeFunction(api[name], retType2, argTypes2, invocationOptions2);
    }
    function typeFitsInRegisters(type) {
      if (Process.arch !== "x64")
        return false;
      const size = sizeOfTypeOnX64(type);
      return size <= 16;
    }
    function sizeOfTypeOnX64(type) {
      if (type instanceof Array)
        return type.reduce((total, field) => total + sizeOfTypeOnX64(field), 0);
      switch (type) {
        case "bool":
        case "char":
        case "uchar":
          return 1;
        case "int16":
        case "uint16":
          return 2;
        case "int":
        case "int32":
        case "uint":
        case "uint32":
        case "float":
          return 4;
        default:
          return 8;
      }
    }
    function unparseSignature(retType2, argTypes2) {
      const retTypeId = typeIdFromAlias(retType2);
      const argTypeIds = argTypes2.map(typeIdFromAlias);
      const argSizes = argTypeIds.map((id) => singularTypeById[id].size);
      const frameSize = argSizes.reduce((total, size) => total + size, 0);
      let frameOffset = 0;
      return retTypeId + frameSize + argTypeIds.map((id, i) => {
        const result = id + frameOffset;
        frameOffset += argSizes[i];
        return result;
      }).join("");
    }
    function parseSignature(sig) {
      const cursor = [sig, 0];
      parseQualifiers(cursor);
      const retType2 = readType(cursor);
      readNumber(cursor);
      const argTypes2 = [];
      let id = JSON.stringify(retType2.type);
      while (dataAvailable(cursor)) {
        parseQualifiers(cursor);
        const argType = readType(cursor);
        readNumber(cursor);
        argTypes2.push(argType);
        id += JSON.stringify(argType.type);
      }
      return {
        id,
        retType: retType2,
        argTypes: argTypes2
      };
    }
    function parseType(type) {
      const cursor = [type, 0];
      return readType(cursor);
    }
    function readType(cursor) {
      let id = readChar(cursor);
      if (id === "@") {
        let next = peekChar(cursor);
        if (next === "?") {
          id += next;
          skipChar(cursor);
          if (peekChar(cursor) === "<")
            skipExtendedBlock(cursor);
        } else if (next === '"') {
          skipChar(cursor);
          readUntil('"', cursor);
        }
      } else if (id === "^") {
        let next = peekChar(cursor);
        if (next === "@") {
          id += next;
          skipChar(cursor);
        }
      }
      const type = singularTypeById[id];
      if (type !== void 0) {
        return type;
      } else if (id === "[") {
        const length = readNumber(cursor);
        const elementType = readType(cursor);
        skipChar(cursor);
        return arrayType(length, elementType);
      } else if (id === "{") {
        if (!tokenExistsAhead("=", "}", cursor)) {
          readUntil("}", cursor);
          return structType([]);
        }
        readUntil("=", cursor);
        const structFields = [];
        let ch;
        while ((ch = peekChar(cursor)) !== "}") {
          if (ch === '"') {
            skipChar(cursor);
            readUntil('"', cursor);
          }
          structFields.push(readType(cursor));
        }
        skipChar(cursor);
        return structType(structFields);
      } else if (id === "(") {
        readUntil("=", cursor);
        const unionFields = [];
        while (peekChar(cursor) !== ")")
          unionFields.push(readType(cursor));
        skipChar(cursor);
        return unionType(unionFields);
      } else if (id === "b") {
        readNumber(cursor);
        return singularTypeById.i;
      } else if (id === "^") {
        readType(cursor);
        return singularTypeById["?"];
      } else if (modifiers.has(id)) {
        return readType(cursor);
      } else {
        throw new Error("Unable to handle type " + id);
      }
    }
    function skipExtendedBlock(cursor) {
      let ch;
      skipChar(cursor);
      while ((ch = peekChar(cursor)) !== ">") {
        if (peekChar(cursor) === "<") {
          skipExtendedBlock(cursor);
        } else {
          skipChar(cursor);
          if (ch === '"')
            readUntil('"', cursor);
        }
      }
      skipChar(cursor);
    }
    function readNumber(cursor) {
      let result = "";
      while (dataAvailable(cursor)) {
        const c = peekChar(cursor);
        const v = c.charCodeAt(0);
        const isDigit = v >= 48 && v <= 57;
        if (isDigit) {
          result += c;
          skipChar(cursor);
        } else {
          break;
        }
      }
      return parseInt(result);
    }
    function readUntil(token, cursor) {
      const buffer = cursor[0];
      const offset = cursor[1];
      const index = buffer.indexOf(token, offset);
      if (index === -1)
        throw new Error("Expected token '" + token + "' not found");
      const result = buffer.substring(offset, index);
      cursor[1] = index + 1;
      return result;
    }
    function readChar(cursor) {
      return cursor[0][cursor[1]++];
    }
    function peekChar(cursor) {
      return cursor[0][cursor[1]];
    }
    function tokenExistsAhead(token, terminator, cursor) {
      const [buffer, offset] = cursor;
      const tokenIndex = buffer.indexOf(token, offset);
      if (tokenIndex === -1)
        return false;
      const terminatorIndex = buffer.indexOf(terminator, offset);
      if (terminatorIndex === -1)
        throw new Error("Expected to find terminator: " + terminator);
      return tokenIndex < terminatorIndex;
    }
    function skipChar(cursor) {
      cursor[1]++;
    }
    function dataAvailable(cursor) {
      return cursor[1] !== cursor[0].length;
    }
    const qualifierById = {
      "r": "const",
      "n": "in",
      "N": "inout",
      "o": "out",
      "O": "bycopy",
      "R": "byref",
      "V": "oneway"
    };
    function parseQualifiers(cursor) {
      const qualifiers = [];
      while (true) {
        const q = qualifierById[peekChar(cursor)];
        if (q === void 0)
          break;
        qualifiers.push(q);
        skipChar(cursor);
      }
      return qualifiers;
    }
    const idByAlias = {
      "char": "c",
      "int": "i",
      "int16": "s",
      "int32": "i",
      "int64": "q",
      "uchar": "C",
      "uint": "I",
      "uint16": "S",
      "uint32": "I",
      "uint64": "Q",
      "float": "f",
      "double": "d",
      "bool": "B",
      "void": "v",
      "string": "*",
      "object": "@",
      "block": "@?",
      "class": "#",
      "selector": ":",
      "pointer": "^v"
    };
    function typeIdFromAlias(alias) {
      if (typeof alias === "object" && alias !== null)
        return `@"${alias.type}"`;
      const id = idByAlias[alias];
      if (id === void 0)
        throw new Error("No known encoding for type " + alias);
      return id;
    }
    const fromNativeId = function(h) {
      if (h.isNull()) {
        return null;
      } else if (h.toString(16) === this.handle.toString(16)) {
        return this;
      } else {
        return new ObjCObject(h);
      }
    };
    const toNativeId = function(v) {
      if (v === null)
        return NULL;
      const type = typeof v;
      if (type === "string") {
        if (cachedNSStringCtor === null) {
          cachedNSString = classRegistry.NSString;
          cachedNSStringCtor = cachedNSString.stringWithUTF8String_;
        }
        return cachedNSStringCtor.call(cachedNSString, Memory.allocUtf8String(v));
      } else if (type === "number") {
        if (cachedNSNumberCtor === null) {
          cachedNSNumber = classRegistry.NSNumber;
          cachedNSNumberCtor = cachedNSNumber.numberWithDouble_;
        }
        return cachedNSNumberCtor.call(cachedNSNumber, v);
      }
      return v;
    };
    const fromNativeBlock = function(h) {
      if (h.isNull()) {
        return null;
      } else if (h.toString(16) === this.handle.toString(16)) {
        return this;
      } else {
        return new Block(h);
      }
    };
    const toNativeBlock = function(v) {
      return v !== null ? v : NULL;
    };
    const toNativeObjectArray = function(v) {
      if (v instanceof Array) {
        const length = v.length;
        const array = Memory.alloc(length * pointerSize);
        for (let i = 0; i !== length; i++)
          array.add(i * pointerSize).writePointer(toNativeId(v[i]));
        return array;
      }
      return v;
    };
    function arrayType(length, elementType) {
      return {
        type: "pointer",
        read(address) {
          const result = [];
          const elementSize = elementType.size;
          for (let index = 0; index !== length; index++) {
            result.push(elementType.read(address.add(index * elementSize)));
          }
          return result;
        },
        write(address, values) {
          const elementSize = elementType.size;
          values.forEach((value, index) => {
            elementType.write(address.add(index * elementSize), value);
          });
        }
      };
    }
    function structType(fieldTypes) {
      let fromNative, toNative;
      if (fieldTypes.some(function(t) {
        return !!t.fromNative;
      })) {
        const fromTransforms = fieldTypes.map(function(t) {
          if (t.fromNative)
            return t.fromNative;
          else
            return identityTransform;
        });
        fromNative = function(v) {
          return v.map(function(e, i) {
            return fromTransforms[i].call(this, e);
          });
        };
      } else {
        fromNative = identityTransform;
      }
      if (fieldTypes.some(function(t) {
        return !!t.toNative;
      })) {
        const toTransforms = fieldTypes.map(function(t) {
          if (t.toNative)
            return t.toNative;
          else
            return identityTransform;
        });
        toNative = function(v) {
          return v.map(function(e, i) {
            return toTransforms[i].call(this, e);
          });
        };
      } else {
        toNative = identityTransform;
      }
      const [totalSize, fieldOffsets] = fieldTypes.reduce(function(result, t) {
        const [previousOffset, offsets] = result;
        const { size } = t;
        const offset = align(previousOffset, size);
        offsets.push(offset);
        return [offset + size, offsets];
      }, [0, []]);
      return {
        type: fieldTypes.map((t) => t.type),
        size: totalSize,
        read(address) {
          return fieldTypes.map((type, index) => type.read(address.add(fieldOffsets[index])));
        },
        write(address, values) {
          values.forEach((value, index) => {
            fieldTypes[index].write(address.add(fieldOffsets[index]), value);
          });
        },
        fromNative,
        toNative
      };
    }
    function unionType(fieldTypes) {
      const largestType = fieldTypes.reduce(function(largest, t) {
        if (t.size > largest.size)
          return t;
        else
          return largest;
      }, fieldTypes[0]);
      let fromNative, toNative;
      if (largestType.fromNative) {
        const fromTransform = largestType.fromNative;
        fromNative = function(v) {
          return fromTransform.call(this, v[0]);
        };
      } else {
        fromNative = function(v) {
          return v[0];
        };
      }
      if (largestType.toNative) {
        const toTransform = largestType.toNative;
        toNative = function(v) {
          return [toTransform.call(this, v)];
        };
      } else {
        toNative = function(v) {
          return [v];
        };
      }
      return {
        type: [largestType.type],
        size: largestType.size,
        read: largestType.read,
        write: largestType.write,
        fromNative,
        toNative
      };
    }
    const longBits = pointerSize == 8 && Process.platform !== "windows" ? 64 : 32;
    modifiers = /* @__PURE__ */ new Set([
      "j",
      // complex
      "A",
      // atomic
      "r",
      // const
      "n",
      // in
      "N",
      // inout
      "o",
      // out
      "O",
      // by copy
      "R",
      // by ref
      "V",
      // one way
      "+"
      // GNU register
    ]);
    singularTypeById = {
      "c": {
        type: "char",
        size: 1,
        read: (address) => address.readS8(),
        write: (address, value) => {
          address.writeS8(value);
        },
        toNative(v) {
          if (typeof v === "boolean") {
            return v ? 1 : 0;
          }
          return v;
        }
      },
      "i": {
        type: "int",
        size: 4,
        read: (address) => address.readInt(),
        write: (address, value) => {
          address.writeInt(value);
        }
      },
      "s": {
        type: "int16",
        size: 2,
        read: (address) => address.readS16(),
        write: (address, value) => {
          address.writeS16(value);
        }
      },
      "l": {
        type: "int32",
        size: 4,
        read: (address) => address.readS32(),
        write: (address, value) => {
          address.writeS32(value);
        }
      },
      "q": {
        type: "int64",
        size: 8,
        read: (address) => address.readS64(),
        write: (address, value) => {
          address.writeS64(value);
        }
      },
      "C": {
        type: "uchar",
        size: 1,
        read: (address) => address.readU8(),
        write: (address, value) => {
          address.writeU8(value);
        }
      },
      "I": {
        type: "uint",
        size: 4,
        read: (address) => address.readUInt(),
        write: (address, value) => {
          address.writeUInt(value);
        }
      },
      "S": {
        type: "uint16",
        size: 2,
        read: (address) => address.readU16(),
        write: (address, value) => {
          address.writeU16(value);
        }
      },
      "L": {
        type: "uint" + longBits,
        size: longBits / 8,
        read: (address) => address.readULong(),
        write: (address, value) => {
          address.writeULong(value);
        }
      },
      "Q": {
        type: "uint64",
        size: 8,
        read: (address) => address.readU64(),
        write: (address, value) => {
          address.writeU64(value);
        }
      },
      "f": {
        type: "float",
        size: 4,
        read: (address) => address.readFloat(),
        write: (address, value) => {
          address.writeFloat(value);
        }
      },
      "d": {
        type: "double",
        size: 8,
        read: (address) => address.readDouble(),
        write: (address, value) => {
          address.writeDouble(value);
        }
      },
      "B": {
        type: "bool",
        size: 1,
        read: (address) => address.readU8(),
        write: (address, value) => {
          address.writeU8(value);
        },
        fromNative(v) {
          return v ? true : false;
        },
        toNative(v) {
          return v ? 1 : 0;
        }
      },
      "v": {
        type: "void",
        size: 0
      },
      "*": {
        type: "pointer",
        size: pointerSize,
        read: (address) => address.readPointer(),
        write: (address, value) => {
          address.writePointer(value);
        },
        fromNative(h) {
          return h.readCString();
        }
      },
      "@": {
        type: "pointer",
        size: pointerSize,
        read: (address) => address.readPointer(),
        write: (address, value) => {
          address.writePointer(value);
        },
        fromNative: fromNativeId,
        toNative: toNativeId
      },
      "@?": {
        type: "pointer",
        size: pointerSize,
        read: (address) => address.readPointer(),
        write: (address, value) => {
          address.writePointer(value);
        },
        fromNative: fromNativeBlock,
        toNative: toNativeBlock
      },
      "^@": {
        type: "pointer",
        size: pointerSize,
        read: (address) => address.readPointer(),
        write: (address, value) => {
          address.writePointer(value);
        },
        toNative: toNativeObjectArray
      },
      "^v": {
        type: "pointer",
        size: pointerSize,
        read: (address) => address.readPointer(),
        write: (address, value) => {
          address.writePointer(value);
        }
      },
      "#": {
        type: "pointer",
        size: pointerSize,
        read: (address) => address.readPointer(),
        write: (address, value) => {
          address.writePointer(value);
        },
        fromNative: fromNativeId,
        toNative: toNativeId
      },
      ":": {
        type: "pointer",
        size: pointerSize,
        read: (address) => address.readPointer(),
        write: (address, value) => {
          address.writePointer(value);
        }
      },
      "?": {
        type: "pointer",
        size: pointerSize,
        read: (address) => address.readPointer(),
        write: (address, value) => {
          address.writePointer(value);
        }
      }
    };
    function identityTransform(v) {
      return v;
    }
    function align(value, boundary) {
      const remainder = value % boundary;
      return remainder === 0 ? value : value + (boundary - remainder);
    }
  }
  var runtime = new Runtime();
  var frida_objc_bridge_default = runtime;

  // agent/ios/format.js
  var PATH_SEPARATOR = "/";
  var XPC_TYPE_ALIASES = {
    string: "string",
    int: "int64",
    long: "int64",
    int64: "int64",
    uint64: "uint64",
    bool: "bool",
    boolean: "bool",
    float: "double",
    double: "double",
    data: "data"
  };
  function normalizeValueType(type) {
    return XPC_TYPE_ALIASES[String(type || "string").toLowerCase()] || null;
  }
  function escapeRegExp(text) {
    return text.replace(/[.*+?^${}()|[\]\\\/]/g, "\\$&");
  }
  function globToRegExp(pattern) {
    let out = "";
    let i = 0;
    const n = pattern.length;
    while (i < n) {
      const c = pattern[i];
      i += 1;
      if (c === "*") {
        out += "[\\s\\S]*";
      } else if (c === "?") {
        out += "[\\s\\S]";
      } else if (c === "[") {
        let j = i;
        if (j < n && pattern[j] === "!") j += 1;
        if (j < n && pattern[j] === "]") j += 1;
        while (j < n && pattern[j] !== "]") j += 1;
        if (j >= n) {
          out += "\\[";
        } else {
          let stuff = pattern.slice(i, j).replace(/\\/g, "\\\\");
          i = j + 1;
          if (stuff[0] === "!") stuff = "^" + stuff.slice(1);
          else if (stuff[0] === "^") stuff = "\\" + stuff;
          out += "[" + stuff + "]";
        }
      } else {
        out += escapeRegExp(c);
      }
    }
    return new RegExp("^(?:" + out + ")$");
  }
  var globCache = /* @__PURE__ */ new Map();
  function fnmatch(value, pattern) {
    let re = globCache.get(pattern);
    if (re === void 0) {
      re = globToRegExp(pattern);
      if (globCache.size > 512) globCache.clear();
      globCache.set(pattern, re);
    }
    return re.test(value);
  }
  function checkMatch(context, rules) {
    for (const rule of rules) {
      let matches = true;
      for (const key of Object.keys(rule)) {
        const p = rule[key];
        if (!(key in context)) {
          matches = false;
          break;
        }
        const val = context[key];
        if (p === "set" || p === "unset") {
          const isSet = Array.isArray(val) ? val.length > 0 : Boolean(val);
          const wantSet = p === "set";
          if (isSet !== wantSet) {
            matches = false;
            break;
          }
        } else if (Array.isArray(val)) {
          if (!val.some((v) => fnmatch(v, p))) {
            matches = false;
            break;
          }
        } else if (!fnmatch(val, p)) {
          matches = false;
          break;
        }
      }
      if (matches) return true;
    }
    return false;
  }
  function isVisible(context, ignoreList, focusList) {
    if (focusList && focusList.length) return checkMatch(context, focusList);
    return !checkMatch(context, ignoreList || []);
  }
  function buildFilterContext(payload) {
    const info = payload.infoIntent || {};
    const ipc = payload.ipc || {};
    const peer = ipc.peer || {};
    return {
      class: String(payload.className || ""),
      method: String(payload.methodName || ""),
      action: String(info.action || ""),
      component: String(info.component || ""),
      data: String(info.data || ""),
      direction: String(ipc.direction || ""),
      peer: peerLabel(peer)
    };
  }
  function peerLabel(peer) {
    if (!peer) return "";
    if (peer.path) return String(peer.path);
    if (peer.pid !== void 0 && peer.pid !== null && peer.pid > 0) return String(peer.pid);
    return "";
  }
  var HEX = "0123456789abcdef";
  function toHex(bytes, limit) {
    const n = Math.min(bytes.length, limit === void 0 ? bytes.length : limit);
    let out = "";
    for (let i = 0; i < n; i++) {
      out += HEX[bytes[i] >> 4] + HEX[bytes[i] & 15];
    }
    return out;
  }
  function parseHex(text) {
    const clean = String(text || "").replace(/^0x/i, "").replace(/[\s:]/g, "");
    if (clean.length % 2 !== 0 || /[^0-9a-fA-F]/.test(clean)) return null;
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++) {
      out[i] = parseInt(clean.substr(i * 2, 2), 16);
    }
    return out;
  }
  var B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  function toBase64(bytes) {
    let out = "";
    let i = 0;
    for (; i + 2 < bytes.length; i += 3) {
      const v = bytes[i] << 16 | bytes[i + 1] << 8 | bytes[i + 2];
      out += B64[v >> 18 & 63] + B64[v >> 12 & 63] + B64[v >> 6 & 63] + B64[v & 63];
    }
    const rest = bytes.length - i;
    if (rest === 1) {
      const v = bytes[i] << 16;
      out += B64[v >> 18 & 63] + B64[v >> 12 & 63] + "==";
    } else if (rest === 2) {
      const v = bytes[i] << 16 | bytes[i + 1] << 8;
      out += B64[v >> 18 & 63] + B64[v >> 12 & 63] + B64[v >> 6 & 63] + "=";
    }
    return out;
  }
  function asciiPrefix(bytes, length) {
    let out = "";
    for (let i = 0; i < Math.min(length, bytes.length); i++) {
      out += String.fromCharCode(bytes[i]);
    }
    return out;
  }
  function detectBplist(bytes) {
    if (bytes.length < 8) return null;
    const magic = asciiPrefix(bytes, 8);
    return /^bplist\d\d$/.test(magic) ? magic : null;
  }
  function extractStrings(bytes, minLength, maxStrings) {
    const min = minLength || 4;
    const max = maxStrings || 64;
    const out = [];
    const seen = /* @__PURE__ */ new Set();
    let current = "";
    const flush = () => {
      if (current.length >= min && !seen.has(current) && !/^bplist\d\d$/.test(current)) {
        seen.add(current);
        out.push(current);
      }
      current = "";
    };
    for (let i = 0; i < bytes.length && out.length < max; i++) {
      const b = bytes[i];
      if (b >= 32 && b < 127) {
        current += String.fromCharCode(b);
      } else {
        flush();
      }
    }
    if (out.length < max) flush();
    return out;
  }
  var SELECTOR_RE = /^[A-Za-z_][A-Za-z0-9_]*(?::(?:[A-Za-z_][A-Za-z0-9_]*:)*)?$/;
  function guessSelector(strings) {
    for (const s of strings || []) {
      if (s.indexOf(":") !== -1 && SELECTOR_RE.test(s)) return s;
    }
    return null;
  }
  function describeNode(node) {
    if (!node) return "";
    switch (node.t) {
      case "dictionary":
        return "{" + node.v.length + " keys}";
      case "array":
        return "[" + node.v.length + " items]";
      case "data": {
        let text = node.len + " bytes";
        if (node.bplist) text += " " + node.bplist;
        if (node.hex) text += " " + node.hex + (node.len * 2 > node.hex.length ? "\u2026" : "");
        return text;
      }
      case "truncated":
        return "\u2026";
      default:
        return node.v === void 0 || node.v === null ? "" : String(node.v);
    }
  }
  function joinPath(prefix, key) {
    return prefix ? prefix + PATH_SEPARATOR + key : key;
  }
  function flattenTree(node, maxEntries) {
    const limit = maxEntries || 256;
    const out = {};
    let count = 0;
    let truncated = false;
    function visit(prefix, n) {
      if (count >= limit) {
        truncated = true;
        return;
      }
      if (n.t === "dictionary" && n.v.length > 0) {
        for (const [key, child] of n.v) visit(joinPath(prefix, key), child);
        return;
      }
      if (n.t === "array" && n.v.length > 0) {
        n.v.forEach((child, idx) => visit(prefix + "[" + idx + "]", child));
        return;
      }
      out[prefix || "(root)"] = { type: n.t, value: describeNode(n) };
      count += 1;
    }
    if (node) visit("", node);
    if (truncated) out["\u2026"] = { type: "truncated", value: "more entries omitted" };
    return out;
  }
  function collectBlobs(node, maxBlobs) {
    const limit = maxBlobs || 16;
    const out = [];
    function visit(prefix, n) {
      if (!n || out.length >= limit) return;
      if (n.t === "dictionary") {
        for (const [key, child] of n.v) visit(joinPath(prefix, key), child);
      } else if (n.t === "array") {
        n.v.forEach((child, idx) => visit(prefix + "[" + idx + "]", child));
      } else if (n.t === "data" && (n.bplist || n.strings && n.strings.length)) {
        const blob = { path: prefix || "(root)", length: n.len, format: n.bplist || null, strings: n.strings || [] };
        if (n.b64) blob.base64 = n.b64;
        out.push(blob);
      }
    }
    visit("", node);
    return out;
  }
  function findChild(node, key) {
    if (!node || node.t !== "dictionary") return null;
    for (const [k, child] of node.v) {
      if (k === key) return child;
    }
    return null;
  }
  function nsxpcInfo(node) {
    const root = findChild(node, "root");
    if (!root || root.t !== "data" || !root.bplist || !/^bplist1[5-7]$/.test(root.bplist)) return null;
    return {
      encoding: root.bplist,
      selector: guessSelector(root.strings),
      strings: root.strings || []
    };
  }
  function splitPath(path) {
    return String(path).split(PATH_SEPARATOR).filter((part) => part.length > 0);
  }
  var TYPE_QUALIFIERS = "rnNoORVA";
  function skipDigits(types2, i) {
    while (i < types2.length && types2[i] >= "0" && types2[i] <= "9") i += 1;
    return i;
  }
  function readBalanced(types2, i, open, close) {
    let depth = 0;
    const start = i;
    for (; i < types2.length; i++) {
      if (types2[i] === open) depth += 1;
      else if (types2[i] === close) {
        depth -= 1;
        if (depth === 0) return [types2.slice(start, i + 1), i + 1];
      }
    }
    return [types2.slice(start), types2.length];
  }
  function readOneType(types2, i) {
    while (i < types2.length && TYPE_QUALIFIERS.indexOf(types2[i]) !== -1) i += 1;
    const c = types2[i];
    if (c === void 0) return [null, i];
    if (c === "@") {
      if (types2[i + 1] === "?") {
        let end = i + 2;
        if (types2[end] === "<") end = readBalanced(types2, end, "<", ">")[1];
        return ["@?", end];
      }
      if (types2[i + 1] === '"') {
        const close = types2.indexOf('"', i + 2);
        if (close !== -1) return ['@"' + types2.slice(i + 2, close) + '"', close + 1];
      }
      return ["@", i + 1];
    }
    if (c === "^") {
      const [inner, end] = readOneType(types2, i + 1);
      return ["^" + (inner || ""), end];
    }
    if (c === "{") return readBalanced(types2, i, "{", "}");
    if (c === "(") return readBalanced(types2, i, "(", ")");
    if (c === "[") return readBalanced(types2, i, "[", "]");
    if (c === "b") return [types2.slice(i, skipDigits(types2, i + 1)), skipDigits(types2, i + 1)];
    return [c, i + 1];
  }
  function parseObjCTypes(types2) {
    const out = [];
    let i = 0;
    const text = String(types2 || "");
    while (i < text.length) {
      const [type, next] = readOneType(text, i);
      if (type === null || next <= i) break;
      out.push(type);
      i = skipDigits(text, next);
    }
    return out;
  }
  function objcTypeKind(encoding) {
    if (!encoding) return "unknown";
    if (encoding === "@?") return "block";
    if (encoding[0] === "@") return "object";
    if (encoding === ":") return "selector";
    if (encoding === "#") return "class";
    if (encoding === "*") return "cstring";
    if (encoding === "B") return "bool";
    if ("cislqCISLQ".indexOf(encoding) !== -1) return "integer";
    if (encoding === "f" || encoding === "d") return "float";
    if (encoding === "v") return "void";
    if (encoding[0] === "^") return "pointer";
    if (encoding[0] === "{") return "struct";
    return "unknown";
  }
  function objcClassHint(encoding) {
    const m2 = /^@"([^"<]*)/.exec(encoding || "");
    return m2 && m2[1] ? m2[1] : null;
  }
  var CSMAGIC_EMBEDDED_SIGNATURE = 4208856256;
  var CSMAGIC_EMBEDDED_ENTITLEMENTS = 4208882033;
  var CSSLOT_ENTITLEMENTS = 5;
  function readU32BE(bytes, offset) {
    return (bytes[offset] << 24 >>> 0) + (bytes[offset + 1] << 16) + (bytes[offset + 2] << 8) + bytes[offset + 3];
  }
  function decodeUtf8(bytes) {
    let out = "";
    let i = 0;
    while (i < bytes.length) {
      const b = bytes[i];
      let cp;
      if (b < 128) {
        cp = b;
        i += 1;
      } else if (b >= 192 && b < 224) {
        cp = (b & 31) << 6 | bytes[i + 1] & 63;
        i += 2;
      } else if (b >= 224 && b < 240) {
        cp = (b & 15) << 12 | (bytes[i + 1] & 63) << 6 | bytes[i + 2] & 63;
        i += 3;
      } else {
        cp = (b & 7) << 18 | (bytes[i + 1] & 63) << 12 | (bytes[i + 2] & 63) << 6 | bytes[i + 3] & 63;
        i += 4;
      }
      out += String.fromCodePoint(cp);
    }
    return out;
  }
  function entitlementsFromSuperBlob(bytes) {
    if (!bytes || bytes.length < 12 || readU32BE(bytes, 0) !== CSMAGIC_EMBEDDED_SIGNATURE) return null;
    const count = readU32BE(bytes, 8);
    for (let idx = 0; idx < count; idx++) {
      const entry = 12 + idx * 8;
      if (entry + 8 > bytes.length) break;
      const type = readU32BE(bytes, entry);
      const offset = readU32BE(bytes, entry + 4);
      if (type !== CSSLOT_ENTITLEMENTS || offset + 8 > bytes.length) continue;
      if (readU32BE(bytes, offset) !== CSMAGIC_EMBEDDED_ENTITLEMENTS) continue;
      const length = readU32BE(bytes, offset + 4);
      const end = Math.min(bytes.length, offset + length);
      return decodeUtf8(bytes.subarray(offset + 8, end));
    }
    return null;
  }
  function nsxpcSendLayout(privateSelector) {
    const parts = String(privateSelector || "").split(":").slice(0, -1);
    if (parts.length === 0) return null;
    const at = (name) => {
      const i = parts.indexOf(name);
      return i === -1 ? -1 : i + 2;
    };
    if (parts[0] === "_sendInvocation") {
      return {
        kind: "invocation",
        invocation: 2,
        arguments: at("orArguments"),
        count: at("count"),
        signature: at("methodSignature"),
        selector: at("selector"),
        proxy: at("withProxy"),
        values: []
      };
    }
    if (parts[0] === "_sendSelector") {
      const values = [];
      for (let i = 1; at("arg" + i) !== -1; i++) values.push(at("arg" + i));
      return { kind: "selector", invocation: -1, arguments: -1, count: -1, signature: -1, selector: 2, proxy: at("withProxy"), values };
    }
    return null;
  }
  var SCALAR_LAYOUT = {
    c: [1, "S8"],
    C: [1, "U8"],
    B: [1, "U8"],
    s: [2, "S16"],
    S: [2, "U16"],
    i: [4, "S32"],
    I: [4, "U32"],
    l: [8, "S64"],
    L: [8, "U64"],
    q: [8, "S64"],
    Q: [8, "U64"],
    f: [4, "Float"],
    d: [8, "Double"]
  };
  function scalarLayout(encoding) {
    const stripped = String(encoding || "").replace(/^[rnNoORVA]+/, "");
    return SCALAR_LAYOUT[stripped] || null;
  }
  function validateSendLayout(layout, encodings) {
    if (!layout || !encodings || encodings.length < 3) return false;
    const kindAt = (index) => objcTypeKind(encodings[index + 1]);
    if (layout.proxy >= 0 && kindAt(layout.proxy) !== "object") return false;
    if (layout.selector >= 0 && kindAt(layout.selector) !== "selector") return false;
    if (layout.kind === "invocation") return kindAt(layout.invocation) === "object";
    if (layout.kind === "selector") {
      return layout.selector >= 0 && layout.values.every((index) => kindAt(index) === "object");
    }
    return false;
  }
  function hookEntryKey(entry) {
    return [entry.kind, entry.function || entry.feature || entry.method || ""].join(":");
  }
  function mergeHookEntries(entries) {
    const merged = /* @__PURE__ */ new Map();
    for (const entry of entries || []) {
      if (!entry || typeof entry !== "object" || entry.clazz !== void 0 || !entry.kind) continue;
      const key = hookEntryKey(entry);
      merged.delete(key);
      merged.set(key, entry);
    }
    return Array.from(merged.values()).filter((entry) => entry.enabled !== false);
  }
  var NAVIGATION_TYPES = {
    "-1": "other",
    0: "link",
    1: "form submit",
    2: "back/forward",
    3: "reload",
    4: "form resubmit"
  };
  function navigationTypeName(value) {
    const name = NAVIGATION_TYPES[String(Number(value))];
    return name || String(value);
  }
  function bodyPreview(bytes, limit) {
    const max = limit || 512;
    if (!bytes || bytes.length === 0) return "";
    const slice = bytes.subarray(0, max);
    let printable = 0;
    for (const b of slice) {
      if (b >= 32 && b < 127 || b === 10 || b === 13 || b === 9) printable += 1;
    }
    const more = bytes.length > max ? "\u2026" : "";
    if (printable / slice.length >= 0.9) {
      let text = "";
      for (const b of slice) text += String.fromCharCode(b);
      return text + more;
    }
    return "hex:" + toHex(slice) + more;
  }
  function hostOf(url) {
    const m2 = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/(?:[^@/?#]*@)?([^:/?#]+)/.exec(String(url || ""));
    return m2 ? m2[1].toLowerCase() : null;
  }

  // agent/ios/decisions.js
  function createDecisionCore(options) {
    const opts = Object.assign({
      send: globalThis.send,
      recv: globalThis.recv,
      threadId: () => Process.getCurrentThreadId(),
      pid: () => Process.id,
      jsThreadId: null,
      captureStack: () => []
    }, options || {});
    let blockEnabled = true;
    let waiting = false;
    let activeDecisionId = null;
    let activeSupportedMods = [];
    let resumeMode = "forward";
    let modQueue = [];
    let decisionCounter = 0;
    let eventCounter = 0;
    let ignoreRules = [];
    let focusRules = [];
    function isFiltered(payload) {
      if (!ignoreRules.length && !focusRules.length) return false;
      try {
        return !isVisible(buildFilterContext(payload), ignoreRules, focusRules);
      } catch (_) {
        return false;
      }
    }
    function buildPayload(ev, context) {
      eventCounter += 1;
      return {
        platform: "ios",
        eventId: "ev-" + opts.pid() + "-" + eventCounter,
        className: ev.className || null,
        methodName: ev.methodName,
        stackTrace: opts.captureStack(context),
        infoIntent: {
          component: ev.component || null,
          action: ev.action || null,
          data: ev.data || null,
          extras: ev.extras || {}
        },
        attackSurface: ev.attackSurface || null,
        ipc: ev.ipc || {}
      };
    }
    function process(ev, context) {
      const payload = buildPayload(ev, context);
      let reason = null;
      if (!ev.interceptable) reason = "observe";
      else if (!blockEnabled) reason = "intercept_off";
      else if (waiting) reason = "busy";
      else if (opts.jsThreadId !== null && opts.threadId() === opts.jsThreadId) reason = "agent_thread";
      else if (isFiltered(payload)) reason = "filtered";
      const willBlock = reason === null;
      let decisionId = null;
      let operation = null;
      if (willBlock) {
        waiting = true;
        decisionCounter += 1;
        decisionId = "decision-" + opts.pid() + "-" + decisionCounter;
        activeDecisionId = decisionId;
        activeSupportedMods = ev.mods || [];
        resumeMode = "forward";
        modQueue = [];
        operation = opts.recv("ioxen-wake:" + decisionId, function() {
        });
      }
      payload.decision = { required: willBlock, id: decisionId, reason, mods: ev.mods || [] };
      opts.send(payload);
      if (!willBlock) return { mode: "forward", mods: [], eventId: payload.eventId };
      try {
        operation.wait();
        return { mode: resumeMode, mods: modQueue.slice(), eventId: payload.eventId };
      } finally {
        waiting = false;
        activeDecisionId = null;
        activeSupportedMods = [];
        resumeMode = "forward";
        modQueue = [];
      }
    }
    function matches(decisionId) {
      return waiting && (!decisionId || decisionId === activeDecisionId);
    }
    return {
      process,
      forward(decisionId) {
        if (!matches(decisionId)) return false;
        resumeMode = "forward";
        return true;
      },
      drop(decisionId) {
        if (!matches(decisionId)) return false;
        resumeMode = "drop";
        return true;
      },
      stageMod(type, key, val, extraType, decisionId) {
        if (!matches(decisionId)) {
          opts.send("[!] Error: No event blocked to modify.");
          return false;
        }
        if (activeSupportedMods.indexOf(type) === -1) {
          opts.send('[!] Modification "' + type + '" is not supported for this event');
          return false;
        }
        modQueue.push({ type, key, val, extraType });
        opts.send("[+] Modification staged: " + type + (extraType ? " (" + extraType + ")" : ""));
        return true;
      },
      // Returns the id of the released decision (or null) so the host can wake
      // the held thread.
      interceptOff() {
        blockEnabled = false;
        if (waiting) {
          resumeMode = "forward";
          return activeDecisionId;
        }
        return null;
      },
      interceptOn() {
        blockEnabled = true;
      },
      setFilters(ignoreList, focusList) {
        ignoreRules = Array.isArray(ignoreList) ? ignoreList : [];
        focusRules = Array.isArray(focusList) ? focusList : [];
        return true;
      },
      isWaiting() {
        return waiting;
      },
      eventCount() {
        return eventCounter;
      }
    };
  }

  // agent/ios_script.js
  var ObjC = typeof globalThis.ObjC !== "undefined" ? globalThis.ObjC : frida_objc_bridge_default;
  try {
    globalThis.ObjC = ObjC;
  } catch (_) {
  }
  var POINTER_SIZE = Process.pointerSize;
  var JS_THREAD_ID = Process.getCurrentThreadId();
  var MAX_STACK_FRAMES = 24;
  var MAX_TREE_NODES = 400;
  var MAX_TREE_DEPTH = 8;
  var MAX_STRING = 4096;
  var DATA_PREVIEW = 64;
  var DATA_SCAN = 65536;
  var MAX_DESCRIPTION = 8192;
  var rpcDepth = 0;
  var busyThreads = /* @__PURE__ */ new Set();
  var keepAlive = [];
  var report = { hooks: 0, failed: 0 };
  function log(prefix, text) {
    send(prefix + " " + text);
  }
  function findExport(name, moduleName) {
    if (moduleName) {
      try {
        const mod = Process.findModuleByName(moduleName);
        if (mod !== null) {
          const p = mod.findExportByName(name);
          if (p !== null) return p;
        }
      } catch (_) {
      }
    }
    try {
      if (typeof Module.findGlobalExportByName === "function") return Module.findGlobalExportByName(name);
    } catch (_) {
    }
    try {
      if (typeof Module.findExportByName === "function") return Module.findExportByName(moduleName || null, name);
    } catch (_) {
    }
    return null;
  }
  function nativeFn(name, moduleName, ret, args) {
    const p = findExport(name, moduleName);
    return p === null ? null : new NativeFunction(p, ret, args);
  }
  function readCString(p, limit) {
    if (p === null || p.isNull()) return null;
    try {
      const s = p.readUtf8String();
      return limit && s.length > limit ? s.slice(0, limit) + "\u2026" : s;
    } catch (_) {
      try {
        return p.readCString();
      } catch (_2) {
        return null;
      }
    }
  }
  function readBytes(p, length) {
    if (p === null || p.isNull() || length <= 0) return new Uint8Array(0);
    return new Uint8Array(p.readByteArray(length));
  }
  function toCString(text) {
    const p = Memory.allocUtf8String(String(text));
    keepTemp(p);
    return p;
  }
  var tempRefs = [];
  function keepTemp(value) {
    tempRefs.push(value);
    if (tempRefs.length > 256) tempRefs = tempRefs.slice(-128);
  }
  function shouldPassthrough() {
    const tid = Process.getCurrentThreadId();
    return tid === JS_THREAD_ID || rpcDepth > 0 || busyThreads.has(tid);
  }
  function withBusyThread(fn) {
    const tid = Process.getCurrentThreadId();
    busyThreads.add(tid);
    try {
      return fn();
    } finally {
      busyThreads.delete(tid);
    }
  }
  var moduleMap = null;
  var moduleMapRefreshed = 0;
  function moduleFor(address) {
    try {
      if (moduleMap === null) moduleMap = new ModuleMap();
      let mod = moduleMap.find(address);
      if (mod === null && Date.now() - moduleMapRefreshed > 1e3) {
        moduleMapRefreshed = Date.now();
        moduleMap.update();
        mod = moduleMap.find(address);
      }
      return mod;
    } catch (_) {
      return null;
    }
  }
  function moduleNameFor(address) {
    const mod = moduleFor(address);
    return mod ? mod.name : null;
  }
  function frameLabel(address) {
    const mod = moduleFor(address);
    return mod ? mod.name + "!0x" + address.sub(mod.base).toString(16) : address.toString();
  }
  var BACKTRACER = Process.platform === "darwin" ? Backtracer.ACCURATE : Backtracer.FUZZY;
  function captureStack(context) {
    try {
      return Thread.backtrace(context, BACKTRACER).slice(0, MAX_STACK_FRAMES).map(frameLabel);
    } catch (_) {
      return [];
    }
  }
  var LIBXPC = "libxpc.dylib";
  var X = {};
  var XPC_TYPES = /* @__PURE__ */ new Map();
  var XPC_CONST = {};
  var XPC_SIGNATURES = {
    xpc_get_type: ["pointer", ["pointer"]],
    xpc_copy_description: ["pointer", ["pointer"]],
    xpc_retain: ["pointer", ["pointer"]],
    xpc_release: ["void", ["pointer"]],
    xpc_dictionary_apply: ["bool", ["pointer", "pointer"]],
    xpc_dictionary_get_value: ["pointer", ["pointer", "pointer"]],
    xpc_dictionary_get_string: ["pointer", ["pointer", "pointer"]],
    xpc_dictionary_set_value: ["void", ["pointer", "pointer", "pointer"]],
    xpc_dictionary_set_string: ["void", ["pointer", "pointer", "pointer"]],
    xpc_dictionary_set_int64: ["void", ["pointer", "pointer", "int64"]],
    xpc_dictionary_set_uint64: ["void", ["pointer", "pointer", "uint64"]],
    xpc_dictionary_set_bool: ["void", ["pointer", "pointer", "bool"]],
    xpc_dictionary_set_double: ["void", ["pointer", "pointer", "double"]],
    xpc_dictionary_set_data: ["void", ["pointer", "pointer", "pointer", "size_t"]],
    xpc_array_get_count: ["size_t", ["pointer"]],
    xpc_array_get_value: ["pointer", ["pointer", "size_t"]],
    xpc_string_get_string_ptr: ["pointer", ["pointer"]],
    xpc_int64_get_value: ["int64", ["pointer"]],
    xpc_uint64_get_value: ["uint64", ["pointer"]],
    xpc_bool_get_value: ["bool", ["pointer"]],
    xpc_double_get_value: ["double", ["pointer"]],
    xpc_date_get_value: ["int64", ["pointer"]],
    xpc_data_get_length: ["size_t", ["pointer"]],
    xpc_data_get_bytes_ptr: ["pointer", ["pointer"]],
    xpc_uuid_get_bytes: ["pointer", ["pointer"]],
    xpc_connection_get_name: ["pointer", ["pointer"]],
    xpc_connection_get_pid: ["int", ["pointer"]],
    xpc_connection_get_euid: ["uint32", ["pointer"]],
    xpc_connection_cancel: ["void", ["pointer"]]
  };
  var XPC_TYPE_SYMBOLS = [
    "dictionary",
    "array",
    "string",
    "int64",
    "uint64",
    "bool",
    "double",
    "date",
    "data",
    "uuid",
    "fd",
    "shmem",
    "null",
    "endpoint",
    "connection",
    "error",
    "activity",
    "mach_send",
    "mach_recv",
    "pipe",
    "serializer",
    "session",
    "rich_error"
  ];
  var ERROR_SYMBOLS = {
    _xpc_error_connection_interrupted: "XPC_ERROR_CONNECTION_INTERRUPTED",
    _xpc_error_connection_invalid: "XPC_ERROR_CONNECTION_INVALID",
    _xpc_error_termination_imminent: "XPC_ERROR_TERMINATION_IMMINENT",
    _xpc_error_peer_code_signing_requirement: "XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT"
  };
  var LIBC = {};
  var xpcReady = false;
  function initNative() {
    for (const name of Object.keys(XPC_SIGNATURES)) {
      const [ret, args] = XPC_SIGNATURES[name];
      X[name] = nativeFn(name, LIBXPC, ret, args);
    }
    for (const name of XPC_TYPE_SYMBOLS) {
      const p = findExport("_xpc_type_" + name, LIBXPC);
      if (p !== null) XPC_TYPES.set(p.strip().toString(), name);
    }
    XPC_CONST.boolTrue = findExport("_xpc_bool_true", LIBXPC);
    XPC_CONST.errors = /* @__PURE__ */ new Map();
    for (const sym of Object.keys(ERROR_SYMBOLS)) {
      const p = findExport(sym, LIBXPC);
      if (p !== null) {
        XPC_CONST.errors.set(p.strip().toString(), ERROR_SYMBOLS[sym]);
        if (sym === "_xpc_error_connection_interrupted") XPC_CONST.interrupted = p;
        if (sym === "_xpc_error_connection_invalid") XPC_CONST.invalid = p;
      }
    }
    LIBC.free = nativeFn("free", "libsystem_malloc.dylib", "void", ["pointer"]);
    LIBC.proc_pidpath = nativeFn("proc_pidpath", "libsystem_kernel.dylib", "int", ["int", "pointer", "uint32"]);
    LIBC.Block_copy = nativeFn("_Block_copy", "libsystem_blocks.dylib", "pointer", ["pointer"]);
    LIBC.Block_release = nativeFn("_Block_release", "libsystem_blocks.dylib", "void", ["pointer"]);
    LIBC.globalBlockClass = findExport("_NSConcreteGlobalBlock", "libsystem_blocks.dylib");
    xpcReady = X.xpc_get_type !== null && X.xpc_dictionary_apply !== null && LIBC.Block_copy !== null && LIBC.globalBlockClass !== null && POINTER_SIZE === 8;
  }
  function xpcType(obj) {
    if (obj === null || obj.isNull()) return "null";
    try {
      return XPC_TYPES.get(X.xpc_get_type(obj).strip().toString()) || "unknown";
    } catch (_) {
      return "unknown";
    }
  }
  function errorName(obj) {
    return XPC_CONST.errors.get(obj.strip().toString()) || null;
  }
  var BLOCK_IS_GLOBAL2 = 1 << 28;
  var BLOCK_HAS_SIGNATURE2 = 1 << 30;
  var BLOCK_SIZE = 48;
  var descriptorCache = /* @__PURE__ */ new Map();
  var invokeCache = /* @__PURE__ */ new Map();
  function blockDescriptor(signature2) {
    let d = descriptorCache.get(signature2);
    if (d === void 0) {
      const types2 = Memory.allocUtf8String(signature2);
      d = Memory.alloc(3 * POINTER_SIZE);
      d.writeULong(0);
      d.add(POINTER_SIZE).writeULong(BLOCK_SIZE);
      d.add(2 * POINTER_SIZE).writePointer(types2);
      keepAlive.push(types2, d);
      descriptorCache.set(signature2, d);
    }
    return d;
  }
  var BLOCK_SLAB_COUNT = 256;
  var blockSlabs = [];
  var blockSlab = null;
  var blockSlabUsed = BLOCK_SLAB_COUNT;
  function allocBlock() {
    if (blockSlabUsed === BLOCK_SLAB_COUNT) {
      blockSlab = Memory.alloc(BLOCK_SIZE * BLOCK_SLAB_COUNT);
      blockSlabs.push(blockSlab);
      blockSlabUsed = 0;
    }
    const blk = blockSlab.add(BLOCK_SIZE * blockSlabUsed);
    blockSlabUsed += 1;
    return blk;
  }
  function makeGlobalBlock(invoke, signature2, original, contextId) {
    const blk = allocBlock();
    blk.writePointer(LIBC.globalBlockClass);
    blk.add(8).writeU32(BLOCK_IS_GLOBAL2 | BLOCK_HAS_SIGNATURE2);
    blk.add(12).writeU32(0);
    const slot = blk.add(16);
    slot.writePointer(invoke.strip().sign("ia", slot));
    blk.add(24).writePointer(blockDescriptor(signature2));
    blk.add(32).writePointer(original || NULL);
    blk.add(40).writeU64(contextId || 0);
    return blk;
  }
  function callBlock(block2, ret, argTypes2, args) {
    const raw = block2.add(16).readPointer().strip();
    const key = raw.toString() + "|" + ret + "|" + argTypes2.join(",");
    let fn = invokeCache.get(key);
    if (fn === void 0) {
      fn = new NativeFunction(raw.sign(), ret, ["pointer"].concat(argTypes2));
      if (invokeCache.size > 2048) invokeCache.clear();
      invokeCache.set(key, fn);
    }
    return fn.apply(null, [block2].concat(args));
  }
  function blockInvokeModule(block2) {
    try {
      return moduleNameFor(block2.add(16).readPointer().strip());
    } catch (_) {
      return null;
    }
  }
  var applyStacks = /* @__PURE__ */ new Map();
  var applyBlock = null;
  function initApplyBlock() {
    const invoke = new NativeCallback(function(_block, key, value) {
      const stack = applyStacks.get(Process.getCurrentThreadId());
      const top = stack !== void 0 ? stack[stack.length - 1] : void 0;
      if (top === void 0 || top.items.length >= top.limit) return 0;
      top.items.push([readCString(key) || "", value]);
      return 1;
    }, "bool", ["pointer", "pointer", "pointer"]);
    keepAlive.push(invoke);
    applyBlock = makeGlobalBlock(invoke, "B24@?0r*8@16", NULL, 0);
    keepAlive.push(applyBlock);
  }
  function dictionaryEntries(dict, limit) {
    const tid = Process.getCurrentThreadId();
    let stack = applyStacks.get(tid);
    if (stack === void 0) {
      stack = [];
      applyStacks.set(tid, stack);
    }
    const collector = { items: [], limit };
    stack.push(collector);
    try {
      X.xpc_dictionary_apply(dict, applyBlock);
    } catch (e) {
      log("[!]", "xpc_dictionary_apply failed: " + e);
    } finally {
      stack.pop();
      if (stack.length === 0) applyStacks.delete(tid);
    }
    return collector.items;
  }
  function decodeXpc(obj, budget, depth) {
    if (budget.nodes <= 0 || depth > MAX_TREE_DEPTH) return { t: "truncated" };
    budget.nodes -= 1;
    const type = xpcType(obj);
    try {
      switch (type) {
        case "dictionary": {
          const entries = dictionaryEntries(obj, 512);
          return { t: "dictionary", v: entries.map(([k, v]) => [k, decodeXpc(v, budget, depth + 1)]) };
        }
        case "array": {
          const count = Math.min(Number(X.xpc_array_get_count(obj)), 256);
          const items = [];
          for (let i = 0; i < count; i++) items.push(decodeXpc(X.xpc_array_get_value(obj, i), budget, depth + 1));
          return { t: "array", v: items };
        }
        case "string":
          return { t: "string", v: readCString(X.xpc_string_get_string_ptr(obj), MAX_STRING) };
        case "int64":
          return { t: "int64", v: X.xpc_int64_get_value(obj).toString() };
        case "uint64":
          return { t: "uint64", v: X.xpc_uint64_get_value(obj).toString() };
        case "bool":
          return { t: "bool", v: X.xpc_bool_get_value(obj) ? "true" : "false" };
        case "double":
          return { t: "double", v: String(X.xpc_double_get_value(obj)) };
        case "date":
          return { t: "date", v: new Date(X.xpc_date_get_value(obj).toNumber() / 1e6).toISOString() };
        case "uuid":
          return { t: "uuid", v: formatUuid(readBytes(X.xpc_uuid_get_bytes(obj), 16)) };
        case "data":
          return decodeData(obj);
        case "error":
          return { t: "error", v: errorName(obj) || describeXpc(obj, 512) };
        case "connection":
          return { t: "connection", v: connectionLabel(obj) };
        case "null":
          return { t: "null", v: "null" };
        default:
          return { t: type, v: describeXpc(obj, 256) };
      }
    } catch (e) {
      return { t: type, v: "<decode failed: " + e + ">" };
    }
  }
  function decodeData(obj) {
    const length = Number(X.xpc_data_get_length(obj));
    const bytesPtr = X.xpc_data_get_bytes_ptr(obj);
    const scanned = readBytes(bytesPtr, Math.min(length, DATA_SCAN));
    const node = { t: "data", len: length, hex: toHex(scanned, DATA_PREVIEW), bplist: detectBplist(scanned) };
    if (node.bplist !== null) {
      node.strings = extractStrings(scanned, 4, 64);
      if (node.bplist === "bplist00" && length <= DATA_SCAN) node.b64 = toBase64(scanned);
    }
    return node;
  }
  function formatUuid(bytes) {
    const h = toHex(bytes);
    return [h.slice(0, 8), h.slice(8, 12), h.slice(12, 16), h.slice(16, 20), h.slice(20)].join("-").toUpperCase();
  }
  function describeXpc(obj, limit) {
    if (X.xpc_copy_description === null) return "";
    const p = X.xpc_copy_description(obj);
    if (p.isNull()) return "";
    try {
      return readCString(p, limit || MAX_DESCRIPTION) || "";
    } finally {
      if (LIBC.free) LIBC.free(p);
    }
  }
  var connections = /* @__PURE__ */ new Map();
  function rememberConnection(conn, meta) {
    if (conn === null || conn.isNull()) return;
    if (connections.size > 4096) connections.delete(connections.keys().next().value);
    connections.set(conn.toString(), meta);
  }
  function connectionMeta(conn) {
    const meta = connections.get(conn.toString()) || {};
    let name = meta.name || null;
    if (!name && X.xpc_connection_get_name) {
      try {
        name = readCString(X.xpc_connection_get_name(conn));
      } catch (_) {
      }
    }
    return {
      name,
      kind: meta.kind || (name ? "named" : "unknown"),
      listener: Boolean(meta.listener),
      privileged: Boolean(meta.privileged),
      listenerName: meta.listenerName || null
    };
  }
  function processPath(pid) {
    if (!LIBC.proc_pidpath || pid <= 0) return null;
    const buf = Memory.alloc(4096);
    try {
      return LIBC.proc_pidpath(pid, buf, 4096) > 0 ? buf.readUtf8String() : null;
    } catch (_) {
      return null;
    }
  }
  var pathCache = /* @__PURE__ */ new Map();
  function peerInfo(conn) {
    const info = { pid: null, euid: null, path: null };
    try {
      info.pid = X.xpc_connection_get_pid(conn);
    } catch (_) {
    }
    try {
      info.euid = X.xpc_connection_get_euid(conn);
    } catch (_) {
    }
    if (info.pid > 0) {
      if (!pathCache.has(info.pid)) {
        if (pathCache.size > 1024) pathCache.clear();
        pathCache.set(info.pid, processPath(info.pid));
      }
      info.path = pathCache.get(info.pid);
    }
    return info;
  }
  function connectionLabel(conn) {
    const meta = connectionMeta(conn);
    const peer = peerInfo(conn);
    const parts = [];
    if (meta.name) parts.push(meta.name);
    if (peer.pid) parts.push("pid " + peer.pid);
    if (peer.path) parts.push(peer.path);
    return parts.join(" ") || conn.toString();
  }
  function componentFor(meta, peer) {
    if (meta.name) return meta.name;
    if (meta.listenerName) return meta.listenerName;
    if (peer.path) return peer.path;
    if (peer.pid) return "pid " + peer.pid;
    return null;
  }
  var decisions = createDecisionCore({
    jsThreadId: JS_THREAD_ID,
    captureStack
  });
  function processEvent(ev, context) {
    return decisions.process(ev, context);
  }
  function resolveParent(dict, path) {
    const parts = splitPath(path);
    if (parts.length === 0) return null;
    let current = dict;
    for (let i = 0; i < parts.length - 1; i++) {
      const keyPtr = toCString(parts[i]);
      let child = X.xpc_dictionary_get_value(current, keyPtr);
      if (child.isNull()) {
        log("[!]", 'Path segment "' + parts[i] + '" not found in ' + path);
        return null;
      }
      if (xpcType(child) !== "dictionary") {
        log("[!]", 'Path segment "' + parts[i] + '" is not a dictionary in ' + path);
        return null;
      }
      current = child;
    }
    return [current, toCString(parts[parts.length - 1])];
  }
  function applyXpcMods(dict, mods) {
    if (!mods.length || dict === null || dict.isNull() || xpcType(dict) !== "dictionary") return;
    for (const mod of mods) {
      try {
        const target = resolveParent(dict, mod.key);
        if (target === null) continue;
        const [parent, key] = target;
        if (mod.type === "extra_rem") {
          X.xpc_dictionary_set_value(parent, key, NULL);
        } else if (mod.type === "extra_add") {
          const type = normalizeValueType(mod.extraType);
          const val = String(mod.val);
          if (type === "int64") X.xpc_dictionary_set_int64(parent, key, int64(val));
          else if (type === "uint64") X.xpc_dictionary_set_uint64(parent, key, uint64(val));
          else if (type === "bool") X.xpc_dictionary_set_bool(parent, key, val.toLowerCase() === "true" || val === "1" ? 1 : 0);
          else if (type === "double") X.xpc_dictionary_set_double(parent, key, parseFloat(val));
          else if (type === "data") {
            const bytes = parseHex(val);
            if (bytes === null) {
              log("[!]", "Invalid hex for data value of " + mod.key);
              continue;
            }
            const buf = Memory.alloc(Math.max(bytes.length, 1));
            buf.writeByteArray(Array.from(bytes));
            X.xpc_dictionary_set_data(parent, key, buf, bytes.length);
          } else {
            X.xpc_dictionary_set_string(parent, key, toCString(val));
          }
        }
      } catch (e) {
        log("[!]", "Error applying " + mod.type + " on " + mod.key + ": " + e);
      }
    }
    log("[+]", "Applied " + mods.length + " modification(s) to XPC message");
  }
  var XPC_MESSAGE_MODS = ["extra_add", "extra_rem"];
  var sendContext = /* @__PURE__ */ new Map();
  function describeMessage(msg) {
    const tree = decodeXpc(msg, { nodes: MAX_TREE_NODES }, 0);
    const nsxpc = nsxpcInfo(tree);
    const extras = flattenTree(tree, 256);
    return {
      tree,
      extras,
      blobs: collectBlobs(tree, 16),
      nsxpc,
      // Only needed when the flattened view is incomplete; building it for every
      // message is expensive.
      description: "\u2026" in extras ? describeXpc(msg, MAX_DESCRIPTION) : null
    };
  }
  function xpcAttackSurface(direction, meta, peer, extra) {
    const surface = { platform: "ios", direction, serviceKind: meta.kind };
    if (meta.listener) surface.listener = true;
    if (meta.privileged) surface.privileged = true;
    if (peer.pid) surface.peerPid = peer.pid;
    if (peer.path) surface.peerPath = peer.path;
    return Object.assign(surface, extra || {});
  }
  function xpcMessageEvent(opts) {
    const meta = connectionMeta(opts.conn);
    const peer = peerInfo(opts.conn);
    const msgType = xpcType(opts.msg);
    const ipc = {
      kind: "xpc",
      direction: opts.direction,
      connection: Object.assign({ address: opts.conn.toString() }, meta),
      peer,
      messageType: msgType,
      expectsReply: Boolean(opts.expectsReply)
    };
    if (opts.correlation) ipc.correlation = opts.correlation;
    let extras = {};
    let action = null;
    let interceptable = opts.interceptable !== false;
    let mods = XPC_MESSAGE_MODS;
    if (msgType === "dictionary") {
      const decoded = describeMessage(opts.msg);
      extras = decoded.extras;
      if (decoded.description) ipc.description = decoded.description;
      if (decoded.blobs.length) ipc.blobs = decoded.blobs;
      if (decoded.nsxpc) {
        ipc.nsxpc = decoded.nsxpc;
        const call = sendContext.get(Process.getCurrentThreadId());
        action = call && call.selector || decoded.nsxpc.selector;
        ipc.selectorSource = call && call.selector ? "nsxpc" : decoded.nsxpc.selector ? "heuristic" : null;
        if (call && call.eventId) {
          ipc.nsxpcCall = call.eventId;
          interceptable = false;
        }
        if (opts.direction !== "outgoing") interceptable = false;
      }
    } else if (msgType === "error") {
      action = errorName(opts.msg) || "XPC_ERROR";
      ipc.description = describeXpc(opts.msg, 1024);
      interceptable = false;
      mods = [];
    } else if (msgType === "connection") {
      const peerConn = peerInfo(opts.msg);
      action = "new peer connection";
      ipc.newPeer = peerConn;
      extras = {
        "peer/pid": { type: "int64", value: String(peerConn.pid) },
        "peer/euid": { type: "uint64", value: String(peerConn.euid) }
      };
      if (peerConn.path) extras["peer/path"] = { type: "string", value: peerConn.path };
      mods = [];
    } else {
      ipc.description = describeXpc(opts.msg, 1024);
      mods = [];
    }
    const surfaceExtra = {};
    if (msgType === "connection") {
      surfaceExtra.exposure = "listener";
      surfaceExtra.peerPid = ipc.newPeer.pid;
      if (ipc.newPeer.path) surfaceExtra.peerPath = ipc.newPeer.path;
    } else if (opts.direction === "incoming" && (meta.kind === "peer" || meta.listenerName)) {
      surfaceExtra.exposure = "service";
    }
    return {
      className: opts.className,
      methodName: opts.methodName,
      component: componentFor(meta, peer),
      action,
      extras,
      interceptable,
      mods: interceptable ? mods : [],
      attackSurface: xpcAttackSurface(opts.direction, meta, peer, surfaceExtra),
      ipc
    };
  }
  function handleXpcEvent(context, opts) {
    return withBusyThread(function() {
      try {
        const ev = xpcMessageEvent(opts);
        const result = processEvent(ev, context);
        if (result.mode === "forward" && result.mods.length) applyXpcMods(opts.msg, result.mods);
        return result;
      } catch (e) {
        log("[!]", opts.methodName + " handler failed: " + e);
        return { mode: "forward", mods: [] };
      }
    });
  }
  var wrapperContexts = /* @__PURE__ */ new Map();
  var wrapperCounter = 0;
  var wrapperInvoke = null;
  function wrapHandler(original, ctx) {
    const copy = LIBC.Block_copy(original);
    wrapperCounter += 1;
    const blk = makeGlobalBlock(wrapperInvoke, "v16@?0@8", copy, wrapperCounter);
    ctx.block = blk;
    ctx.original = copy;
    ctx.module = blockInvokeModule(copy);
    wrapperContexts.set(wrapperCounter, ctx);
    return blk;
  }
  function retireWrapper(id) {
    const ctx = wrapperContexts.get(id);
    if (ctx === void 0) return;
    wrapperContexts.delete(id);
    setTimeout(function() {
      try {
        LIBC.Block_release(ctx.original);
      } catch (_) {
      }
    }, 1e4);
  }
  function initWrapperInvoke() {
    wrapperInvoke = new NativeCallback(function(block2, obj) {
      const id = block2.add(40).readU64().toNumber();
      const original = block2.add(32).readPointer();
      const ctx = wrapperContexts.get(id);
      if (ctx === void 0) {
        return;
      }
      if (shouldPassthrough()) {
        callBlock(original, "void", ["pointer"], [obj]);
        return;
      }
      const state = { delivered: false };
      try {
        deliverWrapped(this.context, id, ctx, original, obj, state);
      } catch (e) {
        log("[!]", "XPC handler wrapper failed: " + e);
        if (!state.delivered) callBlock(original, "void", ["pointer"], [obj]);
      }
    }, "void", ["pointer", "pointer"]);
    keepAlive.push(wrapperInvoke);
  }
  function deliverWrapped(context, id, ctx, original, obj, state) {
    const isReply = ctx.kind === "reply";
    const result = handleXpcEvent(context, {
      conn: ctx.conn,
      msg: obj,
      direction: isReply ? "reply" : "incoming",
      methodName: isReply ? "xpc_reply_handler" : "xpc_event_handler",
      className: ctx.module || "libxpc",
      correlation: ctx.correlation
    });
    if (result.mode === "drop") {
      if (xpcType(obj) === "connection") {
        try {
          X.xpc_connection_cancel(obj);
        } catch (_) {
        }
      }
    } else {
      if (!isReply && xpcType(obj) === "connection") {
        const listener = connectionMeta(ctx.conn);
        rememberConnection(obj, { kind: "peer", listenerName: listener.name || listener.listenerName });
      }
      state.delivered = true;
      callBlock(original, "void", ["pointer"], [obj]);
    }
    if (isReply || errorName(obj) === "XPC_ERROR_CONNECTION_INVALID") retireWrapper(id);
  }
  function hookXpcCreation() {
    const specs = [
      ["xpc_connection_create", function(args) {
        const name = readCString(args[0]);
        return { name, kind: name ? "service" : "anonymous", listener: !name };
      }],
      ["xpc_connection_create_mach_service", function(args) {
        const flags = args[2].toUInt32();
        return { name: readCString(args[0]), kind: "mach", listener: (flags & 1) !== 0, privileged: (flags & 2) !== 0 };
      }],
      ["xpc_connection_create_from_endpoint", function() {
        return { kind: "endpoint" };
      }]
    ];
    for (const [name, describe] of specs) {
      const addr = findExport(name, LIBXPC);
      if (addr === null) continue;
      Interceptor.attach(addr, {
        onEnter(args) {
          this.meta = describe(args);
        },
        onLeave(retval) {
          rememberConnection(retval, this.meta);
        }
      });
    }
  }
  function hookXpc(entry) {
    const fn = entry.function;
    const addr = findExport(fn, LIBXPC);
    if (addr === null) {
      if (!entry.optional) throw new Error(fn + " not found");
      log("[~]", "Skipping " + fn + " (not available on this OS)");
      return false;
    }
    const intercept = entry.intercept !== false;
    const caller = function(ctx) {
      return moduleNameFor(ctx.returnAddress) || "unknown";
    };
    const nsxpcDropped = function() {
      const call = sendContext.get(Process.getCurrentThreadId());
      return call !== void 0 && call.drop === true;
    };
    if (fn === "xpc_connection_send_message" || fn === "xpc_connection_send_notification") {
      const orig = new NativeFunction(addr, "void", ["pointer", "pointer"]);
      const cb = new NativeCallback(function(conn, msg) {
        if (nsxpcDropped()) return;
        if (shouldPassthrough()) return orig(conn, msg);
        const r = handleXpcEvent(this.context, {
          conn,
          msg,
          direction: "outgoing",
          methodName: fn,
          className: caller(this),
          interceptable: intercept
        });
        if (r.mode !== "drop") orig(conn, msg);
      }, "void", ["pointer", "pointer"]);
      Interceptor.replace(addr, cb);
      keepAlive.push(cb);
    } else if (fn === "xpc_connection_send_message_with_reply") {
      const orig = new NativeFunction(addr, "void", ["pointer", "pointer", "pointer", "pointer"]);
      const cb = new NativeCallback(function(conn, msg, queue, handler) {
        if (nsxpcDropped()) return;
        if (shouldPassthrough()) return orig(conn, msg, queue, handler);
        const r = handleXpcEvent(this.context, {
          conn,
          msg,
          direction: "outgoing",
          methodName: fn,
          className: caller(this),
          interceptable: intercept,
          expectsReply: true
        });
        if (r.mode === "drop") return;
        let replyHandler = handler;
        if (!handler.isNull() && xpcReady) {
          replyHandler = wrapHandler(handler, { kind: "reply", conn, correlation: r.eventId });
        }
        orig(conn, msg, queue, replyHandler);
      }, "void", ["pointer", "pointer", "pointer", "pointer"]);
      Interceptor.replace(addr, cb);
      keepAlive.push(cb);
    } else if (fn === "xpc_connection_send_message_with_reply_sync") {
      const orig = new NativeFunction(addr, "pointer", ["pointer", "pointer"]);
      const cb = new NativeCallback(function(conn, msg) {
        if (nsxpcDropped()) return XPC_CONST.interrupted || NULL;
        if (shouldPassthrough()) return orig(conn, msg);
        const module = caller(this);
        const r = handleXpcEvent(this.context, {
          conn,
          msg,
          direction: "outgoing",
          methodName: fn,
          className: module,
          interceptable: intercept,
          expectsReply: true
        });
        if (r.mode === "drop") return XPC_CONST.interrupted || NULL;
        const reply = orig(conn, msg);
        const rr = handleXpcEvent(this.context, {
          conn,
          msg: reply,
          direction: "reply",
          methodName: fn + " (reply)",
          className: module,
          interceptable: intercept,
          correlation: r.eventId
        });
        if (rr.mode === "drop") {
          X.xpc_release(reply);
          return XPC_CONST.interrupted || NULL;
        }
        return reply;
      }, "pointer", ["pointer", "pointer"]);
      Interceptor.replace(addr, cb);
      keepAlive.push(cb);
    } else if (fn === "xpc_connection_set_event_handler") {
      if (!xpcReady) throw new Error("block support unavailable (64-bit libxpc/libsystem_blocks required)");
      Interceptor.attach(addr, {
        onEnter(args) {
          if (args[1].isNull() || shouldPassthrough()) return;
          args[1] = wrapHandler(args[1], { kind: "event", conn: args[0] });
        }
      });
    } else {
      throw new Error("unsupported xpc hook " + fn);
    }
    return true;
  }
  var hookedMethods = /* @__PURE__ */ new Map();
  var activeSelectors = /* @__PURE__ */ new Set();
  function objcAvailable() {
    try {
      return ObjC.available;
    } catch (_) {
      return false;
    }
  }
  function wrapObject(p) {
    if (p === null || p.isNull()) return null;
    try {
      return new ObjC.Object(p);
    } catch (_) {
      return null;
    }
  }
  function objcString(obj) {
    if (obj === null) return null;
    try {
      return obj.toString();
    } catch (_) {
      return null;
    }
  }
  function truncate(text, limit) {
    if (text === null || text === void 0) return text;
    const s = String(text);
    return s.length > limit ? s.slice(0, limit) + "\u2026" : s;
  }
  function describeObjCArg(encoding, value) {
    const kind = objcTypeKind(encoding);
    if (kind === "object") {
      const obj = wrapObject(value);
      if (obj === null) return { type: objcClassHint(encoding) || "id", value: "nil" };
      let className = "id";
      try {
        className = obj.$className;
      } catch (_) {
      }
      if (className.indexOf("Block") !== -1) return { type: className, value: "<block>" };
      try {
        if (obj.isProxy()) return { type: className, value: "<proxy>" };
      } catch (_) {
        return { type: className, value: "<object>" };
      }
      try {
        if (obj.isKindOfClass_(ObjC.classes.NSData)) {
          const length = obj.length();
          const bytes = readBytes(obj.bytes(), Math.min(length, DATA_PREVIEW));
          return { type: className, value: length + " bytes " + toHex(bytes) };
        }
      } catch (_) {
      }
      return { type: className, value: truncate(objcString(obj), 2048) };
    }
    if (kind === "block") return { type: "block", value: value.isNull() ? "nil" : "<block>" };
    if (kind === "selector") return { type: "SEL", value: value.isNull() ? "nil" : ObjC.selectorAsString(value) };
    if (kind === "cstring") return { type: "char *", value: readCString(value, MAX_STRING) };
    if (kind === "bool") return { type: "bool", value: value ? "true" : "false" };
    if (kind === "integer") return { type: "int64", value: String(value) };
    if (kind === "float") return { type: "double", value: String(value) };
    if (kind === "class") return { type: "Class", value: value.isNull() ? "nil" : String(new ObjC.Object(value)) };
    return { type: encoding, value: value === null || value === void 0 ? "" : String(value) };
  }
  function methodEncodings(method2) {
    try {
      return parseObjCTypes(ObjC.api.method_getTypeEncoding(method2.handle).readCString());
    } catch (_) {
      return [];
    }
  }
  function defaultReturn(returnType) {
    if (returnType === "void") return void 0;
    if (returnType === "pointer") return NULL;
    if (Array.isArray(returnType)) return void 0;
    return 0;
  }
  function argumentExtras(encodings, args) {
    const extras = {};
    for (let i = 2; i < args.length; i++) {
      extras["arg" + (i - 2)] = describeObjCArg(encodings[i + 1], args[i]);
    }
    return extras;
  }
  function coerceArg(encoding, mod, current) {
    const kind = objcTypeKind(encoding);
    const type = normalizeValueType(mod.extraType) || "string";
    const val = String(mod.val);
    if (kind === "object") return makeObjCValue(type, val, current instanceof NativePointer ? wrapObject(current) : current);
    if (kind === "bool") return val.toLowerCase() === "true" || val === "1" ? 1 : 0;
    if (kind === "integer") return parseInt(val, val.indexOf("0x") === 0 ? 16 : 10);
    if (kind === "float") return parseFloat(val);
    throw new Error("cannot modify arguments of type " + encoding);
  }
  function argModIndex(mod) {
    const m2 = /^arg(\d+)$/.exec(mod.key || "");
    if (mod.type !== "extra_add" || m2 === null) {
      log("[!]", "Unsupported modification for Objective-C call: " + mod.type + " " + (mod.key || ""));
      return -1;
    }
    return parseInt(m2[1], 10);
  }
  function applyObjCArgMods(encodings, args, mods) {
    for (const mod of mods) {
      const n = argModIndex(mod);
      if (n < 0) continue;
      const index = n + 2;
      if (index >= args.length) {
        log("[!]", "No argument " + mod.key);
        continue;
      }
      try {
        args[index] = coerceArg(encodings[index + 1], mod, args[index]);
      } catch (e) {
        log("[!]", "Error modifying " + mod.key + ": " + e);
      }
    }
  }
  function makeObjCValue(type, val, previous) {
    const C = ObjC.classes;
    let value;
    if (type === "int64" || type === "uint64") value = C.NSNumber.numberWithLongLong_(parseInt(val, 10));
    else if (type === "double") value = C.NSNumber.numberWithDouble_(parseFloat(val));
    else if (type === "bool") value = C.NSNumber.numberWithBool_(val.toLowerCase() === "true" || val === "1");
    else if (type === "data") {
      const bytes = parseHex(val);
      if (bytes === null) throw new Error("invalid hex");
      const buf = Memory.alloc(Math.max(bytes.length, 1));
      buf.writeByteArray(Array.from(bytes));
      value = C.NSData.dataWithBytes_length_(buf, bytes.length);
    } else if (previous !== null && previous.isKindOfClass_(C.NSURL)) {
      value = C.NSURL.URLWithString_(val);
    } else {
      value = C.NSString.stringWithString_(val);
    }
    keepTemp(value);
    return value.handle;
  }
  function hookObjCMethod(klass, methodName, handler) {
    const method2 = klass[methodName];
    if (method2 === void 0) return false;
    const key = method2.handle.toString();
    if (hookedMethods.has(key)) return false;
    const original = method2.implementation;
    const info = {
      className: klass.$className,
      selector: methodName.slice(2),
      returnType: method2.returnType,
      encodings: methodEncodings(method2)
    };
    const replacement = ObjC.implement(method2, function() {
      const args = Array.prototype.slice.call(arguments);
      if (shouldPassthrough()) return original.apply(null, args);
      let called = false;
      const tracked = function() {
        called = true;
        return original.apply(null, arguments);
      };
      try {
        return handler.call(this, tracked, args, info);
      } catch (e) {
        log("[!]", info.className + " " + info.selector + " hook failed: " + e);
        return called ? defaultReturn(info.returnType) : original.apply(null, args);
      }
    });
    method2.implementation = replacement;
    hookedMethods.set(key, { replacement, original });
    return true;
  }
  var attachedMethods = /* @__PURE__ */ new Set();
  function attachObjCMethod(klass, methodName, callbacks) {
    const method2 = klass[methodName];
    if (method2 === void 0) return false;
    const key = method2.handle.toString() + " " + methodName;
    if (attachedMethods.has(key)) return false;
    attachedMethods.add(key);
    const info = { className: klass.$className, selector: methodName.slice(2), encodings: methodEncodings(method2) };
    const guarded = {};
    if (callbacks.onEnter) {
      guarded.onEnter = function(args) {
        this.ioxenSkip = shouldPassthrough();
        if (this.ioxenSkip) return;
        try {
          callbacks.onEnter.call(this, args, info);
        } catch (e) {
          log("[!]", info.className + " " + info.selector + " hook failed: " + e);
        }
      };
    }
    if (callbacks.onLeave) {
      guarded.onLeave = function(retval) {
        if (this.ioxenSkip) return;
        try {
          callbacks.onLeave.call(this, retval, info);
        } catch (e) {
          log("[!]", info.className + " " + info.selector + " hook failed: " + e);
        }
      };
    }
    Interceptor.attach(method2.implementation, guarded);
    return true;
  }
  function callOriginal(original, args, selector2) {
    const key = Process.getCurrentThreadId() + " " + selector2;
    const nested = activeSelectors.has(key);
    activeSelectors.add(key);
    try {
      return original.apply(null, args);
    } finally {
      if (!nested) activeSelectors.delete(key);
    }
  }
  function isNestedSelector(selector2) {
    return activeSelectors.has(Process.getCurrentThreadId() + " " + selector2);
  }
  function runtimeClassName(selfPtr, fallback) {
    const obj = wrapObject(selfPtr);
    try {
      return obj !== null ? obj.$className : fallback;
    } catch (_) {
      return fallback;
    }
  }
  function objcCallEvent(context, original, args, info, extra) {
    const ev = Object.assign({
      className: runtimeClassName(args[0], info.className),
      methodName: (info.isClassMethod ? "+" : "-") + "[" + info.className + " " + info.selector + "]",
      action: info.selector,
      extras: argumentExtras(info.encodings, args),
      interceptable: !isNestedSelector(info.selector),
      mods: ["extra_add"],
      attackSurface: { platform: "ios", direction: "incoming" },
      ipc: { kind: "objc", direction: "incoming", selector: info.selector, receiverClass: info.className }
    }, extra || {});
    const r = withBusyThread(function() {
      return processEvent(ev, context);
    });
    if (r.mode === "drop") {
      if (Array.isArray(info.returnType)) {
        log("[~]", "Cannot drop " + info.selector + " (struct return); forwarding");
      } else {
        return { dropped: true, value: defaultReturn(info.returnType) };
      }
    }
    if (r.mods.length) withBusyThread(function() {
      applyObjCArgMods(info.encodings, args, r.mods);
    });
    return { dropped: false, value: callOriginal(original, args, info.selector) };
  }
  var objcResolver = null;
  function resolveObjCPattern(pattern) {
    const out = [];
    try {
      if (objcResolver === null) objcResolver = new ApiResolver("objc");
      const resolver = objcResolver;
      for (const match of resolver.enumerateMatches(pattern)) {
        const m2 = /^([+-])\[(\S+) (.+)\]$/.exec(match.name);
        if (m2 !== null) out.push({ isClassMethod: m2[1] === "+", className: m2[2], selector: m2[3] });
      }
    } catch (e) {
      log("[!]", "ObjC resolver failed for " + pattern + ": " + e);
    }
    return out;
  }
  function hookObjCTarget(target, handler) {
    const klass = ObjC.classes[target.className];
    if (klass === void 0) return false;
    const name = (target.isClassMethod ? "+ " : "- ") + target.selector;
    return hookObjCMethod(klass, name, function(original, args, info) {
      info.isClassMethod = target.isClassMethod;
      return handler.call(this, original, args, info);
    });
  }
  var nsxpcConnections = /* @__PURE__ */ new Map();
  var nsxpcListeners = /* @__PURE__ */ new Map();
  var reportedInterfaces = /* @__PURE__ */ new Set();
  function nsxpcConnectionName(conn) {
    if (conn === null) return null;
    const known = nsxpcConnections.get(conn.handle.toString());
    if (known && known.name) return known.name;
    try {
      const name = conn.serviceName();
      if (name !== null) return name.toString();
    } catch (_) {
    }
    return null;
  }
  function protocolSummaryObject(iface) {
    if (iface === null) return null;
    const protoPtr = iface.protocol();
    return new ObjC.Protocol(protoPtr.handle ? protoPtr.handle : protoPtr);
  }
  function protocolSummary(iface) {
    if (iface === null) return null;
    try {
      const protoPtr = iface.protocol();
      const proto = new ObjC.Protocol(protoPtr.handle ? protoPtr.handle : protoPtr);
      return {
        name: proto.name,
        methods: Object.keys(proto.methods).filter((n) => n.indexOf("- ") === 0).map((n) => n.slice(2)).sort()
      };
    } catch (e) {
      return { name: objcString(iface), methods: [] };
    }
  }
  function connectionPeer(conn) {
    const peer = { pid: null, euid: null, path: null };
    try {
      peer.pid = conn.processIdentifier();
    } catch (_) {
    }
    try {
      peer.euid = conn.effectiveUserIdentifier();
    } catch (_) {
    }
    if (peer.pid > 0) peer.path = processPath(peer.pid);
    return peer;
  }
  function hookNSXPCConnections() {
    const C = ObjC.classes.NSXPCConnection;
    if (C === void 0) return false;
    const initHook = function(kind) {
      return {
        onEnter(args, info) {
          this.name = info.selector === "initWithListenerEndpoint:" ? null : objcString(wrapObject(args[2]));
          this.options = info.selector === "initWithMachServiceName:options:" ? args[3].toUInt32() : 0;
          this.selector = info.selector;
        },
        onLeave(retval) {
          if (retval.isNull()) return;
          const name = this.name;
          const options = this.options;
          nsxpcConnections.set(retval.toString(), { name, kind, options });
          withBusyThread(function() {
            processEvent({
              className: "NSXPCConnection",
              methodName: "-[NSXPCConnection " + this.selector + "]",
              component: name,
              action: "connect",
              extras: options ? { options: { type: "uint64", value: "0x" + options.toString(16) } } : {},
              interceptable: false,
              attackSurface: { platform: "ios", direction: "outgoing", serviceKind: kind, privileged: (options & 4096) !== 0 },
              ipc: { kind: "nsxpc_connection", direction: "outgoing", service: name, serviceKind: kind, options }
            }, this.context);
          }.bind(this));
        }
      };
    };
    attachObjCMethod(C, "- initWithMachServiceName:options:", initHook("mach"));
    attachObjCMethod(C, "- initWithServiceName:", initHook("service"));
    attachObjCMethod(C, "- initWithListenerEndpoint:", initHook("endpoint"));
    const resumeHook = {
      onEnter(args) {
        const context = this.context;
        withBusyThread(function() {
          reportInterfaces(context, wrapObject(args[0]));
        });
      }
    };
    attachObjCMethod(C, "- resume", resumeHook);
    attachObjCMethod(C, "- activate", resumeHook);
    hookNSXPCSends(C);
    return true;
  }
  function readArgBuffer(buf, encoding) {
    const layout = scalarLayout(encoding);
    if (layout === null) return buf.readPointer();
    return buf["read" + layout[1]]();
  }
  function writeArgBuffer(buf, encoding, value) {
    const layout = scalarLayout(encoding);
    if (layout === null) buf.writePointer(value);
    else if (layout[1] === "Float" || layout[1] === "Double") buf["write" + layout[1]](value);
    else if (layout[1] === "S64") buf.writeS64(int64(String(value)));
    else if (layout[1] === "U64") buf.writeU64(uint64(String(value)));
    else buf["write" + layout[1]](value);
  }
  function protocolArgTypes(conn, selector2) {
    try {
      const proto = protocolSummaryObject(conn.remoteObjectInterface());
      const desc = proto !== null ? proto.methods["- " + selector2] : void 0;
      if (desc !== void 0) return parseObjCTypes(desc.types).slice(3);
    } catch (_) {
    }
    return null;
  }
  function decodeNSXPCSend(layout, args, conn) {
    if (layout.kind === "invocation") {
      const inv = wrapObject(args[layout.invocation]);
      if (inv === null || !inv.isKindOfClass_(ObjC.classes.NSInvocation)) {
        if (layout.selector < 0 || args[layout.selector].isNull()) return null;
        return { selector: ObjC.selectorAsString(args[layout.selector]), args: [] };
      }
      const sig = inv.methodSignature();
      const count = Math.max(0, Number(sig.numberOfArguments()) - 2);
      const decoded = [];
      for (let i = 0; i < count; i++) {
        const encoding = String(sig.getArgumentTypeAtIndex_(i + 2));
        const size = scalarLayout(encoding) !== null || objcTypeKind(encoding) !== "struct" ? 16 : 0;
        if (size === 0) {
          decoded.push({ encoding, get() {
            return NULL;
          }, set() {
            throw new Error("struct arguments are not supported");
          }, opaque: true });
          continue;
        }
        const buf = Memory.alloc(size);
        decoded.push({
          encoding,
          get() {
            inv.getArgument_atIndex_(buf, i + 2);
            return readArgBuffer(buf, encoding);
          },
          set(value) {
            writeArgBuffer(buf, encoding, value);
            inv.setArgument_atIndex_(buf, i + 2);
          }
        });
      }
      return { selector: ObjC.selectorAsString(inv.selector()), args: decoded };
    }
    const selector2 = ObjC.selectorAsString(args[layout.selector]);
    const types2 = protocolArgTypes(conn, selector2) || [];
    return {
      selector: selector2,
      args: layout.values.map(function(index, i) {
        return {
          encoding: types2[i] || "@",
          get() {
            return args[index];
          },
          set(value) {
            args[index] = value;
          }
        };
      })
    };
  }
  var decodeReplies = false;
  function hookNSXPCSends(C) {
    const names = C.$ownMethods.filter((n) => /^- _send(Invocation|Selector):/.test(n));
    let count = 0;
    for (const name of names) {
      const layout = nsxpcSendLayout(name.slice(2));
      if (layout === null) continue;
      const method2 = C[name];
      if (method2 === void 0) continue;
      if (!validateSendLayout(layout, methodEncodings(method2))) {
        log("[~]", "Not decoding " + name + ": unexpected type encoding");
        continue;
      }
      try {
        if (attachObjCMethod(C, name, {
          onEnter(args) {
            this.tid = Process.getCurrentThreadId();
            if (sendContext.has(this.tid)) return;
            this.tracked = true;
            sendContext.set(this.tid, beginNSXPCSend(this.context, args, layout));
          },
          onLeave() {
            if (this.tracked) sendContext.delete(this.tid);
          }
        })) count += 1;
      } catch (e) {
        log("[~]", "NSXPC decoding unavailable for " + name + ": " + e);
      }
    }
    if (count === 0) log("[~]", "No NSXPC send methods recognised; outgoing NSXPC calls are not decoded");
  }
  function beginNSXPCSend(context, args, layout) {
    const conn = wrapObject(args[0]);
    const prepared = withBusyThread(function() {
      let call = null;
      try {
        call = decodeNSXPCSend(layout, args, conn);
      } catch (e) {
        log("[~]", "NSXPC call could not be decoded: " + e);
      }
      if (call === null) return null;
      const service = nsxpcConnectionName(conn);
      const peer = conn !== null ? connectionPeer(conn) : { pid: null, path: null };
      let protocol = null;
      try {
        protocol = protocolSummary(conn.remoteObjectInterface());
      } catch (_) {
      }
      const extras = {};
      call.args.forEach(function(arg, i) {
        if (arg.opaque) {
          extras["arg" + i] = { type: arg.encoding, value: "<struct>" };
          return;
        }
        try {
          extras["arg" + i] = describeObjCArg(arg.encoding, arg.get());
        } catch (e) {
          extras["arg" + i] = { type: arg.encoding, value: "<unreadable: " + e + ">" };
        }
      });
      return {
        call,
        service,
        ev: {
          className: "NSXPCConnection",
          methodName: "-[" + (protocol ? protocol.name : "NSXPCRemoteObjectProxy") + " " + call.selector + "]",
          component: service || (peer.path || (peer.pid ? "pid " + peer.pid : null)),
          action: call.selector,
          extras,
          interceptable: true,
          mods: call.args.length ? ["extra_add"] : [],
          attackSurface: { platform: "ios", direction: "outgoing", peerPid: peer.pid, peerPath: peer.path },
          ipc: { kind: "nsxpc_call", direction: "outgoing", protocol: protocol ? protocol.name : null, selector: call.selector, service, peer }
        }
      };
    });
    if (prepared === null) return { selector: null, eventId: null, drop: false };
    const r = withBusyThread(function() {
      return processEvent(prepared.ev, context);
    });
    if (r.mode === "drop") {
      return { selector: prepared.call.selector, eventId: r.eventId, drop: true };
    }
    withBusyThread(function() {
      for (const mod of r.mods) {
        const n = argModIndex(mod);
        if (n < 0) continue;
        const arg = prepared.call.args[n];
        if (arg === void 0 || arg.opaque) {
          log("[!]", "Cannot modify " + mod.key);
          continue;
        }
        try {
          arg.set(coerceArg(arg.encoding, mod, arg.get()));
        } catch (e) {
          log("[!]", "Error modifying " + mod.key + ": " + e);
        }
      }
      if (!decodeReplies) return;
      prepared.call.args.forEach(function(arg) {
        if (arg.opaque || objcTypeKind(arg.encoding) !== "block") return;
        const blk = arg.get();
        if (blk.isNull()) return;
        const wrapped = wrapReplyBlock(blk, {
          selector: prepared.call.selector,
          service: prepared.service,
          protocol: prepared.ev.ipc.protocol,
          correlation: r.eventId
        });
        if (wrapped !== null) arg.set(wrapped);
      });
    });
    return { selector: prepared.call.selector, eventId: r.eventId, drop: false };
  }
  var replyBlocks = /* @__PURE__ */ new Map();
  var replyCounter = 0;
  function describeBlockArg(encoding, value) {
    if (value instanceof ObjC.Object) return describeObjCArg("@", value.handle);
    if (value === null || value === void 0) return { type: objcClassHint(encoding) || "id", value: "nil" };
    if (typeof value === "boolean") return { type: "bool", value: value ? "true" : "false" };
    return describeObjCArg(encoding, value);
  }
  function wrapReplyBlock(blockPtr, meta) {
    const copy = LIBC.Block_copy(blockPtr);
    let original;
    let originalImpl;
    try {
      original = new ObjC.Block(copy);
      originalImpl = original.implementation;
    } catch (e) {
      LIBC.Block_release(copy);
      log("[~]", "Reply of " + meta.selector + " not decoded (block has no signature)");
      return null;
    }
    const encodings = parseObjCTypes(original.types).slice(2);
    replyCounter += 1;
    const id = replyCounter;
    const wrapper = new ObjC.Block({
      types: original.types,
      implementation: function() {
        const values = Array.prototype.slice.call(arguments);
        if (shouldPassthrough()) return originalImpl.apply(null, values);
        let delivered = false;
        try {
          const extras = {};
          values.forEach(function(v, i) {
            extras["arg" + i] = describeBlockArg(encodings[i], v);
          });
          const r = withBusyThread(function() {
            return processEvent({
              className: "NSXPCConnection",
              methodName: "reply " + meta.selector,
              component: meta.service,
              action: meta.selector,
              extras,
              interceptable: true,
              mods: ["extra_add"],
              attackSurface: { platform: "ios", direction: "reply" },
              ipc: { kind: "nsxpc_reply", direction: "reply", protocol: meta.protocol, selector: meta.selector, service: meta.service, correlation: meta.correlation }
            }, void 0);
          });
          if (r.mode === "drop") return void 0;
          withBusyThread(function() {
            for (const mod of r.mods) {
              const n = argModIndex(mod);
              if (n < 0 || n >= values.length) continue;
              try {
                const current = values[n] instanceof ObjC.Object ? values[n].handle : values[n];
                values[n] = coerceArg(encodings[n], mod, current);
              } catch (e) {
                log("[!]", "Error modifying reply " + mod.key + ": " + e);
              }
            }
          });
          delivered = true;
          return originalImpl.apply(null, values);
        } catch (e) {
          log("[!]", "NSXPC reply hook failed: " + e);
          if (!delivered) return originalImpl.apply(null, values);
          return void 0;
        } finally {
          const entry = replyBlocks.get(id);
          if (entry !== void 0 && !entry.released) {
            entry.released = true;
            setTimeout(function() {
              LIBC.Block_release(entry.copy);
            }, 1e4);
          }
        }
      }
    });
    replyBlocks.set(id, { wrapper, original, copy });
    return wrapper.handle;
  }
  function reportInterfaces(context, conn) {
    if (conn === null) return;
    const key = conn.handle.toString();
    if (reportedInterfaces.has(key)) return;
    let exported = null;
    let remote = null;
    let exportedObject = null;
    try {
      exported = protocolSummary(conn.exportedInterface());
    } catch (_) {
    }
    try {
      remote = protocolSummary(conn.remoteObjectInterface());
    } catch (_) {
    }
    try {
      exportedObject = conn.exportedObject();
    } catch (_) {
    }
    if (exported === null && remote === null) return;
    reportedInterfaces.add(key);
    const name = nsxpcConnectionName(conn);
    const peer = connectionPeer(conn);
    const extras = {};
    if (exported) {
      extras["exported/protocol"] = { type: "protocol", value: exported.name };
      exported.methods.forEach((m2, i) => {
        extras["exported/methods[" + i + "]"] = { type: "selector", value: m2 };
      });
    }
    if (remote) {
      extras["remote/protocol"] = { type: "protocol", value: remote.name };
      remote.methods.forEach((m2, i) => {
        extras["remote/methods[" + i + "]"] = { type: "selector", value: m2 };
      });
    }
    if (exportedObject !== null) extras["exported/object"] = { type: "class", value: exportedObject.$className };
    processEvent({
      className: exportedObject !== null ? exportedObject.$className : "NSXPCConnection",
      methodName: "-[NSXPCConnection resume]",
      component: name || (peer.path || (peer.pid ? "pid " + peer.pid : null)),
      action: "interface",
      extras,
      interceptable: false,
      attackSurface: { platform: "ios", direction: exported ? "incoming" : "outgoing", exposure: exported ? "exported_interface" : void 0 },
      ipc: { kind: "nsxpc_interface", direction: exported ? "incoming" : "outgoing", service: name, peer, exported, remote }
    }, context);
    if (exported !== null && exportedObject !== null) hookExportedObject(exportedObject, exported, name);
  }
  function hookExportedObject(obj, iface, serviceName) {
    for (const selector2 of iface.methods) {
      const klass = obj.$class;
      hookObjCMethod(klass, "- " + selector2, function(original, args, info) {
        const conn = currentNSXPCConnection();
        const peer = conn !== null ? connectionPeer(conn) : { pid: null, path: null };
        const service = (conn !== null ? nsxpcConnectionName(conn) : null) || serviceName;
        return objcCallEvent(this.context, original, args, info, {
          methodName: "-[" + info.className + " " + info.selector + "]",
          component: service || iface.name,
          attackSurface: { platform: "ios", direction: "incoming", exposure: "exported_method", peerPid: peer.pid, peerPath: peer.path },
          ipc: { kind: "nsxpc_call", direction: "incoming", protocol: iface.name, selector: info.selector, service, peer }
        }).value;
      });
    }
  }
  function currentNSXPCConnection() {
    try {
      return ObjC.classes.NSXPCConnection.currentConnection();
    } catch (_) {
      return null;
    }
  }
  function hookNSXPCListeners() {
    const L = ObjC.classes.NSXPCListener;
    if (L === void 0) return false;
    attachObjCMethod(L, "- initWithMachServiceName:", {
      onEnter(args) {
        this.name = objcString(wrapObject(args[2]));
      },
      onLeave(retval) {
        if (!retval.isNull()) nsxpcListeners.set(retval.toString(), { name: this.name, kind: "mach" });
      }
    });
    const classFactory = function(kind) {
      return {
        onLeave(retval) {
          if (!retval.isNull()) nsxpcListeners.set(retval.toString(), { name: null, kind });
        }
      };
    };
    attachObjCMethod(L, "+ serviceListener", classFactory("service"));
    attachObjCMethod(L, "+ anonymousListener", classFactory("anonymous"));
    attachObjCMethod(L, "- setDelegate:", {
      onEnter(args) {
        const delegate = wrapObject(args[2]);
        if (delegate !== null) hookAcceptDelegate(delegate.$className);
      }
    });
    for (const target of resolveObjCPattern("-[* listener:shouldAcceptNewConnection:]")) {
      hookAcceptDelegate(target.className);
    }
    return true;
  }
  function hookAcceptDelegate(className) {
    const klass = ObjC.classes[className];
    if (klass === void 0) return;
    hookObjCMethod(klass, "- listener:shouldAcceptNewConnection:", function(original, args, info) {
      const result = withBusyThread(function() {
        const listener = nsxpcListeners.get(args[2].toString()) || { name: null, kind: "unknown" };
        const conn2 = wrapObject(args[3]);
        const peer = conn2 !== null ? connectionPeer(conn2) : { pid: null, euid: null, path: null };
        const extras = {
          "peer/pid": { type: "int64", value: String(peer.pid) },
          "peer/euid": { type: "uint64", value: String(peer.euid) }
        };
        if (peer.path) extras["peer/path"] = { type: "string", value: peer.path };
        return processEvent({
          className: runtimeClassName(args[0], className),
          methodName: "-[" + className + " listener:shouldAcceptNewConnection:]",
          component: listener.name || listener.kind + " listener",
          action: "accept connection",
          extras,
          interceptable: true,
          mods: [],
          attackSurface: { platform: "ios", direction: "incoming", exposure: "listener", serviceKind: listener.kind, peerPid: peer.pid, peerPath: peer.path },
          ipc: { kind: "nsxpc_accept", direction: "incoming", service: listener.name, serviceKind: listener.kind, peer }
        }, this.context);
      }.bind(this));
      if (result.mode === "drop") {
        log("[+]", "Rejected NSXPC connection (dropped)");
        return 0;
      }
      const accepted = callOriginal(original, args, info.selector);
      const conn = wrapObject(args[3]);
      if (accepted && conn !== null) {
        const listener = nsxpcListeners.get(args[2].toString());
        nsxpcConnections.set(conn.handle.toString(), { name: listener ? listener.name : null, kind: "peer" });
      }
      return accepted;
    });
  }
  var declaredSchemes = null;
  function getDeclaredSchemes() {
    if (declaredSchemes !== null) return declaredSchemes;
    declaredSchemes = /* @__PURE__ */ new Set();
    try {
      const types2 = ObjC.classes.NSBundle.mainBundle().objectForInfoDictionaryKey_("CFBundleURLTypes");
      const list = objcToJs(types2, 4) || [];
      for (const t of list) {
        for (const s of t && t.CFBundleURLSchemes || []) declaredSchemes.add(String(s).toLowerCase());
      }
    } catch (_) {
    }
    return declaredSchemes;
  }
  function urlSurface(direction, url, extra) {
    const surface = Object.assign({ platform: "ios", direction }, extra || {});
    if (url && direction === "incoming") {
      const scheme = String(url).split(":")[0].toLowerCase();
      if (scheme === "http" || scheme === "https") surface.exposure = surface.exposure || "universal_link";
      else surface.exposure = getDeclaredSchemes().has(scheme) ? "declared_scheme" : "url_scheme";
    }
    return surface;
  }
  function optionsExtras(options, prefix) {
    const extras = {};
    const dict = objcToJs(wrapObject(options), 2);
    if (dict && typeof dict === "object") {
      for (const key of Object.keys(dict)) {
        const value = dict[key];
        extras[prefix + key] = typeof value === "string" ? { type: "string", value: truncate(value, 1024) } : { type: "option", value: truncate(JSON.stringify(value), 1024) };
      }
    }
    return extras;
  }
  function urlEvent(context, original, args, info, spec) {
    const urlObj = spec.urlIndex !== void 0 ? wrapObject(args[spec.urlIndex]) : null;
    const url = spec.url !== void 0 ? spec.url : objcString(urlObj);
    const extras = Object.assign({}, spec.extras || {});
    const ev = {
      className: runtimeClassName(args[0], info.className),
      methodName: (info.isClassMethod ? "+" : "-") + "[" + info.className + " " + info.selector + "]",
      action: spec.action,
      data: url,
      component: spec.component || null,
      extras,
      interceptable: spec.interceptable !== false && !isNestedSelector(info.selector),
      mods: spec.urlIndex !== void 0 || spec.setUrl ? ["data"] : [],
      attackSurface: urlSurface(spec.direction, url, spec.surface),
      ipc: { kind: "url", direction: spec.direction, url, selector: info.selector }
    };
    const r = withBusyThread(function() {
      return processEvent(ev, context);
    });
    if (r.mode === "drop") {
      if (spec.onDrop) return spec.onDrop();
      return defaultReturn(info.returnType);
    }
    for (const mod of r.mods) {
      if (mod.type !== "data") continue;
      withBusyThread(function() {
        const newUrl = ObjC.classes.NSURL.URLWithString_(String(mod.val));
        if (newUrl === null || newUrl.handle.isNull()) {
          log("[!]", "Invalid URL: " + mod.val);
          return;
        }
        keepTemp(newUrl);
        if (spec.setUrl) spec.setUrl(newUrl);
        else args[spec.urlIndex] = newUrl.handle;
        log("[+]", "URL replaced with " + mod.val);
      });
    }
    return callOriginal(original, args, info.selector);
  }
  function hookUrlIncoming() {
    const handlers = [
      ["-[* application:openURL:options:]", function(original, args, info) {
        const extras = optionsExtras(args[4], "options/");
        const source = extras["options/UIApplicationOpenURLOptionsSourceApplicationKey"];
        return urlEvent(this.context, original, args, info, {
          direction: "incoming",
          action: "openURL",
          urlIndex: 3,
          extras,
          component: source ? source.value : null
        });
      }],
      ["-[* application:openURL:sourceApplication:annotation:]", function(original, args, info) {
        const source = objcString(wrapObject(args[4]));
        return urlEvent(this.context, original, args, info, {
          direction: "incoming",
          action: "openURL",
          urlIndex: 3,
          component: source,
          extras: source ? { sourceApplication: { type: "string", value: source } } : {}
        });
      }],
      ["-[* application:handleOpenURL:]", function(original, args, info) {
        return urlEvent(this.context, original, args, info, { direction: "incoming", action: "handleOpenURL", urlIndex: 3 });
      }],
      ["-[* application:continueUserActivity:restorationHandler:]", function(original, args, info) {
        return userActivityEvent(this.context, original, args, info, 3);
      }],
      ["-[* scene:continueUserActivity:]", function(original, args, info) {
        return userActivityEvent(this.context, original, args, info, 3);
      }],
      ["-[* scene:openURLContexts:]", function(original, args, info) {
        const contexts = urlContexts(wrapObject(args[3]));
        return urlEvent(this.context, original, args, info, {
          direction: "incoming",
          action: "openURLContexts",
          url: contexts.urls[0] || null,
          component: contexts.source,
          extras: contexts.extras
        });
      }],
      ["-[* scene:willConnectToSession:options:]", function(original, args, info) {
        const options = wrapObject(args[4]);
        let contexts = { urls: [], extras: {}, source: null };
        let activity = null;
        try {
          contexts = urlContexts(options.URLContexts());
        } catch (_) {
        }
        try {
          const acts = options.userActivities().allObjects();
          if (acts.count() > 0) activity = acts.objectAtIndex_(0);
        } catch (_) {
        }
        if (!contexts.urls.length && activity === null) return original.apply(null, args);
        const extras = contexts.extras;
        let url = contexts.urls[0] || null;
        if (activity !== null) {
          extras["userActivity/type"] = { type: "string", value: objcString(activity.activityType()) };
          try {
            url = url || objcString(activity.webpageURL());
          } catch (_) {
          }
        }
        return urlEvent(this.context, original, args, info, {
          direction: "incoming",
          action: "cold launch",
          url,
          component: contexts.source,
          extras,
          interceptable: false
        });
      }]
    ];
    let count = 0;
    for (const [pattern, handler] of handlers) {
      for (const target of resolveObjCPattern(pattern)) {
        if (hookObjCTarget(target, handler)) count += 1;
      }
    }
    return count;
  }
  function urlContexts(set) {
    const out = { urls: [], extras: {}, source: null };
    if (set === null) return out;
    try {
      const items = set.allObjects();
      for (let i = 0; i < items.count(); i++) {
        const ctx = items.objectAtIndex_(i);
        const url = objcString(ctx.URL());
        out.urls.push(url);
        out.extras["urls[" + i + "]"] = { type: "url", value: url };
        try {
          const source = objcString(ctx.options().sourceApplication());
          if (source) {
            out.extras["urls[" + i + "]/sourceApplication"] = { type: "string", value: source };
            out.source = out.source || source;
          }
        } catch (_) {
        }
      }
    } catch (_) {
    }
    return out;
  }
  function userActivityEvent(context, original, args, info, index) {
    const activity = wrapObject(args[index]);
    let url = null;
    const extras = {};
    if (activity !== null) {
      try {
        url = objcString(activity.webpageURL());
      } catch (_) {
      }
      try {
        extras.activityType = { type: "string", value: objcString(activity.activityType()) };
      } catch (_) {
      }
      try {
        const userInfo = objcToJs(activity.userInfo(), 3);
        if (userInfo) {
          for (const key of Object.keys(userInfo)) {
            extras["userInfo/" + key] = { type: "option", value: truncate(JSON.stringify(userInfo[key]), 1024) };
          }
        }
      } catch (_) {
      }
    }
    return urlEvent(context, original, args, info, {
      direction: "incoming",
      action: "continueUserActivity",
      url,
      extras,
      setUrl: activity !== null ? function(newUrl) {
        activity.setWebpageURL_(newUrl);
      } : void 0,
      surface: { exposure: "universal_link" }
    });
  }
  function hookUrlOutgoing() {
    const A = ObjC.classes.UIApplication;
    let count = 0;
    if (A !== void 0) {
      const openWithOptions = function(original, args, info) {
        const completion = args[4];
        return urlEvent(this.context, original, args, info, {
          direction: "outgoing",
          action: "openURL",
          urlIndex: 2,
          extras: optionsExtras(args[3], "options/"),
          onDrop: function() {
            if (!completion.isNull()) {
              try {
                new ObjC.Block(completion).implementation(0);
              } catch (_) {
              }
            }
          }
        });
      };
      if (hookObjCMethod(A, "- openURL:options:completionHandler:", openWithOptions)) count += 1;
      if (hookObjCMethod(A, "- openURL:", function(original, args, info) {
        return urlEvent(this.context, original, args, info, { direction: "outgoing", action: "openURL", urlIndex: 2 });
      })) count += 1;
      if (hookObjCMethod(A, "- canOpenURL:", function(original, args, info) {
        return urlEvent(this.context, original, args, info, {
          direction: "outgoing",
          action: "canOpenURL",
          urlIndex: 2,
          interceptable: false,
          surface: { exposure: "scheme_query" }
        });
      })) count += 1;
    }
    const E = ObjC.classes.NSExtensionContext;
    if (E !== void 0 && hookObjCMethod(E, "- openURL:completionHandler:", function(original, args, info) {
      return urlEvent(this.context, original, args, info, { direction: "outgoing", action: "openURL", urlIndex: 2 });
    })) count += 1;
    return count;
  }
  function objString(p) {
    return objcString(wrapObject(p));
  }
  function jsonPreview(obj, limit) {
    const value = objcToJs(obj, 4);
    if (value === null || value === void 0) return "nil";
    return truncate(typeof value === "string" ? value : JSON.stringify(value), limit || 4096);
  }
  function dataPreview(data) {
    if (data === null) return null;
    try {
      const length = Number(data.length());
      const bytes = readBytes(data.bytes(), Math.min(length, 512));
      return length + " bytes: " + bodyPreview(bytes, 512);
    } catch (_) {
      return null;
    }
  }
  function requestExtras(req, prefix, extras) {
    if (req === null) return null;
    let url = null;
    try {
      url = objcString(req.URL());
    } catch (_) {
    }
    try {
      const method2 = req.HTTPMethod();
      if (method2 !== null) extras[prefix + "method"] = { type: "string", value: method2.toString() };
    } catch (_) {
    }
    try {
      const headers = objcToJs(req.allHTTPHeaderFields(), 2);
      if (headers) {
        for (const key of Object.keys(headers)) {
          extras[prefix + "headers/" + key] = { type: "string", value: truncate(String(headers[key]), 1024) };
        }
      }
    } catch (_) {
    }
    try {
      const body = dataPreview(req.HTTPBody());
      if (body !== null) extras[prefix + "body"] = { type: "data", value: body };
    } catch (_) {
    }
    return url;
  }
  function isMainThread() {
    try {
      return Boolean(ObjC.classes.NSThread.isMainThread());
    } catch (_) {
      return false;
    }
  }
  function webViewUrl(webView) {
    if (webView === null || !isMainThread()) return null;
    try {
      return objcString(webView.URL());
    } catch (_) {
      return null;
    }
  }
  var appBundlePath = null;
  function isAppClass(className) {
    try {
      if (appBundlePath === null) appBundlePath = String(ObjC.classes.NSBundle.mainBundle().bundlePath());
      const klass = ObjC.classes[className];
      if (klass === void 0) return false;
      const image = ObjC.api.class_getImageName(klass.handle);
      return !image.isNull() && image.readUtf8String().indexOf(appBundlePath) === 0;
    } catch (_) {
      return false;
    }
  }
  function frameExtras(frame, prefix, extras) {
    if (frame === null) return null;
    let url = null;
    try {
      extras[prefix + "mainFrame"] = { type: "bool", value: frame.isMainFrame() ? "true" : "false" };
    } catch (_) {
    }
    try {
      url = requestExtras(frame.request(), prefix + "request/", extras);
    } catch (_) {
    }
    try {
      const origin = frame.securityOrigin();
      extras[prefix + "origin"] = {
        type: "string",
        value: objcString(origin.protocol()) + "://" + objcString(origin.host()) + (Number(origin.port()) ? ":" + Number(origin.port()) : "")
      };
    } catch (_) {
    }
    return url;
  }
  function webEvent(context, original, args, info, spec) {
    const ev = {
      className: runtimeClassName(args[0], info.className),
      methodName: (info.isClassMethod ? "+" : "-") + "[" + info.className + " " + info.selector + "]",
      component: spec.component || null,
      action: spec.action,
      data: spec.url || null,
      extras: spec.extras || {},
      interceptable: spec.interceptable !== false && !isNestedSelector(info.selector),
      mods: spec.mods || [],
      attackSurface: Object.assign({ platform: "ios", direction: spec.direction }, spec.surface || {}),
      ipc: { kind: spec.kind || "webview", direction: spec.direction, selector: info.selector, url: spec.url || null }
    };
    const r = withBusyThread(function() {
      return processEvent(ev, context);
    });
    if (r.mode === "drop") {
      if (spec.onDrop) return spec.onDrop();
      return defaultReturn(info.returnType);
    }
    withBusyThread(function() {
      for (const mod of r.mods) {
        if (mod.type === "data" && spec.setUrl) {
          const url = ObjC.classes.NSURL.URLWithString_(String(mod.val));
          if (url === null) {
            log("[!]", "Invalid URL: " + mod.val);
            continue;
          }
          keepTemp(url);
          spec.setUrl(url);
          log("[+]", "URL replaced with " + mod.val);
        } else if (mod.type === "extra_add") {
          applyObjCArgMods(info.encodings, args, [mod]);
        }
      }
    });
    return callOriginal(original, args, info.selector);
  }
  function hookPattern(pattern, handler) {
    let count = 0;
    for (const target of resolveObjCPattern(pattern)) {
      if (!isAppClass(target.className)) continue;
      if (hookObjCTarget(target, handler)) count += 1;
    }
    return count;
  }
  function attachPattern(pattern, callbacks) {
    let count = 0;
    for (const target of resolveObjCPattern(pattern)) {
      if (!isAppClass(target.className)) continue;
      const klass = ObjC.classes[target.className];
      if (klass === void 0) continue;
      if (attachObjCMethod(klass, (target.isClassMethod ? "+ " : "- ") + target.selector, callbacks)) count += 1;
    }
    return count;
  }
  function observeWeb(context, ev) {
    withBusyThread(function() {
      processEvent(Object.assign({
        className: "WebKit",
        interceptable: false,
        mods: [],
        extras: {}
      }, ev, {
        attackSurface: Object.assign({ platform: "ios", direction: ev.direction }, ev.surface || {}),
        ipc: Object.assign({ kind: ev.kind || "webview", direction: ev.direction }, ev.ipc || {})
      }), context);
    });
  }
  function hookWebBridges() {
    let count = 0;
    const onMessage = function(withReply) {
      return function(original, args, info) {
        const msg = wrapObject(args[3]);
        const extras = {};
        let name = null;
        let url = null;
        if (msg !== null) {
          try {
            name = objcString(msg.name());
          } catch (_) {
          }
          try {
            extras.body = { type: "json", value: jsonPreview(msg.body()) };
          } catch (_) {
          }
          try {
            url = frameExtras(msg.frameInfo(), "frame/", extras);
          } catch (_) {
          }
          try {
            extras["webView/url"] = { type: "url", value: webViewUrl(msg.webView()) };
          } catch (_) {
          }
        }
        if (name !== null) extras.name = { type: "string", value: name };
        if (withReply) extras.replyHandler = { type: "block", value: "<reply>" };
        return webEvent(this.context, original, args, info, {
          direction: "incoming",
          action: "script message",
          component: name,
          url,
          extras,
          surface: { exposure: "js_bridge" }
        });
      };
    };
    count += hookPattern("-[* userContentController:didReceiveScriptMessage:]", onMessage(false));
    count += hookPattern("-[* userContentController:didReceiveScriptMessage:replyHandler:]", onMessage(true));
    const W = ObjC.classes.WKUserContentController;
    if (W !== void 0) {
      const registration = function(nameIndex) {
        return {
          onEnter(args, info) {
            const handler = wrapObject(args[2]);
            const name = objString(args[nameIndex]);
            observeWeb(this.context, {
              methodName: "-[WKUserContentController " + info.selector + "]",
              component: name,
              action: "register JS bridge",
              direction: "incoming",
              extras: {
                name: { type: "string", value: name },
                handler: { type: "class", value: handler !== null ? handler.$className : "nil" },
                replies: { type: "bool", value: info.selector.indexOf("WithReply") !== -1 ? "true" : "false" }
              },
              surface: { exposure: "js_bridge" }
            });
          }
        };
      };
      if (attachObjCMethod(W, "- addScriptMessageHandler:name:", registration(3))) count += 1;
      if (attachObjCMethod(W, "- addScriptMessageHandler:contentWorld:name:", registration(4))) count += 1;
      if (attachObjCMethod(W, "- addScriptMessageHandlerWithReply:contentWorld:name:", registration(4))) count += 1;
      if (attachObjCMethod(W, "- addUserScript:", {
        onEnter(args) {
          const script = wrapObject(args[2]);
          let source = null;
          let mainFrameOnly = null;
          try {
            source = objcString(script.source());
          } catch (_) {
          }
          try {
            mainFrameOnly = script.isForMainFrameOnly() ? "true" : "false";
          } catch (_) {
          }
          observeWeb(this.context, {
            methodName: "-[WKUserContentController addUserScript:]",
            action: "inject user script",
            direction: "outgoing",
            extras: {
              source: { type: "javascript", value: truncate(source, 4096) },
              mainFrameOnly: { type: "bool", value: mainFrameOnly }
            }
          });
        }
      })) count += 1;
    }
    const J = ObjC.classes.JSContext;
    if (J !== void 0) {
      if (attachObjCMethod(J, "- setObject:forKeyedSubscript:", {
        onEnter(args) {
          const obj = wrapObject(args[2]);
          const key = objString(args[3]);
          observeWeb(this.context, {
            className: "JavaScriptCore",
            methodName: "-[JSContext setObject:forKeyedSubscript:]",
            component: key,
            action: "expose native object",
            direction: "incoming",
            extras: {
              name: { type: "string", value: key },
              object: { type: obj !== null ? obj.$className : "nil", value: obj !== null ? truncate(objcString(obj), 512) : "nil" }
            },
            surface: { exposure: "js_bridge" },
            ipc: { engine: "JavaScriptCore" }
          });
        }
      })) count += 1;
    }
    return count;
  }
  function attachWebCall(klass, name, describe) {
    return attachObjCMethod(klass, name, {
      onEnter(args, info) {
        const spec = describe(args, info);
        const ev = {
          className: spec.className || info.className,
          methodName: "-[" + info.className + " " + info.selector + "]",
          component: spec.component || null,
          action: spec.action,
          data: spec.url || null,
          extras: spec.extras || {},
          interceptable: spec.interceptable !== false,
          mods: spec.mods || [],
          attackSurface: { platform: "ios", direction: "outgoing" },
          ipc: { kind: "webview", direction: "outgoing", selector: info.selector, url: spec.url || null }
        };
        const r = withBusyThread(function() {
          return processEvent(ev, this.context);
        }.bind(this));
        withBusyThread(function() {
          if (r.mode === "drop") {
            if (spec.drop) {
              spec.drop(args);
              log("[+]", info.selector + " neutralised (dropped)");
            } else {
              log("[~]", info.selector + " cannot be dropped; forwarded unchanged");
            }
            return;
          }
          for (const mod of r.mods) {
            if (mod.type === "data" && spec.setUrl) {
              const url = ObjC.classes.NSURL.URLWithString_(String(mod.val));
              if (url === null) {
                log("[!]", "Invalid URL: " + mod.val);
                continue;
              }
              keepTemp(url);
              spec.setUrl(args, url);
              log("[+]", "URL replaced with " + mod.val);
            } else if (mod.type === "extra_add") {
              applyObjCArgMods(info.encodings, args, [mod]);
            }
          }
        });
      }
    });
  }
  function nsString(text) {
    const value = ObjC.classes.NSString.stringWithString_(text);
    keepTemp(value);
    return value.handle;
  }
  function blankRequest() {
    const request = ObjC.classes.NSURLRequest.requestWithURL_(ObjC.classes.NSURL.URLWithString_("about:blank"));
    keepTemp(request);
    return request.handle;
  }
  function hookWebLoads() {
    let count = 0;
    for (const viewClass of ["WKWebView", "UIWebView"]) {
      const V = ObjC.classes[viewClass];
      if (V === void 0) continue;
      const add = function(name, describe) {
        if (V[name] !== void 0 && attachWebCall(V, name, describe)) count += 1;
      };
      add("- loadRequest:", function(args) {
        const extras = {};
        const url = requestExtras(wrapObject(args[2]), "request/", extras);
        return {
          action: "load request",
          component: hostOf(url),
          url,
          extras,
          mods: ["data"],
          // Replaces the whole request: headers and body of the original are not kept.
          setUrl: function(a, newUrl) {
            const request = ObjC.classes.NSURLRequest.requestWithURL_(newUrl);
            keepTemp(request);
            a[2] = request.handle;
          },
          drop: function(a) {
            a[2] = blankRequest();
          }
        };
      });
      add("- loadHTMLString:baseURL:", function(args) {
        const base = objString(args[3]);
        return {
          action: "load HTML",
          component: hostOf(base),
          url: base,
          mods: ["data", "extra_add"],
          extras: { arg0: { type: "html", value: truncate(objString(args[2]), 4096) }, baseURL: { type: "url", value: base } },
          setUrl: function(a, newUrl) {
            a[3] = newUrl.handle;
          },
          drop: function(a) {
            a[2] = nsString("");
            a[3] = NULL;
          }
        };
      });
      add("- loadFileURL:allowingReadAccessToURL:", function(args) {
        return {
          action: "load file",
          url: objString(args[2]),
          mods: ["data"],
          extras: { readAccessURL: { type: "url", value: objString(args[3]) } },
          setUrl: function(a, newUrl) {
            a[2] = newUrl.handle;
          }
        };
      });
      add("- loadData:MIMEType:characterEncodingName:baseURL:", function(args) {
        const base = objString(args[5]);
        return {
          action: "load data",
          component: hostOf(base),
          url: base,
          interceptable: false,
          extras: { data: { type: "data", value: dataPreview(wrapObject(args[2])) }, mimeType: { type: "string", value: objString(args[3]) } }
        };
      });
      const evaluate = function(args) {
        const page = webViewUrl(wrapObject(args[0]));
        return {
          action: "evaluate JavaScript",
          component: hostOf(page),
          url: page,
          mods: ["extra_add"],
          extras: { arg0: { type: "javascript", value: truncate(objString(args[2]), 4096) } },
          drop: function(a) {
            a[2] = nsString("void 0");
          }
        };
      };
      add("- evaluateJavaScript:completionHandler:", evaluate);
      add("- evaluateJavaScript:inFrame:inContentWorld:completionHandler:", evaluate);
      add("- callAsyncJavaScript:arguments:inFrame:inContentWorld:completionHandler:", evaluate);
      add("- stringByEvaluatingJavaScriptFromString:", evaluate);
    }
    const J = ObjC.classes.JSContext;
    if (J !== void 0) {
      const evaluateScript = function(args) {
        return {
          className: "JavaScriptCore",
          action: "evaluate JavaScript",
          interceptable: false,
          extras: { arg0: { type: "javascript", value: truncate(objString(args[2]), 4096) } }
        };
      };
      for (const name of ["- evaluateScript:", "- evaluateScript:withSourceURL:"]) {
        if (J[name] !== void 0 && attachWebCall(J, name, evaluateScript)) count += 1;
      }
    }
    return count;
  }
  function hookWebNavigation() {
    let count = 0;
    const wk = function(withPreferences) {
      return function(original, args, info) {
        const action = wrapObject(args[3]);
        const handler = withPreferences ? args[5] : args[4];
        const extras = {};
        let url = null;
        if (action !== null) {
          try {
            url = requestExtras(action.request(), "request/", extras);
          } catch (_) {
          }
          try {
            extras.navigationType = { type: "string", value: navigationTypeName(action.navigationType()) };
          } catch (_) {
          }
          try {
            const target = action.targetFrame();
            extras.targetFrame = { type: "string", value: target === null ? "new window" : target.isMainFrame() ? "main" : "subframe" };
          } catch (_) {
          }
          try {
            frameExtras(action.sourceFrame(), "sourceFrame/", extras);
          } catch (_) {
          }
        }
        return webEvent(this.context, original, args, info, {
          direction: "incoming",
          action: "navigation",
          component: hostOf(url),
          url,
          extras,
          onDrop: function() {
            try {
              const block2 = new ObjC.Block(handler);
              if (withPreferences) block2.implementation(0, args[4]);
              else block2.implementation(0);
              log("[+]", "Navigation cancelled (dropped)");
            } catch (e) {
              log("[!]", "Could not cancel navigation: " + e);
            }
          }
        });
      };
    };
    count += hookPattern("-[* webView:decidePolicyForNavigationAction:decisionHandler:]", wk(false));
    count += hookPattern("-[* webView:decidePolicyForNavigationAction:preferences:decisionHandler:]", wk(true));
    count += hookPattern("-[* webView:shouldStartLoadWithRequest:navigationType:]", function(original, args, info) {
      const extras = {};
      const url = requestExtras(wrapObject(args[3]), "request/", extras);
      extras.navigationType = { type: "string", value: navigationTypeName(Number(args[4])) };
      return webEvent(this.context, original, args, info, {
        direction: "incoming",
        action: "navigation",
        component: hostOf(url),
        url,
        extras,
        onDrop: function() {
          return 0;
        }
      });
    });
    return count;
  }
  function hookWebSchemes() {
    let count = 0;
    const C = ObjC.classes.WKWebViewConfiguration;
    if (C !== void 0 && attachObjCMethod(C, "- setURLSchemeHandler:forURLScheme:", {
      onEnter(args) {
        const handler = wrapObject(args[2]);
        const scheme = objString(args[3]);
        observeWeb(this.context, {
          methodName: "-[WKWebViewConfiguration setURLSchemeHandler:forURLScheme:]",
          component: scheme,
          action: "register URL scheme handler",
          direction: "incoming",
          extras: {
            scheme: { type: "string", value: scheme },
            handler: { type: "class", value: handler !== null ? handler.$className : "nil" }
          },
          surface: { exposure: "webview_scheme" }
        });
      }
    })) count += 1;
    count += attachPattern("-[* webView:startURLSchemeTask:]", {
      onEnter(args, info) {
        const task = wrapObject(args[3]);
        const extras = {};
        let url = null;
        try {
          url = requestExtras(task.request(), "request/", extras);
        } catch (_) {
        }
        observeWeb(this.context, {
          className: info.className,
          methodName: "-[" + info.className + " webView:startURLSchemeTask:]",
          component: url ? url.split(":")[0] : null,
          action: "URL scheme request",
          direction: "incoming",
          data: url,
          extras,
          surface: { exposure: "webview_scheme" }
        });
      }
    });
    const browsers = [
      ["SFSafariViewController", "- initWithURL:"],
      ["SFSafariViewController", "- initWithURL:configuration:"],
      ["SFSafariViewController", "- initWithURL:entersReaderIfAvailable:"],
      ["ASWebAuthenticationSession", "- initWithURL:callbackURLScheme:completionHandler:"],
      ["SFAuthenticationSession", "- initWithURL:callbackURLScheme:completionHandler:"]
    ];
    for (const [className, name] of browsers) {
      const K = ObjC.classes[className];
      if (K === void 0) continue;
      if (attachObjCMethod(K, name, {
        onEnter(args, info) {
          const url = objString(args[2]);
          const extras = {};
          if (info.selector.indexOf("callbackURLScheme") !== -1) {
            extras.callbackURLScheme = { type: "string", value: objString(args[3]) };
          }
          observeWeb(this.context, {
            className,
            methodName: "-[" + className + " " + info.selector + "]",
            component: hostOf(url),
            action: className.indexOf("Authentication") !== -1 ? "web authentication" : "in-app browser",
            direction: "outgoing",
            data: url,
            extras
          });
        }
      })) count += 1;
    }
    return count;
  }
  var networkThreads = /* @__PURE__ */ new Set();
  function isNetworkTaskMethod(name) {
    return /^- (data|upload|download)TaskWith(Request|URL):/.test(name) || /^- webSocketTaskWith(URL|Request):/.test(name) || name === "- streamTaskWithHostName:port:";
  }
  function networkSessionClasses() {
    const out = [];
    for (const name of ["NSURLSession", "__NSURLSessionLocal"]) {
      const klass = ObjC.classes[name];
      if (klass === void 0) continue;
      try {
        const image = ObjC.api.class_getImageName(klass.handle).readUtf8String();
        if (image.indexOf("CFNetwork") === -1 && image.indexOf("Foundation") === -1) continue;
      } catch (_) {
        continue;
      }
      out.push(klass);
    }
    return out;
  }
  function hookNetworkRequests() {
    let count = 0;
    for (const S of networkSessionClasses()) {
      for (const name of S.$ownMethods.filter(isNetworkTaskMethod)) {
        if (attachNetworkMethod(S, name)) count += 1;
      }
    }
    return count;
  }
  function attachNetworkMethod(S, name) {
    return attachObjCMethod(S, name, {
      onEnter(args, info) {
        const tid = Process.getCurrentThreadId();
        if (networkThreads.has(tid)) return;
        networkThreads.add(tid);
        this.networkTid = tid;
        const extras = {};
        let url = null;
        let method2 = null;
        if (info.selector === "streamTaskWithHostName:port:") {
          url = "tcp://" + objString(args[2]) + ":" + args[3].toInt32();
        } else {
          const target = wrapObject(args[2]);
          if (target !== null && target.isKindOfClass_(ObjC.classes.NSURLRequest)) {
            url = requestExtras(target, "", extras);
            method2 = extras.method ? extras.method.value : null;
          } else {
            url = objcString(target);
          }
        }
        if (info.selector.indexOf("fromData:") !== -1) {
          const body = dataPreview(wrapObject(args[3]));
          if (body !== null) extras.body = { type: "data", value: body };
        } else if (info.selector.indexOf("fromFile:") !== -1) {
          extras.file = { type: "url", value: objString(args[3]) };
        }
        withBusyThread(function() {
          processEvent({
            className: "CFNetwork",
            methodName: "-[" + info.className + " " + info.selector + "]",
            component: hostOf(url),
            action: method2 || info.selector.split("With")[0],
            data: url,
            extras,
            interceptable: false,
            mods: [],
            attackSurface: { platform: "ios", direction: "outgoing" },
            ipc: { kind: "network", direction: "outgoing", url }
          }, this.context);
        }.bind(this));
      },
      onLeave() {
        if (this.networkTid !== void 0) networkThreads.delete(this.networkTid);
      }
    });
  }
  function hookNotify(entry) {
    const fn = entry.function;
    const addr = findExport(fn, "libsystem_notify.dylib");
    if (addr === null) {
      if (!entry.optional) throw new Error(fn + " not found");
      return false;
    }
    const intercept = entry.intercept !== false;
    if (fn === "notify_post") {
      const orig = new NativeFunction(addr, "uint32", ["pointer"]);
      const cb = new NativeCallback(function(namePtr) {
        if (shouldPassthrough()) return orig(namePtr);
        const name = readCString(namePtr);
        const r = withBusyThread(function() {
          return processEvent({
            className: moduleNameFor(this.returnAddress) || "unknown",
            methodName: fn,
            component: name,
            action: "post",
            interceptable: intercept,
            mods: [],
            attackSurface: { platform: "ios", direction: "outgoing", exposure: "darwin_notification" },
            ipc: { kind: "darwin_notification", direction: "outgoing", name }
          }, this.context);
        }.bind(this));
        return r.mode === "drop" ? 0 : orig(namePtr);
      }, "uint32", ["pointer"]);
      Interceptor.replace(addr, cb);
      keepAlive.push(cb);
      return true;
    }
    Interceptor.attach(addr, {
      onEnter(args) {
        if (shouldPassthrough()) return;
        const name = readCString(args[0]);
        const context = this.context;
        const caller = moduleNameFor(this.returnAddress) || "unknown";
        withBusyThread(function() {
          processEvent({
            className: caller,
            methodName: fn,
            component: name,
            action: "register",
            interceptable: false,
            attackSurface: { platform: "ios", direction: "incoming", exposure: "darwin_listener" },
            ipc: { kind: "darwin_notification", direction: "incoming", name }
          }, context);
        });
      }
    });
    return true;
  }
  function hookCustomObjC(entry) {
    const pattern = entry.method;
    const targets = /[*?]/.test(pattern) ? resolveObjCPattern(pattern) : function() {
      const m2 = /^([+-])\[(\S+) (.+)\]$/.exec(pattern);
      if (m2 === null) throw new Error("invalid method spec " + pattern + ' (expected "-[Class selector:]")');
      return [{ isClassMethod: m2[1] === "+", className: m2[2], selector: m2[3] }];
    }();
    let count = 0;
    for (const target of targets) {
      const ok = hookObjCTarget(target, function(original, args, info) {
        return objcCallEvent(this.context, original, args, info, {
          interceptable: entry.intercept !== false && !isNestedSelector(info.selector),
          component: entry.component || info.className,
          attackSurface: { platform: "ios", direction: entry.direction || "incoming" },
          ipc: { kind: "objc", direction: entry.direction || "incoming", selector: info.selector, receiverClass: info.className }
        }).value;
      });
      if (ok) count += 1;
    }
    if (count === 0) {
      if (entry.optional) return "none";
      throw new Error("no methods matched " + pattern);
    }
    return count;
  }
  function objcToJs(obj, depth) {
    if (obj === null || obj === void 0) return null;
    if (depth < 0) return objcString(obj);
    const C = ObjC.classes;
    try {
      if (obj.isKindOfClass_(C.NSString)) return obj.toString();
      if (obj.isKindOfClass_(C.NSNumber)) {
        const s = obj.toString();
        const n = Number(s);
        return isNaN(n) ? s : n;
      }
      if (obj.isKindOfClass_(C.NSArray)) {
        const out = [];
        const count = Math.min(obj.count(), 256);
        for (let i = 0; i < count; i++) out.push(objcToJs(obj.objectAtIndex_(i), depth - 1));
        return out;
      }
      if (obj.isKindOfClass_(C.NSDictionary)) {
        const out = {};
        const keys = obj.allKeys();
        const count = Math.min(keys.count(), 256);
        for (let i = 0; i < count; i++) {
          const key = keys.objectAtIndex_(i);
          out[key.toString()] = objcToJs(obj.objectForKey_(key), depth - 1);
        }
        return out;
      }
      if (obj.isKindOfClass_(C.NSData)) return "<" + obj.length() + " bytes>";
    } catch (_) {
    }
    return objcString(obj);
  }
  function readMainEntitlements() {
    const main = Process.mainModule || Process.enumerateModules()[0];
    const base = main.base;
    if (base.readU32() !== 4277009103) return null;
    const ncmds = base.add(16).readU32();
    let lc = base.add(32);
    let textVm = null;
    let linkedit = null;
    let signature2 = null;
    for (let i = 0; i < ncmds; i++) {
      const cmd = lc.readU32();
      const size = lc.add(4).readU32();
      if (cmd === 25) {
        const segname = lc.add(8).readCString(16);
        if (segname === "__TEXT") textVm = lc.add(24).readU64();
        if (segname === "__LINKEDIT") linkedit = { vm: lc.add(24).readU64(), fileoff: lc.add(40).readU64() };
      } else if (cmd === 29) {
        signature2 = { dataoff: lc.add(8).readU32(), datasize: lc.add(12).readU32() };
      }
      lc = lc.add(size);
    }
    if (textVm === null || linkedit === null || signature2 === null) return null;
    const slide = base.sub(ptr(textVm.toString()));
    const address = slide.add(ptr(linkedit.vm.toString())).add(signature2.dataoff - linkedit.fileoff.toNumber());
    return entitlementsFromSuperBlob(readBytes(address, signature2.datasize));
  }
  function listExtensions(bundle) {
    const out = [];
    try {
      const dir = bundle.builtInPlugInsPath();
      if (dir === null) return out;
      const fm = ObjC.classes.NSFileManager.defaultManager();
      const items = fm.contentsOfDirectoryAtPath_error_(dir, NULL);
      if (items === null) return out;
      for (let i = 0; i < items.count(); i++) {
        const name = items.objectAtIndex_(i).toString();
        if (!name.endsWith(".appex")) continue;
        const path = dir.toString() + "/" + name;
        const ext = ObjC.classes.NSBundle.bundleWithPath_(path);
        const info = ext !== null ? objcToJs(ext.infoDictionary(), 4) || {} : {};
        const nsext = info.NSExtension || {};
        out.push({
          name,
          bundleId: info.CFBundleIdentifier || null,
          point: nsext.NSExtensionPointIdentifier || null,
          principalClass: nsext.NSExtensionPrincipalClass || null,
          attributes: nsext.NSExtensionAttributes || null
        });
      }
    } catch (e) {
      log("[~]", "Extension enumeration failed: " + e);
    }
    return out;
  }
  function staticAttackSurface() {
    const out = { platform: "ios", pid: Process.id, process: null, bundle: null, entitlements: null };
    try {
      const main = Process.mainModule || Process.enumerateModules()[0];
      out.process = { name: main.name, path: main.path };
    } catch (_) {
    }
    try {
      out.entitlements = readMainEntitlements();
    } catch (e) {
      log("[~]", "Entitlements unavailable: " + e);
    }
    if (!objcAvailable() || ObjC.classes.NSBundle === void 0) return out;
    try {
      const bundle = ObjC.classes.NSBundle.mainBundle();
      const info = objcToJs(bundle.infoDictionary(), 5) || {};
      out.bundle = {
        identifier: info.CFBundleIdentifier || null,
        name: info.CFBundleDisplayName || info.CFBundleName || null,
        version: info.CFBundleShortVersionString || null,
        build: info.CFBundleVersion || null,
        executable: info.CFBundleExecutable || null,
        path: objcString(bundle.bundlePath()),
        minimumOS: info.MinimumOSVersion || null
      };
      out.urlTypes = (info.CFBundleURLTypes || []).map((t) => ({
        name: t.CFBundleURLName || null,
        schemes: t.CFBundleURLSchemes || [],
        role: t.CFBundleTypeRole || null
      }));
      out.queriedSchemes = info.LSApplicationQueriesSchemes || [];
      out.userActivityTypes = info.NSUserActivityTypes || [];
      out.documentTypes = (info.CFBundleDocumentTypes || []).map((t) => ({
        name: t.CFBundleTypeName || null,
        types: t.LSItemContentTypes || [],
        role: t.CFBundleTypeRole || null
      }));
      out.exportedTypes = (info.UTExportedTypeDeclarations || []).map((t) => t.UTTypeIdentifier || null);
      out.backgroundModes = info.UIBackgroundModes || [];
      out.supportsDocumentBrowser = Boolean(info.UISupportsDocumentBrowser);
      out.fileSharing = Boolean(info.UIFileSharingEnabled);
      out.openInPlace = Boolean(info.LSSupportsOpeningDocumentsInPlace);
      out.extensions = listExtensions(bundle);
    } catch (e) {
      log("[!]", "Static attack surface failed: " + e);
    }
    return out;
  }
  function installHook(entry) {
    const kind = entry.kind;
    if (kind === "xpc") {
      if (X.xpc_get_type === null) throw new Error("libxpc not loaded");
      return hookXpc(entry);
    }
    if (kind === "notify") return hookNotify(entry);
    if (kind === "nsxpc" || kind === "url" || kind === "objc" || kind === "webview" || kind === "network") {
      if (!objcAvailable()) {
        log("[~]", "Skipping " + describeEntry(entry) + " (Objective-C runtime not available)");
        return false;
      }
      if (kind === "objc") return hookCustomObjC(entry);
      if (kind === "nsxpc" && entry.feature === "connections") return hookNSXPCConnections();
      if (kind === "nsxpc" && entry.feature === "listeners") return hookNSXPCListeners();
      if (kind === "nsxpc" && entry.feature === "replies") {
        decodeReplies = true;
        return true;
      }
      if (kind === "url" && entry.feature === "incoming") return hookUrlIncoming() > 0 || "none";
      if (kind === "url" && entry.feature === "outgoing") return hookUrlOutgoing() > 0 || "none";
      if (kind === "webview" && entry.feature === "bridges") return hookWebBridges() > 0 || "none";
      if (kind === "webview" && entry.feature === "loads") return hookWebLoads() > 0 || "none";
      if (kind === "webview" && entry.feature === "navigation") return hookWebNavigation() > 0 || "none";
      if (kind === "webview" && entry.feature === "schemes") return hookWebSchemes() > 0 || "none";
      if (kind === "network" && entry.feature === "requests") return hookNetworkRequests() > 0 || "none";
    }
    throw new Error("unknown hook definition");
  }
  function describeEntry(entry) {
    return entry.kind + ":" + (entry.function || entry.feature || entry.method || "?");
  }
  function rpcGuard(fn) {
    return function() {
      rpcDepth += 1;
      try {
        return fn.apply(null, arguments);
      } finally {
        rpcDepth -= 1;
      }
    };
  }
  var MAX_EXCEPTION_REPORTS = 3;
  var exceptionReports = 0;
  function installCrashReporter() {
    Process.setExceptionHandler(function(details) {
      if (exceptionReports >= MAX_EXCEPTION_REPORTS) return false;
      exceptionReports += 1;
      try {
        const memory = details.memory || null;
        send({
          ioxenEvent: "crash",
          sequence: exceptionReports,
          pid: Process.id,
          type: details.type,
          address: details.address ? frameLabel(details.address) : null,
          memory: memory ? { operation: memory.operation, address: memory.address.toString() } : null,
          threadId: Process.getCurrentThreadId(),
          stackTrace: captureStack(details.context)
        });
      } catch (_) {
      }
      return false;
    });
  }
  var initialized = false;
  var lastReportedEvents = 0;
  rpc.exports = {
    proxy: rpcGuard(function(hookConfig) {
      if (initialized) return;
      initialized = true;
      send("[*] Initializing iOS IPC hooks");
      const started = Date.now();
      try {
        installCrashReporter();
      } catch (e) {
        log("[~]", "Crash reporting unavailable: " + e);
      }
      initNative();
      if (xpcReady) {
        initApplyBlock();
        initWrapperInvoke();
        hookXpcCreation();
      } else {
        log("[~]", "XPC block support unavailable; XPC message decoding is limited");
      }
      for (const entry of mergeHookEntries(hookConfig)) {
        try {
          const result = installHook(entry);
          if (result === true || typeof result === "number") {
            report.hooks += 1;
            send("[~] Hooked " + describeEntry(entry));
          } else if (result === "none") {
            send("[~] No implementations found for " + describeEntry(entry));
          }
        } catch (e) {
          report.failed += 1;
          log("[!]", "Error registering hook " + describeEntry(entry) + ": " + e);
        }
      }
      send("[+] iOS IPC hooks initialized (" + report.hooks + " active, " + report.failed + " failed, " + (Date.now() - started) + " ms)");
      setInterval(function() {
        const seen = decisions.eventCount();
        if (seen !== lastReportedEvents) {
          send("[agent] " + (seen - lastReportedEvents) + " IPC events in the last 5 s (" + seen + " total)");
          lastReportedEvents = seen;
        }
      }, 5e3);
    }),
    forward: function(decisionId) {
      return decisions.forward(decisionId);
    },
    drop: function(decisionId) {
      return decisions.drop(decisionId);
    },
    stageMod: function(type, key, val, extraType, decisionId) {
      return decisions.stageMod(type, key, val, extraType, decisionId);
    },
    // Returns the id of the decision that was released (or null) so the host
    // can post its wake message.
    interceptoff: function() {
      return decisions.interceptOff();
    },
    intercepton: function() {
      decisions.interceptOn();
    },
    setFilters: function(ignoreList, focusList) {
      return decisions.setFilters(ignoreList, focusList);
    },
    getProcessInfo: rpcGuard(function() {
      const info = { platform: "ios", pid: Process.id, arch: Process.arch, objc: objcAvailable(), xpc: xpcReady };
      try {
        const main = Process.mainModule || Process.enumerateModules()[0];
        info.process = main.name;
      } catch (_) {
      }
      return info;
    }),
    getAttackSurface: rpcGuard(function() {
      return staticAttackSurface();
    })
  };
})();
