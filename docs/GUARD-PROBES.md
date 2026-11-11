# File guard: probe routes from the review rounds

The file guard in `acp/gate.py` is a best-effort prototype: an in-process Python audit
hook that runs while a tool body runs. It refuses process starts, lasting registrations
and paths outside the allowed directories, and restores interpreter state after each call.
It is not isolation and not an OS sandbox.

The rows below are the routes the independent judges probed against the guard in review
rounds C13 to C22 (round C14 judged the bench and ran no guard probes). They are judge
probes, not a proof: a route not listed here is untested, not safe. Sources are the
verdict files `VERDICT-paper-C13.md` to `VERDICT-paper-C22.md` and the fix12k report.

Out of scope by design: ctypes, tampering with gate state, object-graph walking (reaching
host objects through references and changing them in place, including the contents of
`sys.modules` and class methods), host-held file handles, and metadata calls (`os.stat`,
`os.access`). Routes in these classes are listed as "out of scope"; a few were fixed anyway.

Columns: `n` is the number of routes a row stands for (1, unless a verdict listed the
routes without a row each); `then` is the outcome when the judge ran it, one of
"refused" (the guard raised and the call did not run), "held" (contained: the route was
put back, or ran with no leak outside the session; also used where a verdict does not
say which of refused or put back), "escaped in scope" or "out of scope"; `fix` names the
merge into `paper-v1.2` and the test that now covers the route; `now` is the outcome at
the current head ("held" rows were not re-run). Re-runs of an earlier round's routes are
not counted again. G030 is a grouped probe: the C15 verdict gives only a count of blocked
routes and no list, so it counts once. Rows marked [named] are reviewer attacks a judge
listed without a run.

Counts, from `python3 tools/guard_probes_count.py docs/GUARD-PROBES.md`:

```
routes_total=140
refused_first_try=76
held_first_try=15
did_not_get_through_first_try=91
escaped_in_scope_then_fixed=34
out_of_scope_then=15
out_of_scope_now=12
```

| id | route | round | n | then | fix | now |
|---|---|---|---|---|---|---|
| G001 | multiprocessing spawn-context Process reads outside | C13 | 1 | escaped in scope | fix12c b2adc506, test_spawned_process_cannot_read_outside | refused |
| G002 | readline.write_history_file writes outside | C13 | 1 | escaped in scope | fix12c b2adc506, test_readline_history_write_outside_refused | refused |
| G003 | os.mkfifo outside | C13 | 1 | escaped in scope | fix12c b2adc506, test_mkfifo_outside_refused | refused |
| G004 | AF_UNIX socket.bind to an outside path | C13 | 1 | escaped in scope | fix12c b2adc506, test_unix_socket_bind_outside_refused | refused |
| G005 | os.chflags outside | C13 | 1 | escaped in scope | fix12c b2adc506, test_chflags_outside_refused | refused |
| G006 | os.access on an outside path (metadata) | C13 | 1 | out of scope | - | out of scope |
| G007 | thread start via closure-cell swap (gate state) | C13 | 1 | out of scope | - | out of scope |
| G008 | multiprocessing fork | C13 | 1 | refused | - | refused |
| G009 | ThreadPoolExecutor | C13 | 1 | refused | - | refused |
| G010 | ctypes | C13 | 1 | refused | - | refused |
| G011 | dbm open outside | C13 | 1 | refused | - | refused |
| G012 | tempfile.mkstemp(dir=outside) | C13 | 1 | refused | - | refused |
| G013 | importlib load from outside | C13 | 1 | refused | - | refused |
| G014 | zipfile outside | C13 | 1 | refused | - | refused |
| G015 | logging.FileHandler outside | C13 | 1 | refused | - | refused |
| G016 | sqlite ATTACH / VACUUM outside | C13 | 1 | refused | - | refused |
| G017 | mmap of an outside file | C13 | 1 | refused | - | refused |
| G018 | PathLike __fspath__ TOCTOU via io.FileIO read | C15 | 1 | escaped in scope | fix12d eee95654, test_pathlike_toctou_fileio_refused | refused |
| G019 | PathLike __fspath__ TOCTOU via io.FileIO write | C15 | 1 | escaped in scope | fix12d eee95654, test_pathlike_toctou_fileio_refused | refused |
| G020 | PathLike __fspath__ TOCTOU via os.mkfifo | C15 | 1 | escaped in scope | fix12d eee95654, test_pathlike_toctou_mkfifo_refused | refused |
| G021 | PathLike __fspath__ TOCTOU via os.mknod | C15 | 1 | escaped in scope | fix12d eee95654, test_pathlike_toctou_mkfifo_refused | refused |
| G022 | symlink to outside | C15 | 1 | refused | - | refused |
| G023 | `..` path | C15 | 1 | refused | - | refused |
| G024 | bytes path | C15 | 1 | refused | - | refused |
| G025 | dir_fd | C15 | 1 | refused | - | refused |
| G026 | os.open | C15 | 1 | refused | - | refused |
| G027 | shutil | C15 | 1 | refused | - | refused |
| G028 | subprocess | C15 | 1 | refused | - | refused |
| G029 | ctypes | C15 | 1 | refused | - | refused |
| G030 | other routes, not named in the verdict ("35 of my own escapes were blocked" minus the 8 above; grouped, counted once) | C15 | 1 | refused | - | refused |
| G031 | deferred signal.setitimer / SIGALRM handler | C16 | 1 | escaped in scope | fix12e 1fecdc81, test_deferred_signal_handler_refused | refused |
| G032 | returned object with __del__ | C16 | 1 | escaped in scope | fix12e 1fecdc81, test_returned_object_del_refused | refused |
| G033 | host-held int fd via fcntl F_GETPATH | C16 | 1 | out of scope | - | out of scope |
| G034 | __index__ fd read | C16 | 1 | refused | - | refused |
| G035 | __index__ dir_fd | C16 | 1 | refused | - | refused |
| G036 | mkfifo with dir_fd | C16 | 1 | refused | - | refused |
| G037 | open(opener=) | C16 | 1 | refused | - | refused |
| G038 | fwalk relative | C16 | 1 | refused | - | refused |
| G039 | sqlite ATTACH | C16 | 1 | refused | - | refused |
| G040 | sqlite VACUUM INTO | C16 | 1 | refused | - | refused |
| G041 | sqlite file: URI | C16 | 1 | refused | - | refused |
| G042 | direct posix import | C16 | 1 | refused | - | refused |
| G043 | unix socket | C16 | 1 | refused | - | refused |
| G044 | E3 os.register_at_fork | C17 | 1 | escaped in scope | fix12f 9ac78c10, test_register_at_fork_refused | refused |
| G045 | E7 sys.set_asyncgen_hooks | C17 | 1 | escaped in scope | fix12f 9ac78c10, test_asyncgen_hooks_restored | refused |
| G046 | E8 root logging handler added | C17 | 1 | out of scope | fix12f 9ac78c10, test_logging_root_handler_restored | refused |
| G047 | E16 sys.path changed | C17 | 1 | out of scope | fix12f 9ac78c10, test_sys_path_environ_restored | refused |
| G048 | E17 os.environ PYTHONPATH changed | C17 | 1 | out of scope | fix12f 9ac78c10, test_sys_path_environ_restored | refused |
| G049 | E4 sys.addaudithook | C17 | 1 | refused | - | refused |
| G050 | E5 threading.Timer | C17 | 1 | refused | - | refused |
| G051 | E9 generator | C17 | 1 | refused | - | refused |
| G052 | E11 setprofile | C17 | 1 | refused | - | refused |
| G053 | E12 atexit re-import | C17 | 1 | refused | - | refused |
| G054 | E13 _signal / setitimer | C17 | 1 | refused | - | refused |
| G055 | E10, E19, E20 (verdict: "ran inside the window and stayed guarded") | C17 | 3 | held | - | held |
| G056 | E1, E1b, E2 __del__ via module global, gc.freeze (verdict: "Allowed, no leak seen") | C17 | 3 | held | - | held |
| G057 | N1 logging.root.addFilter | C18 | 1 | escaped in scope | fix12g f8ed68f2, test_root_filters_restored | refused |
| G058 | N3 PathFinder.find_spec patched (borderline) | C18 | 1 | escaped in scope | fix12g f8ed68f2, test_pathfinder_attrs_restored | refused |
| G059 | N5 setLogRecordFactory (borderline) | C18 | 1 | escaped in scope | fix12g f8ed68f2, test_record_factory_restored | refused |
| G060 | N12 sys.stdout replaced (borderline) | C18 | 1 | escaped in scope | fix12g f8ed68f2, test_std_streams_restored | refused |
| G061 | N2 host handler mutated in place | C18 | 1 | out of scope | - | out of scope |
| G062 | N6 child-logger handler | C18 | 1 | out of scope | - | out of scope |
| G063 | N11 weakref callback in a module global | C18 | 1 | out of scope | - | out of scope |
| G064 | N7 unsetenv | C18 | 1 | refused | - | refused |
| G065 | N8 os.environ rebound | C18 | 1 | refused | - | refused |
| G066 | N9 nested asyncgen | C18 | 1 | refused | - | refused |
| G067 | N10 list-subclass sys.path | C18 | 1 | refused | - | refused |
| G068 | P1 sys.__stdout__ / __stderr__ rebound | C19 | 1 | escaped in scope | fix12h 3caef1de, test_original_std_streams_restored | refused |
| G069 | P3 logging.root rebound | C19 | 1 | escaped in scope | fix12h 3caef1de, test_root_logger_binding_refused_and_restored | refused |
| G070 | P8 sys class swap whose __setattr__ raises | C19 | 1 | escaped in scope | fix12h 3caef1de, test_module_class_swap_raising_setattr | refused |
| G071 | P9 sys.__class__ lying swap with excepthook | C19 | 1 | escaped in scope | fix12h 3caef1de, test_sys_class_swap_lying_refused | refused |
| G072 | P10 logging.__class__ swap with record factory | C19 | 1 | escaped in scope | fix12h 3caef1de, test_logging_class_swap_lying_refused | refused |
| G073 | P12 BuiltinImporter.find_spec patched | C19 | 1 | escaped in scope | fix12h 3caef1de, test_builtin_frozen_importer_attrs_restored | refused |
| G074 | P13 logging.disable | C19 | 1 | escaped in scope | fix12h 3caef1de, test_logging_disable_restored | refused |
| G075 | P2, P4-P7, P11, P14-P16 (verdict: "Restored or refused", not split per route) | C19 | 9 | held | - | held |
| G076 | posixpath class swap, then cross-session read | C20 | 1 | escaped in scope | fix12i eb2a6a4b, test_posixpath_class_swap_then_cross_session_read_refused | refused |
| G077 | builtins class swap | C20 | 1 | escaped in scope | fix12i eb2a6a4b, test_any_module_or_logger_class_swap_restored_and_refused | refused |
| G078 | importlib class swap | C20 | 1 | escaped in scope | fix12i eb2a6a4b, test_any_module_or_logger_class_swap_restored_and_refused | refused |
| G079 | json class swap | C20 | 1 | escaped in scope | fix12i eb2a6a4b, test_any_module_or_logger_class_swap_restored_and_refused | refused |
| G080 | named logger class swap | C20 | 1 | escaped in scope | fix12i eb2a6a4b, test_any_module_or_logger_class_swap_restored_and_refused | refused |
| G081 | class property with a no-op setter hangs the restore loop | C20 | 1 | escaped in scope | fix12i eb2a6a4b, test_noop_setter_property_hits_restore_cap | refused |
| G082 | sys.modules["json"] replaced by a fake | C20 | 1 | out of scope | - | out of scope |
| G083 | Logger.callHandlers patched | C20 | 1 | out of scope | - | out of scope |
| G084 | logging.root class swap | C20 | 1 | refused | - | refused |
| G085 | logging manager class swap | C20 | 1 | refused | - | refused |
| G086 | del sys.excepthook | C20 | 1 | refused | - | refused |
| G087 | del logging.root | C20 | 1 | refused | - | refused |
| G088 | del sys.__stdout__ | C20 | 1 | refused | - | refused |
| G089 | module first imported in the call (colorsys) gets a class swap | C21 | 1 | escaped in scope | fix12j e888402c, test_module_imported_in_body_class_swap_restored_and_refused | refused |
| G090 | logger made in the call gets a class swap | C21 | 1 | escaped in scope | fix12j e888402c, test_logger_made_in_body_class_swap_restored_and_refused | refused |
| G091 | acp.gate._GUARD.allow set to None (gate state) | C21 | 1 | out of scope | - | out of scope |
| G092 | builtins.open = _io.open | C21 | 1 | refused | - | refused |
| G093 | os.open direct | C21 | 1 | refused | - | refused |
| G094 | os.open rebound | C21 | 1 | refused | - | refused |
| G095 | str-subclass path | C21 | 1 | refused | - | refused |
| G096 | PathLike lie | C21 | 1 | refused | - | refused |
| G097 | chdir, then relative path | C21 | 1 | refused | - | refused |
| G098 | symlink | C21 | 1 | refused | - | refused |
| G099 | hardlink | C21 | 1 | refused | - | refused |
| G100 | fake posixpath / os.path in sys.modules | C21 | 1 | refused | - | refused |
| G101 | posixpath swapped and swapped back | C21 | 1 | refused | - | refused |
| G102 | asyncio.run | C21 | 1 | refused | - | refused |
| G103 | asyncio.to_thread | C21 | 1 | refused | - | refused |
| G104 | ThreadPoolExecutor | C21 | 1 | refused | - | refused |
| G105 | io.FileIO | C21 | 1 | refused | - | refused |
| G106 | os.rename | C21 | 1 | refused | - | refused |
| G107 | N1 logger class swapped to PlaceHolder, plus a loggerMap key that reads outside | C22 | 1 | escaped in scope | fix12k 18195909, test_existing_logger_swapped_to_placeholder_restored_and_refused, test_placeholder_with_foreign_loggermap_key_refused | refused |
| G108 | N2 module class swapped to _LazyModule | C22 | 1 | escaped in scope | fix12k 18195909, test_new_module_swapped_to_lazy_module_restored_and_refused | refused |
| G109 | leaked host-held int fds [named] | C22 | 1 | out of scope | - | out of scope |
| G110 | PlaceHolder / LazyLoader objects planted inside loggerDict or sys.modules [named] | C22 | 1 | out of scope | - | out of scope |
| G111 | ctypes or gc walking to host objects [named] | C22 | 1 | out of scope | - | out of scope |
| G112 | dir_fd relative | C22 | 1 | refused | - | refused |
| G113 | hardlink | C22 | 1 | refused | - | refused |
| G114 | rename | C22 | 1 | refused | - | refused |
| G115 | sqlite ATTACH | C22 | 1 | refused | - | refused |
| G116 | sqlite VACUUM INTO | C22 | 1 | refused | - | refused |
| G117 | io.open_code | C22 | 1 | refused | - | refused |
| G118 | import via sys.path from the victim directory | C22 | 1 | refused | - | refused |
| G119 | listdir | C22 | 1 | refused | - | refused |
| G120 | mkstemp | C22 | 1 | refused | - | refused |
| G121 | AF_UNIX bind | C22 | 1 | refused | - | refused |
| G122 | utime | C22 | 1 | refused | - | refused |
| G123 | /private alias | C22 | 1 | refused | - | refused |
| G124 | shutil.copyfile | C22 | 1 | refused | - | refused |
| G125 | mkfifo | C22 | 1 | refused | - | refused |
| G126 | truncate | C22 | 1 | refused | - | refused |
| G127 | chflags | C22 | 1 | refused | - | refused |
| G128 | /dev/fd/0 | C22 | 1 | refused | - | refused |

Not rows: re-runs of earlier rounds (C16 re-ran the C15 routes, C22 re-ran the C21 routes;
all refused) and reviewer notes that are not about the file guard (case-insensitive APFS
session ids; shared authorship of the E1/E2p controls, attacker and oracle).
