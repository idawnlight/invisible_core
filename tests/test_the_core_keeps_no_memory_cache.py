"""The core keeps no value in memory between two calls.

⛔ WHY. A cache that answers instead of the code hides what the code costs: a launch that is slow is slow in a place
nobody can see, because the second call is fast and the first one is measured once. The owner's decision of
2026-11-20 is "all the in-memory caches out of the core, a clean structure to see where to optimise": every call
computes, or reads, the value it returns, and every cost shows in the call that pays it.

WHAT THIS SCANS: every module of ``src/invisible_core``, as syntax, for every shape a memo takes:

  * ``functools.lru_cache`` / ``cache`` / ``cached_property`` (as a decorator or called);
  * ``global NAME`` in a function that then assigns ``NAME``;
  * a dict / list / set of the MODULE written into from inside a function (``NAME[k] = v``, ``NAME.setdefault``,
    ``.update``, ``.append``, ``.add``, ``.pop``, ``.clear`` and the rest, ``del NAME[k]``, ``NAME[k] += v``);
  * a mutable default argument written into (``def f(x, _memo={})``);
  * a class attribute written into from a method (``Class.X = v``, ``cls.X[k] = v``, ``self.X[k] = v`` where ``X`` is a
    class-level container no instance rebinds), which is the same memo with another address;
  * an attribute written on a module-level function (``f._memo = {}``).

A shape that appears is a failure UNLESS it is in :data:`EXCEPTIONS`: one line, ``module:name -> why``. Each
exception holds no value that a later call reads instead of computing; and each one has to be FOUND by the scan, so a
name that is renamed or removed makes this test fail until its line goes too - the list cannot rot.
"""
from __future__ import annotations

import ast
import pathlib
from typing import Dict, List, Set, Tuple

ROOT = pathlib.Path(__file__).resolve().parent.parent / "src" / "invisible_core"

#: module (dotted, relative to invisible_core) : name -> why it is not a memo.
EXCEPTIONS: Dict[str, str] = {
    "_geoip_db:_CHECKED_THIS_PROCESS": "a flag that the database update was looked for once in this process; it answers no call",
    "_geoip_db:_SLOT": "the flight of a download in progress, shared by the callers that ask at the same moment",
    "_intermediates:_WARNED": "the warning is printed once; the list it is about is read from the file on every call",
    "_intermediates:_SLOT": "the flight of a download in progress, shared by the callers that ask at the same moment",
    "_cached_asset:FlightSlot": "the class of those flights: a download in progress, empty once it ends",
    "_geo:_egress_flight": "the request in flight, shared by callers that ask at the same moment; empty once it ends",
    "_geo:_egress_lock": "the lock of the flight above",
    "pin:_REPAIR_ATTEMPTED": "a guard against repairing the same pin twice in a row; it holds no value a caller reads",
    "process:_registry": "the live children of this process, the thing the reaper has to end: state, not a memo",
    "process:_registry_lock": "the lock of the registry above",
    "juggler._pacing:_winmm": "the handle of the Windows timer library, a resource and not a computed value",
    "juggler._pacing:_winmm_tried": "whether the handle was looked for; not a value",
    "juggler._pacing:_timer_period_depth": "how many callers hold the timer period raised: a counter of a resource",
    "release:PKG_NAME": "the command line of the release tool names the package it runs for, once, at its start; nobody reads a computed value",
    "release:DIST_NAME": "same: the name of the distribution the release tool runs for",
    "release:DEFAULT_INDEX_JSON_URL": "same: the index the release tool runs against",
    "testing.world:_INSTALLED": "the pytest plugin of the test world: whether it was installed in this run",
    "testing.world:_MISMARKED": "the pytest plugin of the test world: the tests it reports, not a value any call reads",
    "testing.world:_WORLD": "the test world itself (state of a session under test)",
}

_MUTATORS = frozenset({
    "setdefault", "update", "append", "extend", "insert", "add", "pop", "popitem", "clear", "remove", "discard",
    "__setitem__", "__delitem__", "appendleft", "extendleft", "popleft", "difference_update", "intersection_update",
    "symmetric_difference_update",
})
_CACHE_DECORATORS = frozenset({"lru_cache", "cache", "cached_property"})
_CONTAINER_CALLS = frozenset({
    "dict", "list", "set", "deque", "defaultdict", "OrderedDict", "Counter", "WeakKeyDictionary",
    "WeakValueDictionary", "WeakSet", "bytearray",
})


def _is_container(node: ast.AST) -> bool:
    if isinstance(node, (ast.Dict, ast.List, ast.Set, ast.DictComp, ast.ListComp, ast.SetComp)):
        return True
    if isinstance(node, ast.Call):
        f = node.func
        name = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None
        return name in _CONTAINER_CALLS
    return False


def _target_names(target: ast.AST) -> List[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [n for t in target.elts for n in _target_names(t)]
    if isinstance(target, ast.Starred):
        return _target_names(target.value)
    return []


def _assigned_names(body: ast.AST) -> Set[str]:
    """Names BOUND in a function body (not looking into nested functions or classes), which shadow a module's."""
    out: Set[str] = set()

    def walk(node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                if not isinstance(child, ast.Lambda):
                    out.add(child.name)
                continue
            if isinstance(child, ast.Assign):
                for t in child.targets:
                    out.update(_target_names(t))
            elif isinstance(child, (ast.AnnAssign, ast.AugAssign)):
                out.update(_target_names(child.target))
            elif isinstance(child, (ast.For, ast.AsyncFor)):
                out.update(_target_names(child.target))
            elif isinstance(child, (ast.With, ast.AsyncWith)):
                for item in child.items:
                    if item.optional_vars is not None:
                        out.update(_target_names(item.optional_vars))
            elif isinstance(child, ast.ExceptHandler) and child.name:
                out.add(child.name)
            elif isinstance(child, ast.NamedExpr):
                out.update(_target_names(child.target))
            elif isinstance(child, (ast.Import, ast.ImportFrom)):
                for a in child.names:
                    out.add((a.asname or a.name).split(".")[0])
            elif isinstance(child, ast.comprehension):
                out.update(_target_names(child.target))
            walk(child)

    walk(body)
    return out


def _scan_module(tree: ast.Module) -> List[Tuple[str, int, str]]:
    """(name, line, what) of every memo shape in one module."""
    found: List[Tuple[str, int, str]] = []

    module_containers: Set[str] = set()
    module_functions: Set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Assign) and _is_container(node.value):
            for t in node.targets:
                module_containers.update(_target_names(t))
        elif isinstance(node, ast.AnnAssign) and node.value is not None and _is_container(node.value):
            module_containers.update(_target_names(node.target))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            module_functions.add(node.name)

    # decorators anywhere
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            for dec in node.decorator_list:
                d = dec.func if isinstance(dec, ast.Call) else dec
                name = d.id if isinstance(d, ast.Name) else d.attr if isinstance(d, ast.Attribute) else None
                if name in _CACHE_DECORATORS:
                    found.append((node.name, dec.lineno, "@%s" % name))

    def functions_of(scope: ast.AST, cls: "ast.ClassDef | None" = None):
        for node in ast.iter_child_nodes(scope):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                yield node, cls
                yield from functions_of(node, cls)
            elif isinstance(node, ast.ClassDef):
                yield from functions_of(node, node)
            else:
                yield from functions_of(node, cls)

    def base_name(node: ast.AST) -> "str | None":
        """NAME of NAME, NAME[k], NAME.attr[k]... the root Name of a chain of subscripts."""
        while isinstance(node, ast.Subscript):
            node = node.value
        return node.id if isinstance(node, ast.Name) else None

    for fn, cls in functions_of(tree):
        local = _assigned_names(fn) | {a.arg for a in ast.walk(fn.args) if isinstance(a, ast.arg)}
        globals_declared: Set[str] = set()
        for node in ast.walk(fn):
            if isinstance(node, ast.Global):
                globals_declared.update(node.names)
        local -= globals_declared

        # mutable default arguments written into
        defaults = {}
        positional = fn.args.posonlyargs + fn.args.args
        for arg, dflt in zip(positional[len(positional) - len(fn.args.defaults):], fn.args.defaults):
            defaults[arg.arg] = dflt
        for arg, dflt in zip(fn.args.kwonlyargs, fn.args.kw_defaults):
            if dflt is not None:
                defaults[arg.arg] = dflt
        mutable_defaults = {n for n, d in defaults.items() if _is_container(d)}

        class_level: Set[str] = set()
        class_containers: Set[str] = set()
        rebound_on_instance: Set[str] = set()
        if cls is not None:
            for node in cls.body:
                if isinstance(node, ast.Assign):
                    for t in node.targets:
                        class_level.update(_target_names(t))
                        if _is_container(node.value):
                            class_containers.update(_target_names(t))
                elif isinstance(node, ast.AnnAssign) and node.value is not None:
                    class_level.update(_target_names(node.target))
                    if _is_container(node.value):
                        class_containers.update(_target_names(node.target))
            for node in ast.walk(cls):
                targets = []
                if isinstance(node, ast.Assign):
                    targets = node.targets
                elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
                    targets = [node.target]
                for t in targets:
                    if (isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) and t.value.id == "self"):
                        rebound_on_instance.add(t.attr)
        first_arg = fn.args.args[0].arg if fn.args.args else None
        class_name = cls.name if cls is not None else None

        def is_class_ref(node: ast.AST) -> bool:
            """cls / ClassName / type(self) / self.__class__ in a method of this class."""
            if class_name is None:
                return False
            if isinstance(node, ast.Name):
                return node.id == class_name or (node.id == "cls" and first_arg == "cls")
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "type":
                return True
            return isinstance(node, ast.Attribute) and node.attr == "__class__"

        def shared_container(node: ast.AST) -> "str | None":
            """X when `node` is `<class ref>.X`, or `self.X` of a class-level container no instance rebinds."""
            if not isinstance(node, ast.Attribute):
                return None
            if is_class_ref(node.value) and node.attr in class_level:
                return node.attr
            if (isinstance(node.value, ast.Name) and node.value.id == "self" and node.attr in class_containers
                    and node.attr not in rebound_on_instance):
                return node.attr
            return None

        for node in ast.walk(fn):
            # global NAME ... NAME = v
            targets: List[ast.AST] = []
            if isinstance(node, ast.Assign):
                targets = list(node.targets)
            elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
                targets = [node.target]
            elif isinstance(node, ast.Delete):
                targets = list(node.targets)
            for t in targets:
                for name in _target_names(t):
                    if name in globals_declared:
                        found.append((name, node.lineno, "global %s rebound in %s()" % (name, fn.name)))
                if isinstance(t, ast.Subscript):
                    name = base_name(t)
                    if name in module_containers and name not in local:
                        found.append((name, node.lineno, "%s[...] written in %s()" % (name, fn.name)))
                    elif name in mutable_defaults:
                        found.append((name, node.lineno, "mutable default %s written in %s()" % (name, fn.name)))
                    inner = t.value
                    while isinstance(inner, ast.Subscript):
                        inner = inner.value
                    shared = shared_container(inner)
                    if shared:
                        found.append((shared, node.lineno, "class attribute %s[...] written in %s()" % (shared, fn.name)))
                if isinstance(t, ast.Attribute):
                    if is_class_ref(t.value) and not isinstance(node, ast.Delete):
                        found.append((t.attr, node.lineno, "class attribute %s rebound in %s()" % (t.attr, fn.name)))
                    elif isinstance(t.value, ast.Name) and t.value.id in module_functions and t.value.id not in local:
                        found.append((t.value.id, node.lineno, "attribute .%s written on the function %s" % (t.attr, t.value.id)))
            # NAME.setdefault(...) and the rest
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in _MUTATORS:
                recv = node.func.value
                name = recv.id if isinstance(recv, ast.Name) else None
                if name in module_containers and name not in local:
                    found.append((name, node.lineno, "%s.%s() called in %s()" % (name, node.func.attr, fn.name)))
                elif name in mutable_defaults:
                    found.append((name, node.lineno, "mutable default %s.%s() in %s()" % (name, node.func.attr, fn.name)))
                else:
                    shared = shared_container(recv)
                    if shared:
                        found.append((shared, node.lineno, "class attribute %s.%s() called in %s()"
                                      % (shared, node.func.attr, fn.name)))
    return found


def _module_level_names(tree: ast.Module) -> Set[str]:
    out: Set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(node.name)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                out.update(_target_names(t))
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            out.update(_target_names(node.target))
    return out


def _module_of(path: pathlib.Path) -> str:
    module = ".".join(path.relative_to(ROOT).with_suffix("").parts)
    return module[: -len(".__init__")] if module.endswith(".__init__") else module


def _scan_core() -> Dict[str, List[Tuple[str, int, str]]]:
    out: Dict[str, List[Tuple[str, int, str]]] = {}
    for path in sorted(ROOT.rglob("*.py")):
        module = _module_of(path)
        found = _scan_module(ast.parse(path.read_text(encoding="utf-8"), filename=str(path)))
        if found:
            out[module] = found
    return out


def test_the_core_keeps_no_memory_cache():
    findings = _scan_core()
    unexcused = []
    for module, items in findings.items():
        for name, line, what in items:
            if "%s:%s" % (module, name) not in EXCEPTIONS:
                unexcused.append("%s.py:%d  %s  (%s)" % (module.replace(".", "/"), line, name, what))
    assert not unexcused, (
        "the core keeps a value in memory between two calls (a cache): compute or read it on every call, or, if it holds no "
        "value a later call reads in place of computing it, say so in EXCEPTIONS:\n  " + "\n  ".join(unexcused))


def test_every_exception_is_still_found_by_the_scan():
    defined = {"%s:%s" % (_module_of(path), name)
               for path in ROOT.rglob("*.py")
               for name in _module_level_names(ast.parse(path.read_text(encoding="utf-8")))}
    stale = sorted(key for key in EXCEPTIONS if key not in defined)
    assert not stale, (
        "an exception names something that no longer exists in its module (renamed or removed): delete its line so the "
        "list says only what is true: %s" % stale)


def test_a_removed_memo_does_not_come_back_under_an_exception():
    """The exceptions are for state that holds no value a call reads in place of computing it. These are the names of
    the memos that were taken out (2026-11-20): none of them may be named in the list, nor exist."""
    taken_out = ["_udp_exit:_cache", "_udp_exit:remember", "_geo:_egress_kept", "seal:_ACTIVE", "seal:_IDENT_CACHE",
                 "juggler.keyboard:_CLOSURES", "_webgl_personas:_GPU_POOL_CACHE", "_webgl_personas:_DEVICES_CACHE"]
    defined = {"%s:%s" % (_module_of(path), name)
               for path in ROOT.rglob("*.py")
               for name in _module_level_names(ast.parse(path.read_text(encoding="utf-8")))}
    back = [key for key in taken_out if key in EXCEPTIONS or key in defined]
    assert not back, "a memo that was taken out is back: %s" % back


def test_the_scan_finds_each_shape_it_claims(tmp_path):
    """The scanner on a module of its own, one shape per function: a scan that finds nothing proves nothing."""
    source = '''
import functools
from functools import lru_cache

_D = {}
_L = []
_S = set()
_N = None

@functools.lru_cache(maxsize=1)
def a(): return 1

@lru_cache
def b(): return 1

def c():
    global _N
    _N = 1

def d(k): _D[k] = 1
def e(k): _D.setdefault(k, 1)
def f(k): _L.append(k)
def g(k): _S.add(k)
def h(k): del _D[k]
def i(k, _memo={}): _memo[k] = 1
def j(): j.memo = 1

class K:
    shared = {}
    count = 0
    def __init__(self): self.own = {}
    def m(self, k): self.shared[k] = 1
    @classmethod
    def n(cls, k): cls.count = k
    def o(self, k): K.shared.update({k: 1})
    def p(self, k): self.own[k] = 1

def clean(k):
    local = {}
    local[k] = 1
    _D2 = {}
    return local, _D2
'''
    tree = ast.parse(source)
    names = sorted({(n, w.split()[0]) for n, _l, w in _scan_module(tree)})
    found = {n for n, _w in names}
    assert {"a", "b", "_N", "_D", "_L", "_S", "_memo", "j", "shared", "count"} <= found, names
    assert "clean" not in found and "own" not in found and "local" not in found, names
    assert sum(1 for n, _l, _w in _scan_module(tree) if n == "_D") == 3          # d, e, h
