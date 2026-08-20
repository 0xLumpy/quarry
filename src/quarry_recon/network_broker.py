"""Linux seccomp user-notification broker for target-facing tool sockets.

The filtered launcher never asks the kernel to continue an intercepted pointer
syscall.  The worker copies the tracee's arguments, authenticates its shared file
table, duplicates the socket with ``pidfd_getfd``, decides the exact peer, and
performs the operation on that duplicate.  This is intentionally Linux-specific
and every missing primitive is an admission refusal.

The module is kept independent of repository publication.  The fixed worker owns
the listener and returns a bounded decision summary to the parent protocol; only
the parent may turn that summary into run evidence.
"""
from __future__ import annotations

import contextlib
import ctypes
import errno
import fcntl
import hashlib
import ipaddress
import json
import math
import os
import platform
import re
import select
import signal
import socket
import stat
import struct
import threading
import time
from dataclasses import dataclass

from .oos_regex import OOSRegexError, compile_oos, oos_search


class NetworkBrokerError(RuntimeError):
    """The kernel authority is unavailable, ambiguous, or failed."""


class NetworkBrokerRefused(NetworkBrokerError):
    """The host or request cannot safely acquire network authority."""


class NetworkEffectFence:
    """Invocation-wide linearization point for cancellation and contact.

    ``cancel()`` returns only after any syscall already inside the fence has
    returned.  Once it returns, no later guarded connect/send/bind/listen can
    start.  Components may poll independently between effects, but they share
    this one epoch and event.
    """

    def __init__(self, event: threading.Event | None = None):
        if event is not None and not isinstance(event, threading.Event):
            raise NetworkBrokerRefused("network_effect_fence_event_invalid")
        self.event = event or threading.Event()
        self._lock = threading.RLock()
        self._closed = False
        self._epoch = 0
        self._sockets: set[socket.socket] = set()
        self._cleanups: dict[int, tuple[object, object, object]] = {}

    def __enter__(self) -> int:
        self._lock.acquire()
        if self._closed or self.event.is_set():
            self._lock.release()
            raise NetworkBrokerRefused("network_effect_fence_closed")
        return self._epoch

    def __exit__(self, _kind, _value, _traceback) -> bool:
        self._lock.release()
        return False

    def is_set(self) -> bool:
        return self._closed or self.event.is_set()

    def set(self) -> None:
        self.cancel()

    def cancel(self) -> None:
        # Wake in-flight nonblocking emulation before waiting for the effect
        # lock it currently owns.  The lock acquisition below is still the
        # linearization point: when cancel() returns, that effect has drained,
        # all tracked data planes are closed, and no later effect can enter.
        self.event.set()
        with self._lock:
            if not self._closed:
                self._closed = True
                self._epoch += 1
            # A nonblocking connect can remain in progress after connect_ex()
            # returns.  Closing every registered data-plane socket while the
            # effect lock is held makes cancellation a boundary, rather than a
            # check-then-effect hint.  Owners still close/unregister in their
            # normal settlement paths; close is deliberately idempotent here.
            failures = []
            for handle in tuple(self._sockets):
                try:
                    handle.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                close_fault = None
                try:
                    handle.close()
                except OSError as exc:
                    close_fault = exc
                try:
                    closed = handle.fileno() < 0
                except OSError:
                    closed = False
                if closed:
                    self._sockets.discard(handle)
                else:
                    failures.append(
                        close_fault
                        or OSError("tracked socket close was not proven"),
                    )
            cancellation = None
            for identity, entry in tuple(self._cleanups.items()):
                closed, close_fault = self._close_cleanup_locked(entry)
                if closed:
                    self._cleanups.pop(identity, None)
                    if (close_fault is not None
                            and not isinstance(close_fault, Exception)
                            and cancellation is None):
                        cancellation = close_fault
                else:
                    failures.append(
                        close_fault
                        or OSError("tracked cleanup was not proven"),
                    )
            if failures:
                raise NetworkBrokerRefused(
                    "network_effect_socket_close_failed",
                ) from failures[0]
            if cancellation is not None:
                raise cancellation

    def track_socket(self, handle: socket.socket) -> None:
        if not isinstance(handle, socket.socket):
            raise NetworkBrokerRefused("network_effect_socket_invalid")
        with self._lock:
            if self._closed or self.event.is_set():
                fault = None
                try:
                    handle.close()
                except OSError as exc:
                    fault = exc
                try:
                    closed = handle.fileno() < 0
                except OSError:
                    closed = False
                if not closed:
                    self._sockets.add(handle)
                    raise NetworkBrokerRefused(
                        "network_effect_socket_close_failed",
                    ) from fault
                raise NetworkBrokerRefused("network_effect_fence_closed")
            self._sockets.add(handle)

    def untrack_socket(self, handle: socket.socket) -> None:
        with self._lock:
            self._sockets.discard(handle)

    @staticmethod
    def _close_cleanup_locked(entry) -> tuple[bool, BaseException | None]:
        _owner, close, closed = entry
        fault = None
        try:
            close()
        except BaseException as exc:
            fault = exc
        try:
            proven = closed() is True
        except BaseException as exc:
            proven = False
            if fault is None:
                fault = exc
        return proven, fault

    def track_cleanup(self, owner: object, *, close, closed) -> None:
        """Register a non-socket OFD owner in the cancellation boundary.

        Worker-listener registries retain a duplicate of the listening OFD.
        Tracking only the component's ``socket`` would therefore let that
        duplicate keep accepting after cancellation.  The close callback and
        independent closure proof remain registered until closure is proven.
        """
        if owner is None or not callable(close) or not callable(closed):
            raise NetworkBrokerRefused("network_effect_cleanup_invalid")
        identity = id(owner)
        entry = (owner, close, closed)
        with self._lock:
            existing = self._cleanups.get(identity)
            if existing is not None and existing[0] is not owner:
                raise NetworkBrokerRefused("network_effect_cleanup_invalid")
            if existing is not None:
                raise NetworkBrokerRefused("network_effect_cleanup_duplicate")
            if self._closed or self.event.is_set():
                proven, fault = self._close_cleanup_locked(entry)
                if not proven:
                    self._cleanups[identity] = entry
                    raise NetworkBrokerRefused(
                        "network_effect_cleanup_close_failed",
                    ) from fault
                if fault is not None and not isinstance(fault, Exception):
                    raise fault
                raise NetworkBrokerRefused("network_effect_fence_closed")
            self._cleanups[identity] = entry

    def close_tracked_cleanup(self, owner: object) -> None:
        """Close and forget one retained OFD only after independent proof."""
        if owner is None:
            raise NetworkBrokerRefused("network_effect_cleanup_invalid")
        identity = id(owner)
        with self._lock:
            entry = self._cleanups.get(identity)
            if entry is None or entry[0] is not owner:
                raise NetworkBrokerRefused("network_effect_cleanup_unowned")
            proven, fault = self._close_cleanup_locked(entry)
            if not proven:
                self.event.set()
                if not self._closed:
                    self._closed = True
                    self._epoch += 1
                raise NetworkBrokerRefused(
                    "network_effect_cleanup_close_failed",
                ) from fault
            self._cleanups.pop(identity, None)
            if fault is not None and not isinstance(fault, Exception):
                raise fault

    def replace_tracked_socket(self, old: socket.socket,
                               new: socket.socket) -> None:
        """Atomically transfer cancellation authority between socket objects.

        ``SSLContext.wrap_socket`` detaches the raw Python socket while keeping
        its kernel fd alive in a new ``SSLSocket``.  Leaving the detached shell
        in this registry would make cancellation close EBADF while TLS I/O kept
        running.  Callers hold the effect fence across wrap+transfer, and this
        method additionally validates that the old object was actually owned.
        """
        if not isinstance(old, socket.socket) or not isinstance(new, socket.socket):
            raise NetworkBrokerRefused("network_effect_socket_invalid")
        with self._lock:
            if old not in self._sockets:
                fault = None
                try:
                    new.close()
                except OSError as exc:
                    fault = exc
                try:
                    closed = new.fileno() < 0
                except OSError:
                    closed = False
                if not closed:
                    self._sockets.add(new)
                    self.event.set()
                    self._closed = True
                    raise NetworkBrokerRefused(
                        "network_effect_socket_close_failed",
                    ) from fault
                raise NetworkBrokerRefused(
                    "network_effect_socket_transfer_unowned",
                )
            self._sockets.discard(old)
            if self._closed or self.event.is_set():
                try:
                    new.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                fault = None
                try:
                    new.close()
                except OSError as exc:
                    fault = exc
                try:
                    closed = new.fileno() < 0
                except OSError:
                    closed = False
                if not closed:
                    self._sockets.add(new)
                    raise NetworkBrokerRefused(
                        "network_effect_socket_close_failed",
                    ) from fault
                raise NetworkBrokerRefused("network_effect_fence_closed")
            self._sockets.add(new)

    def close_tracked_socket(self, handle: socket.socket, *,
                             shutdown: bool = True) -> None:
        """Shutdown/close one data plane before releasing fence ownership."""
        if not isinstance(handle, socket.socket) or type(shutdown) is not bool:
            raise NetworkBrokerRefused("network_effect_socket_invalid")
        with self._lock:
            if shutdown:
                try:
                    handle.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            fault = None
            try:
                handle.close()
            except OSError as exc:
                fault = exc
            try:
                closed = handle.fileno() < 0
            except OSError:
                closed = False
            if not closed:
                self.event.set()
                if not self._closed:
                    self._closed = True
                    self._epoch += 1
                self._sockets.add(handle)
                raise NetworkBrokerRefused(
                    "network_effect_socket_close_failed",
                ) from fault
            self._sockets.discard(handle)

    @contextlib.contextmanager
    def settlement(self):
        """Wait for effects and permit idempotent cleanup after cancellation."""
        with self._lock:
            yield

    @property
    def epoch(self) -> int:
        with self._lock:
            return self._epoch


class _CombinedCancellation:
    """Effect fence shared across components without forfeiting listener HUP."""

    def __init__(self, local: threading.Event, shared: threading.Event):
        self._local = local
        self._shared = shared

    def is_set(self) -> bool:
        return self._local.is_set() or self._shared.is_set()

    def set(self) -> None:
        self._local.set()
        self._shared.set()


_PR_SET_NO_NEW_PRIVS = 38
_PR_SET_CHILD_SUBREAPER = 36
_PR_GET_CHILD_SUBREAPER = 37
_PR_GET_DUMPABLE = 3
_PR_SET_DUMPABLE = 4
_SECCOMP_SET_MODE_FILTER = 1
_SECCOMP_FILTER_FLAG_NEW_LISTENER = 1 << 3
_SECCOMP_RET_KILL_PROCESS = 0x80000000
_SECCOMP_RET_ERRNO = 0x00050000
_SECCOMP_RET_USER_NOTIF = 0x7FC00000
_SECCOMP_RET_ALLOW = 0x7FFF0000
_AUDIT_ARCH_X86_64 = 0xC000003E
_AUDIT_ARCH_AARCH64 = 0xC00000B7
_X32_SYSCALL_BIT = 0x40000000
_KCMP_FILE = 0
_KCMP_FILES = 2
_SO_PROTOCOL = 38
_SO_DOMAIN = 39
_AF_XDP = 44
_MAX_SOCKADDR_BYTES = 256
_MAX_PROC_STATUS_BYTES = 64 * 1024
_MAX_DECISIONS = 1024
_MAX_RECORD_BYTES = 1024
# Component-local bound.  The backend remains incomplete until these finite
# rows are streamed to a trusted invocation artifact whose compact digest fits
# the separate 64-KiB durable settlement row.
_MAX_DECISION_SUMMARY_BYTES = _MAX_DECISIONS * (_MAX_RECORD_BYTES + 1)
_MAX_SEND_BYTES = 1024 * 1024
_MAX_IOVECTORS = 1024
_MAX_CONTROL_BYTES = 64 * 1024
_MAX_RIGHTS_FDS = 16
_MAX_INHERITED_FDS = 4096
_MAX_REAPED_DESCENDANTS = 4096
_MAX_CONTROL_GRANTS = 1024
# Aggregate envelope: at most 16 concurrent operations can hold a copied
# 1-MiB payload and its ctypes mirror (32 MiB total), or 16 SCM_RIGHTS
# duplicates each (256 descriptors total).  These products, rather than only
# per-notification ceilings, are the supported invocation resource contract.
_MAX_NOTIFICATION_WORKERS = 16
_BROKER_SETTLEMENT_SECONDS = 2.0
_MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024
_MAX_EXECUTABLE_HASH_SECONDS = 5.0
_MSG_ZEROCOPY = 0x04000000
_MSG_FASTOPEN = 0x20000000
_SCM_RIGHTS = 1
_SCM_CREDENTIALS = 2
_SCM_PIDFD = 4
_CMSG_HEADER = struct.Struct("=Qii")
_HANDOFF = struct.Struct("!4sBBI")
_HANDOFF_MAGIC = b"QNB1"
_HANDOFF_VERSION = 1
_HANDOFF_CLOSED = b"SC1!"
_HANDOFF_ACK = b"G"
_DNS_MEDIATOR_TCP_AUTH_MAGIC = b"QDT1"
_DNS_MEDIATOR_UDP_PERSISTENT_AUTH_MAGIC = b"QDP1"
_DNS_MEDIATOR_UDP_QUERY_AUTH_MAGIC = b"QDQ1"
_DNS_MEDIATOR_AUTH_BYTES = 32

# DNS wire values which the target-DNS doors can originate.  These are source
# identities, not a user-configurable query vocabulary.
_DNS_QTYPE_A = 1
_DNS_QTYPE_NS = 2
_DNS_QTYPE_CNAME = 5
_DNS_QTYPE_SOA = 6
_DNS_QTYPE_PTR = 12
_DNS_QTYPE_MX = 15
_DNS_QTYPE_TXT = 16
_DNS_QTYPE_AAAA = 28
_DNS_QTYPE_CAA = 257
_DNS_EMPTY_OPT = struct.Struct("!BHHIH")
_DNS_EMPTY_OPT_UDP_SIZE = 4096
_DNS_SOURCE_QTYPES = {
    "dns.dnsx_records": frozenset({
        _DNS_QTYPE_A, _DNS_QTYPE_AAAA, _DNS_QTYPE_CNAME, _DNS_QTYPE_MX,
        _DNS_QTYPE_NS, _DNS_QTYPE_TXT, _DNS_QTYPE_SOA, _DNS_QTYPE_CAA,
    }),
    "enrich.dnsx_resolve": frozenset({_DNS_QTYPE_A}),
    "enrich.dnsx_cname": frozenset({_DNS_QTYPE_A, _DNS_QTYPE_CNAME}),
    "horizontal.revdns": frozenset({_DNS_QTYPE_PTR}),
    "vertical.puredns_brute": frozenset({_DNS_QTYPE_A}),
    "vertical.puredns_resolve": frozenset({_DNS_QTYPE_A}),
    "enrich.a1d_brute": frozenset({_DNS_QTYPE_A}),
    "osint.dmarc": frozenset({_DNS_QTYPE_TXT}),
}
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_SOURCE = re.compile(r"[a-z0-9][a-z0-9_.-]{0,127}\Z")
_CHROMIUM_SINGLETON_DIR = re.compile(
    r"org\.chromium\.Chromium\.[A-Za-z0-9_-]{6,32}\Z",
)
_SINGLETON_BIND_ATTEMPTS = 4
_PROFILE_IDS = {"standard": 1, "browser": 2}
_PROFILES_BY_ID = {value: key for key, value in _PROFILE_IDS.items()}


@dataclass(frozen=True)
class _Architecture:
    audit: int
    seccomp: int
    pidfd_getfd: int
    process_vm_readv: int
    process_vm_writev: int
    kcmp: int
    socket: int
    socketpair: int
    connect: int
    sendto: int
    sendmsg: int
    sendmmsg: int
    bind: int
    listen: int
    accept: int
    accept4: int
    setsockopt: int
    io_uring_setup: int
    io_uring_enter: int
    io_uring_register: int
    bpf: int
    prctl: int
    ptrace: int
    userfaultfd: int
    kill: int
    tkill: int
    tgkill: int
    rt_sigqueueinfo: int
    rt_tgsigqueueinfo: int
    pidfd_send_signal: int


_ARCHITECTURES = {
    "x86_64": _Architecture(
        _AUDIT_ARCH_X86_64, 317, 438, 310, 311, 312,
        41, 53, 42, 44, 46, 307, 49, 50, 43, 288, 54,
        425, 426, 427, 321, 157, 101, 323,
        62, 200, 234, 129, 297, 424,
    ),
    "aarch64": _Architecture(
        _AUDIT_ARCH_AARCH64, 277, 438, 270, 271, 272,
        198, 199, 203, 206, 211, 269, 200, 201, 202, 242, 208,
        425, 426, 427, 280, 167, 117, 282,
        129, 130, 131, 138, 240, 424,
    ),
}


def _architecture() -> _Architecture:
    if os.name != "posix" or platform.system() != "Linux":
        raise NetworkBrokerRefused("network_broker_platform_unsupported")
    machine = platform.machine().lower()
    if machine != "x86_64":
        raise NetworkBrokerRefused("network_broker_architecture_unattested")
    architecture = _ARCHITECTURES.get(machine)
    if architecture is None:
        raise NetworkBrokerRefused("network_broker_architecture_unsupported")
    return architecture


class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_ushort),
        ("filters", ctypes.POINTER(_SockFilter)),
    ]


class _SeccompData(ctypes.Structure):
    _fields_ = [
        ("nr", ctypes.c_int),
        ("arch", ctypes.c_uint32),
        ("instruction_pointer", ctypes.c_uint64),
        ("args", ctypes.c_uint64 * 6),
    ]


class _SeccompNotif(ctypes.Structure):
    _fields_ = [
        ("id", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("data", _SeccompData),
    ]


class _SeccompNotifResp(ctypes.Structure):
    _fields_ = [
        ("id", ctypes.c_uint64),
        ("val", ctypes.c_int64),
        ("error", ctypes.c_int32),
        ("flags", ctypes.c_uint32),
    ]


class _IOVec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("length", ctypes.c_size_t)]


class _MsgHdr(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_void_p),
        ("name_length", ctypes.c_uint32),
        ("iov", ctypes.POINTER(_IOVec)),
        ("iov_length", ctypes.c_size_t),
        ("control", ctypes.c_void_p),
        ("control_length", ctypes.c_size_t),
        ("flags", ctypes.c_int),
    ]


def _ioc(direction: int, kind: int, number: int, size: int) -> int:
    # Linux asm-generic ioctl layout used by both supported architectures.
    if not 0 <= size < (1 << 14):
        raise NetworkBrokerRefused("network_broker_ioctl_size_invalid")
    return (direction << 30) | (size << 16) | (kind << 8) | number


_SECCOMP_IOCTL_NOTIF_RECV = _ioc(
    3, ord("!"), 0, ctypes.sizeof(_SeccompNotif),
)
_SECCOMP_IOCTL_NOTIF_SEND = _ioc(
    3, ord("!"), 1, ctypes.sizeof(_SeccompNotifResp),
)
_SECCOMP_IOCTL_NOTIF_ID_VALID = _ioc(1, ord("!"), 2, 8)


_BPF_LD_W_ABS = 0x20
_BPF_JMP_JEQ_K = 0x15
_BPF_JMP_JSET_K = 0x45
_BPF_ALU_AND_K = 0x54
_BPF_RET_K = 0x06


def _filter_program(architecture: _Architecture, *, profile: str = "standard"):
    """Build the fixed forward-only cBPF program with resolved labels."""
    if profile not in {"standard", "browser"}:
        raise NetworkBrokerRefused("network_broker_filter_profile_invalid")
    browser = profile == "browser"
    allow = _SECCOMP_RET_ALLOW
    refuse = _SECCOMP_RET_ERRNO | errno.EPERM
    notify = _SECCOMP_RET_USER_NOTIF
    instructions: list[_SockFilter] = []
    labels: dict[str, int] = {}
    jumps: list[tuple[int, str | None, str | None]] = []

    def label(name: str) -> None:
        if name in labels:
            raise NetworkBrokerRefused("network_broker_filter_label_duplicate")
        labels[name] = len(instructions)

    def statement(code: int, value: int) -> None:
        instructions.append(_SockFilter(code, 0, 0, value))

    def jump(code: int, value: int, yes: str | None, no: str | None) -> None:
        jumps.append((len(instructions), yes, no))
        instructions.append(_SockFilter(code, 0, 0, value))

    statement(_BPF_LD_W_ABS, 4)
    jump(_BPF_JMP_JEQ_K, architecture.audit, "load_nr", "kill")
    label("load_nr")
    statement(_BPF_LD_W_ABS, 0)
    jump(_BPF_JMP_JSET_K, _X32_SYSCALL_BIT, "kill", "socket_gate")
    label("socket_gate")
    jump(_BPF_JMP_JEQ_K, architecture.socket, "socket_domain", "socketpair_gate")
    label("socket_domain")
    statement(_BPF_LD_W_ABS, 16)
    jump(_BPF_JMP_JEQ_K, socket.AF_INET, "inet_socket_type", "socket_domain_v6")
    label("socket_domain_v6")
    jump(_BPF_JMP_JEQ_K, socket.AF_INET6, "inet_socket_type", "socket_domain_unix")
    label("socket_domain_unix")
    jump(_BPF_JMP_JEQ_K, socket.AF_UNIX, "unix_socket_type", "socket_domain_netlink")
    label("socket_domain_netlink")
    # Route-netlink compatibility was explored, but no accepted runtime lane
    # requires it.  Denying creation is substantially narrower than trying to
    # infer read-only intent from mutable netlink messages.
    jump(_BPF_JMP_JEQ_K, socket.AF_NETLINK, "deny", "deny")

    label("inet_socket_type")
    statement(_BPF_LD_W_ABS, 24)
    statement(_BPF_ALU_AND_K, 0xF)
    jump(
        _BPF_JMP_JEQ_K, socket.SOCK_STREAM,
        "inet_stream_protocol", "inet_socket_dgram",
    )
    label("inet_stream_protocol")
    statement(_BPF_LD_W_ABS, 32)
    jump(_BPF_JMP_JEQ_K, 0, "allow", "inet_stream_protocol_tcp")
    label("inet_stream_protocol_tcp")
    jump(_BPF_JMP_JEQ_K, socket.IPPROTO_TCP, "allow", "deny")
    label("inet_socket_dgram")
    jump(
        _BPF_JMP_JEQ_K, socket.SOCK_DGRAM,
        "deny" if browser else "inet_dgram_protocol", "deny",
    )
    if not browser:
        label("inet_dgram_protocol")
        statement(_BPF_LD_W_ABS, 32)
        jump(_BPF_JMP_JEQ_K, 0, "allow", "inet_dgram_protocol_udp")
        label("inet_dgram_protocol_udp")
        jump(_BPF_JMP_JEQ_K, socket.IPPROTO_UDP, "allow", "deny")

    label("unix_socket_type")
    statement(_BPF_LD_W_ABS, 24)
    statement(_BPF_ALU_AND_K, 0xF)
    jump(_BPF_JMP_JEQ_K, socket.SOCK_STREAM, "allow", "unix_socket_dgram")
    label("unix_socket_dgram")
    jump(
        _BPF_JMP_JEQ_K, socket.SOCK_DGRAM,
        "deny" if browser else "allow", "unix_socket_seqpacket",
    )
    label("unix_socket_seqpacket")
    jump(_BPF_JMP_JEQ_K, socket.SOCK_SEQPACKET, "allow", "deny")

    label("socketpair_gate")
    jump(_BPF_JMP_JEQ_K, architecture.socketpair, "socketpair_domain", "setsockopt_gate")
    label("socketpair_domain")
    statement(_BPF_LD_W_ABS, 16)
    jump(_BPF_JMP_JEQ_K, socket.AF_UNIX, "socketpair_type", "deny")
    label("socketpair_type")
    statement(_BPF_LD_W_ABS, 24)
    statement(_BPF_ALU_AND_K, 0xF)
    jump(_BPF_JMP_JEQ_K, socket.SOCK_STREAM, "allow", "socketpair_dgram")
    label("socketpair_dgram")
    jump(
        _BPF_JMP_JEQ_K, socket.SOCK_DGRAM,
        "deny" if browser else "allow", "socketpair_seqpacket",
    )
    label("socketpair_seqpacket")
    jump(_BPF_JMP_JEQ_K, socket.SOCK_SEQPACKET, "allow", "deny")

    # Scalar level/option values cannot be pointer-raced.  Block source-route
    # and header-inclusion options while preserving ordinary TCP/socket tuning.
    label("setsockopt_gate")
    jump(_BPF_JMP_JEQ_K, architecture.setsockopt, "setsockopt_level", "prctl_gate")
    label("setsockopt_level")
    statement(_BPF_LD_W_ABS, 24)
    jump(_BPF_JMP_JEQ_K, socket.IPPROTO_IP, "setsockopt_ip", "setsockopt_ipv6_level")
    label("setsockopt_ip")
    statement(_BPF_LD_W_ABS, 32)
    for index, option in enumerate((3, 4, 5)):
        next_label = f"setsockopt_ip_{index}"
        jump(_BPF_JMP_JEQ_K, option, "deny", next_label)
        label(next_label)
    jump(_BPF_JMP_JEQ_K, 0xFFFFFFFF, "deny", "allow")
    label("setsockopt_ipv6_level")
    jump(_BPF_JMP_JEQ_K, socket.IPPROTO_IPV6, "setsockopt_ipv6", "allow")
    label("setsockopt_ipv6")
    statement(_BPF_LD_W_ABS, 32)
    for index, option in enumerate((6, 54, 55, 57, 59)):
        next_label = f"setsockopt_ipv6_{index}"
        jump(_BPF_JMP_JEQ_K, option, "deny", next_label)
        label(next_label)
    jump(_BPF_JMP_JEQ_K, 0xFFFFFFFF, "deny", "allow")

    # A later ordinary filter is strictly additive: it cannot weaken this
    # inherited USER_NOTIF action.  The dangerous case is a newer listener,
    # because the kernel routes a notification to the newest matching listener.
    # Preserve Chromium's sandbox filters while refusing that exact authority.
    label("prctl_gate")
    jump(_BPF_JMP_JEQ_K, architecture.prctl, "allow", "seccomp_gate")
    label("seccomp_gate")
    jump(_BPF_JMP_JEQ_K, architecture.seccomp, "seccomp_operation", "sendmsg_gate")
    label("seccomp_operation")
    statement(_BPF_LD_W_ABS, 16)
    jump(
        _BPF_JMP_JEQ_K, _SECCOMP_SET_MODE_FILTER,
        "seccomp_filter_flags", "allow",
    )
    label("seccomp_filter_flags")
    statement(_BPF_LD_W_ABS, 24)
    jump(
        _BPF_JMP_JSET_K, _SECCOMP_FILTER_FLAG_NEW_LISTENER,
        "deny", "allow",
    )

    label("sendmsg_gate")
    if browser:
        jump(_BPF_JMP_JEQ_K, architecture.sendmsg, "sendmsg_flags", "sendto_gate")
        label("sendmsg_flags")
        # sendmsg(2) takes an int, but retain the broker's exact scalar
        # rejection of non-canonical high register bits before going native.
        statement(_BPF_LD_W_ABS, 36)
        jump(_BPF_JMP_JEQ_K, 0, "sendmsg_flags_low", "deny")
        label("sendmsg_flags_low")
        statement(_BPF_LD_W_ABS, 32)
        # Browser-profile socket creation admits only connection-oriented
        # INET streams and AF_UNIX streams/seqpackets.  Their peer is fixed by
        # mediated connect/accept (or the attested inherited descriptor set):
        # msg_name cannot retarget them, and an unconnected stream cannot send.
        # Execute on the tracee's OFD so Unix peer credentials and SCM_RIGHTS
        # retain their real sender identity.  Browser Unix peers are confined
        # descendants under this same inherited filter; named/abstract outside
        # peers and inherited transports are refused.  SCM_RIGHTS therefore
        # only redistributes that confined descriptor set.  The standard
        # profile, which can create datagrams, still mediates every sendmsg.
        jump(
            _BPF_JMP_JSET_K,
            _MSG_FASTOPEN | _MSG_ZEROCOPY | 0x80000000,
            "deny", "allow",
        )

        # Chromium's sandbox and Mojo IPC use destination-less sendto() at high
        # volume.  The only IP stream peers a browser-profile process can
        # possess are mediated connect() peers or the request-owned accepted
        # DevTools channel.  Let that exact connected data-plane shape execute
        # on the tracee's OFD; any sockaddr remains a notification.
        label("sendto_gate")
        jump(
            _BPF_JMP_JEQ_K, architecture.sendto,
            "sendto_flags", "deny_syscalls",
        )
        label("sendto_flags")
        statement(_BPF_LD_W_ABS, 40)
        jump(_BPF_JMP_JSET_K, _MSG_FASTOPEN, "deny", "sendto_pointer_low")
        label("sendto_pointer_low")
        statement(_BPF_LD_W_ABS, 48)
        jump(_BPF_JMP_JEQ_K, 0, "sendto_pointer_high", "notify")
        label("sendto_pointer_high")
        statement(_BPF_LD_W_ABS, 52)
        jump(_BPF_JMP_JEQ_K, 0, "sendto_length_low", "notify")
        label("sendto_length_low")
        statement(_BPF_LD_W_ABS, 56)
        jump(_BPF_JMP_JEQ_K, 0, "sendto_length_high", "notify")
        label("sendto_length_high")
        statement(_BPF_LD_W_ABS, 60)
        jump(_BPF_JMP_JEQ_K, 0, "allow", "notify")

    label("deny_syscalls")
    # Reload nr after inspecting scalar syscall arguments above.
    statement(_BPF_LD_W_ABS, 0)
    denied = (
        architecture.io_uring_setup, architecture.io_uring_enter,
        architecture.io_uring_register,
        architecture.bpf, architecture.pidfd_getfd,
        architecture.process_vm_readv, architecture.process_vm_writev,
        architecture.ptrace, architecture.userfaultfd,
        architecture.sendmmsg,
        architecture.kill, architecture.tkill, architecture.tgkill,
        architecture.rt_sigqueueinfo, architecture.rt_tgsigqueueinfo,
        architecture.pidfd_send_signal,
    )
    for index, number in enumerate(denied):
        next_label = f"deny_syscall_{index}"
        jump(_BPF_JMP_JEQ_K, number, "deny", next_label)
        label(next_label)
    notified = (
        architecture.connect,
        *((architecture.sendto,) if not browser else ()),
        *((architecture.sendmsg,) if not browser else ()),
        architecture.bind, architecture.listen,
        architecture.accept, architecture.accept4,
    )
    for index, number in enumerate(notified):
        next_label = f"notify_syscall_{index}"
        jump(_BPF_JMP_JEQ_K, number, "notify", next_label)
        label(next_label)
    jump(_BPF_JMP_JEQ_K, 0xFFFFFFFF, "deny", "allow")

    label("kill")
    statement(_BPF_RET_K, _SECCOMP_RET_KILL_PROCESS)
    label("deny")
    statement(_BPF_RET_K, refuse)
    label("notify")
    statement(_BPF_RET_K, notify)
    label("allow")
    statement(_BPF_RET_K, allow)

    for index, yes, no in jumps:
        offsets = []
        for destination in (yes, no):
            if destination is None:
                offsets.append(0)
                continue
            if destination not in labels:
                raise NetworkBrokerRefused("network_broker_filter_label_missing")
            offset = labels[destination] - index - 1
            if not 0 <= offset <= 255:
                raise NetworkBrokerRefused("network_broker_filter_jump_invalid")
            offsets.append(offset)
        instructions[index].jt, instructions[index].jf = offsets
    array = (_SockFilter * len(instructions))(*instructions)
    return array, _SockFprog(len(instructions), array)


def _libc():
    library = ctypes.CDLL(None, use_errno=True)
    if not all(hasattr(library, name) for name in ("syscall", "prctl", "ioctl")):
        raise NetworkBrokerRefused("network_broker_libc_api_unavailable")
    return library


def acquire_worker_subreaper() -> None:
    """Make the single-purpose runner worker the proved descendant reaper.

    This must run before the parked launcher can exec or fork descendants.
    Without it, a double-forked tool child is reparented outside the worker and
    Yama can revoke the broker's ``pidfd_getfd``/``process_vm_readv`` authority
    while the child still owns the inherited notification filter.
    """
    library = _libc()
    ctypes.set_errno(0)
    if library.prctl(_PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise NetworkBrokerRefused(
            "network_broker_subreaper_acquisition_failed",
        ) from OSError(error, os.strerror(error))
    observed = ctypes.c_int(-1)
    ctypes.set_errno(0)
    if library.prctl(
            _PR_GET_CHILD_SUBREAPER, ctypes.byref(observed), 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise NetworkBrokerRefused(
            "network_broker_subreaper_proof_failed",
        ) from OSError(error, os.strerror(error))
    if observed.value != 1:
        raise NetworkBrokerRefused("network_broker_subreaper_proof_failed")


def seal_worker_identity() -> None:
    """Make the broker unreadable by same-UID tracees before launcher ACK.

    The worker remains the tracees' parent/subreaper and therefore retains the
    kernel authority it needs over dumpable descendants.  Making the *worker*
    non-dumpable closes the inverse ``/proc/<worker>/{mem,fd}`` attack without
    granting the target a ptrace exception or capability.
    """
    library = _libc()
    ctypes.set_errno(0)
    if library.prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise NetworkBrokerRefused(
            "network_broker_worker_dumpability_seal_failed",
        ) from OSError(error, os.strerror(error))
    ctypes.set_errno(0)
    observed = library.prctl(_PR_GET_DUMPABLE, 0, 0, 0, 0)
    if observed != 0:
        if observed < 0:
            error = ctypes.get_errno()
            cause = OSError(error, os.strerror(error))
        else:
            cause = None
        raise NetworkBrokerRefused(
            "network_broker_worker_dumpability_proof_failed",
        ) from cause


def reap_adopted_descendants(*, launcher_reaped: bool,
                             deadline_monotonic: float) -> tuple[tuple[int, int], ...]:
    """Boundedly reap all adopted descendants after containment is empty.

    The caller must first reap the authenticated direct launcher and prove its
    cgroup task set empty.  A live adopted child at the deadline is therefore a
    settlement failure, never a silently detached daemon.
    """
    if launcher_reaped is not True or type(deadline_monotonic) not in {int, float}:
        raise NetworkBrokerRefused("network_broker_descendant_reap_precondition_failed")
    if not math.isfinite(deadline_monotonic):
        raise NetworkBrokerRefused("network_broker_descendant_reap_precondition_failed")
    observed = ctypes.c_int(-1)
    library = _libc()
    ctypes.set_errno(0)
    if library.prctl(
            _PR_GET_CHILD_SUBREAPER, ctypes.byref(observed), 0, 0, 0) != 0 \
            or observed.value != 1:
        raise NetworkBrokerRefused("network_broker_subreaper_proof_failed")
    reaped: list[tuple[int, int]] = []
    while True:
        try:
            pid, status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return tuple(reaped)
        except InterruptedError:
            continue
        if pid > 0:
            reaped.append((pid, status))
            if len(reaped) > _MAX_REAPED_DESCENDANTS:
                raise NetworkBrokerRefused(
                    "network_broker_descendant_reap_bound_exceeded",
                )
            continue
        remaining = deadline_monotonic - time.monotonic()
        if remaining <= 0:
            raise NetworkBrokerRefused(
                "network_broker_descendant_reap_incomplete",
            )
        time.sleep(min(0.01, remaining))


def _syscall(library, number: int, *args) -> int:
    ctypes.set_errno(0)
    result = library.syscall(number, *args)
    if result < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return int(result)


def install_listener(*, profile: str = "standard") -> int:
    """Install the fixed inherited filter in the calling launcher."""
    architecture = _architecture()
    _refuse_privileged_process()
    library = _libc()
    ctypes.set_errno(0)
    if library.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise NetworkBrokerRefused("network_broker_no_new_privs_failed") from OSError(
            error, os.strerror(error),
        )
    filters, program = _filter_program(architecture, profile=profile)
    try:
        listener = _syscall(
            library, architecture.seccomp, _SECCOMP_SET_MODE_FILTER,
            _SECCOMP_FILTER_FLAG_NEW_LISTENER, ctypes.byref(program),
        )
        # Keep the ctypes instruction array alive through the syscall.
        del filters
    except OSError as exc:
        raise NetworkBrokerRefused("network_broker_listener_install_failed") from exc
    try:
        _validate_listener_fd(listener)
    except BaseException:
        os.close(listener)
        raise
    return listener


def _refuse_privileged_process() -> None:
    if os.geteuid() == 0 or os.getegid() == 0:
        raise NetworkBrokerRefused("network_broker_privileged_identity_refused")
    try:
        body = _read_bounded_file("/proc/self/status", _MAX_PROC_STATUS_BYTES)
    except OSError as exc:
        raise NetworkBrokerRefused("network_broker_capability_snapshot_failed") from exc
    capability_lines = {}
    for line in body.splitlines():
        name, separator, value = line.partition(":")
        if separator and name in {"CapInh", "CapPrm", "CapEff", "CapAmb"}:
            if name in capability_lines:
                raise NetworkBrokerRefused("network_broker_capability_snapshot_invalid")
            capability_lines[name] = value.strip()
    if set(capability_lines) != {"CapInh", "CapPrm", "CapEff", "CapAmb"}:
        raise NetworkBrokerRefused("network_broker_capability_snapshot_invalid")
    try:
        capabilities = tuple(int(capability_lines[name], 16)
                             for name in ("CapInh", "CapPrm", "CapEff", "CapAmb"))
    except ValueError as exc:
        raise NetworkBrokerRefused("network_broker_capability_snapshot_invalid") from exc
    # Inheritable/permitted/effective/ambient authority can regain packet/BPF
    # capabilities, ptrace the broker, or mutate routing.  CapBnd is not called
    # empty here: ordinary unprivileged launchers cannot drop it.  It is inert
    # only under NNP plus the profile's namespace/mount isolation, which is a
    # separate preflight gate before this backend may be enabled.
    if any(capabilities):
        raise NetworkBrokerRefused("network_broker_capability_set_not_empty")


def _attest_inherited_fds(expected_fds, *, control_fds=(),
                          exec_pipe_fds=()) -> None:
    """Require the fixed launcher's exact regular/pipe descriptor graph."""
    try:
        expected = tuple(expected_fds)
        controls = tuple(control_fds)
        inherited_pipes = dict(exec_pipe_fds)
    except TypeError as exc:
        raise NetworkBrokerRefused(
            "network_broker_inherited_fd_allowlist_invalid",
        ) from exc
    if (not expected or len(expected) > _MAX_INHERITED_FDS
            or any(type(fd) is not int or fd < 0 for fd in expected)
            or len(set(expected)) != len(expected)
            or any(fd not in expected for fd in controls)
            or len(set(controls)) != len(controls)
            or any(type(fd) is not int or fd not in expected
                   for fd in inherited_pipes)
            or set(controls) & set(inherited_pipes)):
        raise NetworkBrokerRefused(
            "network_broker_inherited_fd_allowlist_invalid",
        )
    try:
        names = os.listdir("/proc/self/fd")
    except OSError as exc:
        raise NetworkBrokerRefused(
            "network_broker_inherited_fd_snapshot_failed",
        ) from exc
    numeric: dict[int, tuple[os.stat_result, str]] = {}
    for name in names:
        if not name.isascii() or not name.isdecimal():
            raise NetworkBrokerRefused(
                "network_broker_inherited_fd_snapshot_invalid",
            )
        fd = int(name)
        if fd in numeric or len(numeric) >= _MAX_INHERITED_FDS:
            raise NetworkBrokerRefused(
                "network_broker_inherited_fd_snapshot_invalid",
            )
        try:
            observed = os.fstat(fd)
            target = os.readlink(f"/proc/self/fd/{fd}")
        except OSError as exc:
            # os.listdir's own procfs descriptor can be present in the returned
            # names after it has already been closed.  The launcher is
            # single-threaded here, so EBADF/ENOENT has no attacker race.
            if exc.errno in {errno.EBADF, errno.ENOENT} and fd not in expected:
                continue
            raise NetworkBrokerRefused(
                "network_broker_inherited_fd_snapshot_failed",
            ) from exc
        numeric[fd] = (observed, target)
    if set(numeric) != set(expected):
        raise NetworkBrokerRefused(
            "network_broker_inherited_fd_allowlist_mismatch",
        )
    for fd, (observed, target) in numeric.items():
        if stat.S_ISSOCK(observed.st_mode) or target.startswith("anon_inode:"):
            raise NetworkBrokerRefused(
                "network_broker_inherited_transport_authority_refused",
            )
        if fd in controls or fd in inherited_pipes:
            if not stat.S_ISFIFO(observed.st_mode) or not target.startswith("pipe:["):
                raise NetworkBrokerRefused(
                    "network_broker_inherited_control_fd_invalid",
                )
            descriptor_flags = fcntl.fcntl(fd, fcntl.F_GETFD)
            if fd in controls and not descriptor_flags & fcntl.FD_CLOEXEC:
                raise NetworkBrokerRefused(
                    "network_broker_inherited_control_fd_invalid",
                )
            if fd in inherited_pipes:
                expected_access, expected_dev, expected_ino = inherited_pipes[fd]
                if (descriptor_flags & fcntl.FD_CLOEXEC
                        or fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE
                        != expected_access
                        or (observed.st_dev, observed.st_ino)
                        != (expected_dev, expected_ino)):
                    raise NetworkBrokerRefused(
                        "network_broker_exec_pipe_identity_invalid",
                    )
            continue
        if fd not in {0, 1, 2}:
            raise NetworkBrokerRefused(
                "network_broker_inherited_fd_allowlist_invalid",
            )
        if not (stat.S_ISREG(observed.st_mode) or stat.S_ISFIFO(observed.st_mode)
                or stat.S_ISCHR(observed.st_mode) and target == "/dev/null"):
            raise NetworkBrokerRefused(
                "network_broker_stdio_identity_invalid",
            )


def attest_exec_fds(*, pipe_controls=()) -> None:
    """Final fixed-launcher proof immediately before execve."""
    try:
        controls = tuple(pipe_controls)
    except TypeError as exc:
        raise NetworkBrokerRefused(
            "network_broker_exec_pipe_identity_invalid",
        ) from exc
    if not controls:
        _attest_inherited_fds((0, 1, 2))
        return
    expected_records = ((3, "read"), (4, "write"))
    if (len(controls) != 2
            or any(type(record) not in {tuple, list} or len(record) != 4
                   for record in controls)
            or tuple((record[0], record[1]) for record in controls)
            != expected_records
            or any(type(record[2]) is not int or record[2] < 0
                   or type(record[3]) is not int or record[3] <= 0
                   for record in controls)
            or (controls[0][2], controls[0][3])
            == (controls[1][2], controls[1][3])):
        raise NetworkBrokerRefused(
            "network_broker_exec_pipe_identity_invalid",
        )
    inherited = (
        (3, (os.O_RDONLY, controls[0][2], controls[0][3])),
        (4, (os.O_WRONLY, controls[1][2], controls[1][3])),
    )
    _attest_inherited_fds(
        (0, 1, 2, 3, 4), exec_pipe_fds=inherited,
    )


def _validate_listener_fd(fd: int) -> None:
    if type(fd) is not int or fd < 3:
        raise NetworkBrokerRefused("network_broker_listener_fd_invalid")
    try:
        observed = os.fstat(fd)
        target = os.readlink(f"/proc/self/fd/{fd}")
        flags = fcntl.fcntl(fd, fcntl.F_GETFD)
    except OSError as exc:
        raise NetworkBrokerRefused("network_broker_listener_fd_invalid") from exc
    if (not stat.S_ISREG(observed.st_mode) and not target.startswith("anon_inode:")):
        raise NetworkBrokerRefused("network_broker_listener_fd_invalid")
    if target != "anon_inode:seccomp notify" or not flags & fcntl.FD_CLOEXEC:
        raise NetworkBrokerRefused("network_broker_listener_fd_invalid")


def _validate_pidfd(fd: int) -> None:
    if type(fd) is not int or fd < 0:
        raise NetworkBrokerRefused("network_broker_pidfd_invalid")
    try:
        target = os.readlink(f"/proc/self/fd/{fd}")
    except OSError as exc:
        raise NetworkBrokerRefused("network_broker_pidfd_invalid") from exc
    if target != "anon_inode:[pidfd]":
        raise NetworkBrokerRefused("network_broker_pidfd_invalid")


def _read_exact_until(fd: int, size: int, *, deadline_monotonic: float,
                      cancellation=None, child_pidfd: int | None = None) -> bytes:
    if (type(fd) is not int or fd < 0 or type(size) is not int or size < 0
            or type(deadline_monotonic) not in {int, float}
            or not math.isfinite(deadline_monotonic)):
        raise NetworkBrokerRefused("network_broker_handoff_deadline_invalid")
    if child_pidfd is not None:
        _validate_pidfd(child_pidfd)
    body = bytearray()
    poller = select.poll()
    poller.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL)
    if child_pidfd is not None:
        poller.register(child_pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    while len(body) < size:
        if cancellation is not None and cancellation.is_set():
            raise NetworkBrokerRefused("network_broker_handoff_cancelled")
        remaining = deadline_monotonic - time.monotonic()
        if remaining <= 0:
            raise NetworkBrokerRefused("network_broker_handoff_deadline_expired")
        events = poller.poll(max(1, min(50, math.ceil(remaining * 1000))))
        if not events:
            continue
        data_ready = False
        child_exited = False
        for observed_fd, mask in events:
            if observed_fd == fd:
                if mask & (select.POLLERR | select.POLLNVAL):
                    raise NetworkBrokerRefused("network_broker_handoff_pipe_failed")
                data_ready = data_ready or bool(mask & (select.POLLIN | select.POLLHUP))
            elif observed_fd == child_pidfd:
                child_exited = True
        if data_ready:
            try:
                chunk = os.read(fd, size - len(body))
            except InterruptedError:
                continue
            if not chunk:
                raise NetworkBrokerRefused("network_broker_handoff_pipe_truncated")
            body.extend(chunk)
            continue
        if child_exited:
            raise NetworkBrokerRefused("network_broker_handoff_child_exited")
    return bytes(body)


def _write_all_until(fd: int, body: bytes, *, deadline_monotonic: float,
                     cancellation=None, child_pidfd: int | None = None) -> None:
    view = memoryview(body)
    poller = select.poll()
    poller.register(fd, select.POLLOUT | select.POLLHUP | select.POLLERR | select.POLLNVAL)
    if child_pidfd is not None:
        _validate_pidfd(child_pidfd)
        poller.register(child_pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    while view:
        if cancellation is not None and cancellation.is_set():
            raise NetworkBrokerRefused("network_broker_handoff_cancelled")
        remaining = deadline_monotonic - time.monotonic()
        if remaining <= 0:
            raise NetworkBrokerRefused("network_broker_handoff_deadline_expired")
        writable = False
        child_exited = False
        for observed_fd, mask in poller.poll(
                max(1, min(50, math.ceil(remaining * 1000)))):
            if observed_fd == fd:
                if mask & (select.POLLHUP | select.POLLERR | select.POLLNVAL):
                    raise NetworkBrokerRefused("network_broker_handoff_pipe_failed")
                writable = writable or bool(mask & select.POLLOUT)
            elif observed_fd == child_pidfd:
                child_exited = True
        if child_exited:
            raise NetworkBrokerRefused("network_broker_handoff_child_exited")
        if not writable:
            continue
        try:
            written = os.write(fd, view)
        except (BlockingIOError, InterruptedError):
            continue
        if written <= 0:
            raise NetworkBrokerRefused("network_broker_handoff_pipe_failed")
        view = view[written:]


def _require_eof_until(fd: int, *, deadline_monotonic: float,
                       cancellation=None, child_pidfd: int | None = None) -> None:
    """Require EOF without permitting a held pipe writer to stall bootstrap."""
    poller = select.poll()
    poller.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL)
    if child_pidfd is not None:
        _validate_pidfd(child_pidfd)
        poller.register(child_pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    while True:
        if cancellation is not None and cancellation.is_set():
            raise NetworkBrokerRefused("network_broker_handoff_cancelled")
        remaining = deadline_monotonic - time.monotonic()
        if remaining <= 0:
            raise NetworkBrokerRefused("network_broker_handoff_deadline_expired")
        pipe_ready = False
        child_exited = False
        for observed_fd, mask in poller.poll(
                max(1, min(50, math.ceil(remaining * 1000)))):
            if observed_fd == fd:
                if mask & (select.POLLERR | select.POLLNVAL):
                    raise NetworkBrokerRefused("network_broker_handoff_pipe_failed")
                pipe_ready = pipe_ready or bool(mask & (select.POLLIN | select.POLLHUP))
            elif observed_fd == child_pidfd:
                child_exited = True
        if pipe_ready:
            try:
                trailing = os.read(fd, 1)
            except InterruptedError:
                continue
            if trailing:
                raise NetworkBrokerRefused("network_broker_handoff_trailing_data")
            return
        if child_exited:
            raise NetworkBrokerRefused("network_broker_handoff_child_exited")


def _abort_direct_child(child_pid: int, child_pidfd: int,
                        *, deadline_monotonic: float) -> None:
    try:
        signal.pidfd_send_signal(child_pidfd, signal.SIGKILL)
    except (AttributeError, ProcessLookupError):
        pass
    except OSError as exc:
        if exc.errno != errno.ESRCH:
            raise NetworkBrokerRefused("network_broker_handoff_child_kill_failed") from exc
    while time.monotonic() < deadline_monotonic:
        try:
            observed, _status = os.waitpid(child_pid, os.WNOHANG)
        except ChildProcessError:
            return
        if observed == child_pid:
            return
        time.sleep(0.01)
    raise NetworkBrokerRefused("network_broker_handoff_child_reap_failed")


def child_install_and_report(report_fd: int, ack_fd: int, *,
                             profile: str = "standard",
                             control_fds=(),
                             deadline_monotonic: float) -> None:
    """Install, prove the listener route, close the original, then await ACK."""
    if (type(report_fd) is not int or type(ack_fd) is not int
            or report_fd < 3 or ack_fd < 3 or report_fd == ack_fd):
        raise NetworkBrokerRefused("network_broker_handoff_fd_invalid")
    if (type(deadline_monotonic) not in {int, float}
            or not math.isfinite(deadline_monotonic)
            or deadline_monotonic <= time.monotonic()):
        raise NetworkBrokerRefused("network_broker_handoff_deadline_invalid")
    listener = -1
    try:
        try:
            extra_controls = tuple(control_fds)
        except TypeError as exc:
            raise NetworkBrokerRefused(
                "network_broker_inherited_fd_allowlist_invalid",
            ) from exc
        _attest_inherited_fds(
            (0, 1, 2, report_fd, ack_fd, *extra_controls),
            control_fds=(report_fd, ack_fd, *extra_controls),
        )
        listener = install_listener(profile=profile)
        try:
            profile_id = _PROFILE_IDS[profile]
        except KeyError as exc:
            raise NetworkBrokerRefused(
                "network_broker_filter_profile_invalid",
            ) from exc
        _write_all_until(
            report_fd,
            _HANDOFF.pack(_HANDOFF_MAGIC, _HANDOFF_VERSION, profile_id, listener),
            deadline_monotonic=deadline_monotonic,
        )
        # This sentinel cannot contact a host.  The worker must receive its
        # exact notification and return EPERM before the fixed child proceeds.
        sentinel = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            try:
                sentinel.connect(("0.0.0.0", 0))
            except OSError as exc:
                if exc.errno != errno.EPERM:
                    raise NetworkBrokerRefused(
                        "network_broker_sentinel_result_invalid",
                    ) from exc
            else:
                raise NetworkBrokerRefused("network_broker_sentinel_was_allowed")
        finally:
            sentinel.close()
        os.close(listener)
        listener = -1
        _write_all_until(
            report_fd, _HANDOFF_CLOSED,
            deadline_monotonic=deadline_monotonic,
        )
        os.close(report_fd)
        report_fd = -1
        acknowledgement = _read_exact_until(
            ack_fd, 1, deadline_monotonic=deadline_monotonic,
        )
        if acknowledgement != _HANDOFF_ACK:
            raise NetworkBrokerRefused("network_broker_handoff_ack_invalid")
        _require_eof_until(
            ack_fd, deadline_monotonic=deadline_monotonic,
        )
        os.close(ack_fd)
        ack_fd = -1
    finally:
        for fd in (listener, report_fd, ack_fd):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass


@dataclass(frozen=True)
class ListenerHandoff:
    child_pid: int
    child_pidfd: int
    remote_fd: int
    listener_fd: int
    profile: str


def duplicate_reported_listener(
        child_pid: int, report_fd: int, *, expected_profile: str,
        deadline_monotonic: float, cancellation=None,
        abort_child_on_failure: bool = True) -> ListenerHandoff:
    """Pin one direct child and duplicate its reported listener authority."""
    if (type(child_pid) is not int or child_pid <= 0
            or type(report_fd) is not int or report_fd < 3
            or type(abort_child_on_failure) is not bool):
        raise NetworkBrokerRefused("network_broker_handoff_identity_invalid")
    if (expected_profile not in _PROFILE_IDS
            or type(deadline_monotonic) not in {int, float}
            or not math.isfinite(deadline_monotonic)
            or deadline_monotonic <= time.monotonic()):
        raise NetworkBrokerRefused("network_broker_handoff_identity_invalid")
    try:
        pidfd = os.pidfd_open(child_pid, 0)
    except (AttributeError, OSError) as exc:
        raise NetworkBrokerRefused("network_broker_pidfd_open_failed") from exc
    listener = -1
    try:
        _validate_pidfd(pidfd)
        raw = _read_exact_until(
            report_fd, _HANDOFF.size,
            deadline_monotonic=deadline_monotonic,
            cancellation=cancellation, child_pidfd=pidfd,
        )
        magic, version, profile_id, remote_fd = _HANDOFF.unpack(raw)
        profile = _PROFILES_BY_ID.get(profile_id)
        if (magic != _HANDOFF_MAGIC or version != _HANDOFF_VERSION
                or profile != expected_profile
                or not 3 <= remote_fd <= (1 << 31) - 1):
            raise NetworkBrokerRefused("network_broker_handoff_frame_invalid")
        listener = _pidfd_getfd(pidfd, remote_fd)
        _validate_listener_fd(listener)
        return ListenerHandoff(child_pid, pidfd, remote_fd, listener, profile)
    except BaseException:
        if listener >= 0:
            os.close(listener)
        try:
            if abort_child_on_failure:
                _abort_direct_child(
                    child_pid, pidfd,
                    deadline_monotonic=time.monotonic() + 2.0,
                )
        finally:
            os.close(pidfd)
        raise


def verify_listener_bootstrap(
        handoff: ListenerHandoff, report_fd: int, *,
        deadline_monotonic: float, cancellation=None,
        abort_child_on_failure: bool = True) -> None:
    """Authenticate the sentinel notification and the child's original close."""
    if (type(handoff) is not ListenerHandoff
            or type(abort_child_on_failure) is not bool
            or type(deadline_monotonic) not in {int, float}
            or not math.isfinite(deadline_monotonic)
            or deadline_monotonic <= time.monotonic()):
        raise NetworkBrokerRefused("network_broker_handoff_identity_invalid")
    _validate_pidfd(handoff.child_pidfd)
    try:
        poller = select.poll()
        poller.register(
            handoff.listener_fd,
            select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL,
        )
        poller.register(
            handoff.child_pidfd,
            select.POLLIN | select.POLLHUP | select.POLLERR,
        )
        while True:
            if cancellation is not None and cancellation.is_set():
                raise NetworkBrokerRefused("network_broker_handoff_cancelled")
            remaining = deadline_monotonic - time.monotonic()
            if remaining <= 0:
                raise NetworkBrokerRefused("network_broker_handoff_deadline_expired")
            events = poller.poll(max(1, min(50, math.ceil(remaining * 1000))))
            listener_ready = any(
                fd == handoff.listener_fd and mask & select.POLLIN
                for fd, mask in events
            )
            if listener_ready:
                break
            if any(fd == handoff.child_pidfd for fd, _mask in events):
                raise NetworkBrokerRefused("network_broker_handoff_child_exited")
        notification = _SeccompNotif()
        _ioctl(
            handoff.listener_fd, _SECCOMP_IOCTL_NOTIF_RECV, notification,
        )
        if (notification.pid != handoff.child_pid
            or notification.data.arch != _architecture().audit
            or notification.data.nr != _architecture().connect):
            raise NetworkBrokerRefused("network_broker_sentinel_notification_invalid")
        identifier = ctypes.c_uint64(notification.id)
        _ioctl(
        handoff.listener_fd, _SECCOMP_IOCTL_NOTIF_ID_VALID, identifier,
    )
        destination = _copy_destination(
        int(notification.pid), int(notification.data.args[1]),
        int(notification.data.args[2]),
        validate=lambda: _ioctl(
            handoff.listener_fd, _SECCOMP_IOCTL_NOTIF_ID_VALID,
            ctypes.c_uint64(notification.id),
        ),
    )
        duplicate = _duplicate_tracee_fd(
        int(notification.pid), int(notification.data.args[0]),
        validate=lambda: _ioctl(
            handoff.listener_fd, _SECCOMP_IOCTL_NOTIF_ID_VALID,
            ctypes.c_uint64(notification.id),
        ),
    )
        try:
            _ioctl(
            handoff.listener_fd, _SECCOMP_IOCTL_NOTIF_ID_VALID,
            ctypes.c_uint64(notification.id),
        )
            domain, kind, protocol = _socket_metadata(duplicate)
        finally:
            os.close(duplicate)
        if (destination.family != socket.AF_INET or destination.peer != "0.0.0.0"
            or destination.port != 0 or domain != socket.AF_INET
            or kind & 0xF != socket.SOCK_STREAM
            or protocol not in {0, socket.IPPROTO_TCP}):
            raise NetworkBrokerRefused("network_broker_sentinel_notification_invalid")
        response = _SeccompNotifResp(notification.id, 0, -errno.EPERM, 0)
        _ioctl(handoff.listener_fd, _SECCOMP_IOCTL_NOTIF_SEND, response)
        if _read_exact_until(
                report_fd, len(_HANDOFF_CLOSED),
                deadline_monotonic=deadline_monotonic,
                cancellation=cancellation,
                child_pidfd=handoff.child_pidfd) != _HANDOFF_CLOSED:
            raise NetworkBrokerRefused("network_broker_handoff_close_invalid")
        _require_eof_until(
            report_fd,
            deadline_monotonic=deadline_monotonic,
            cancellation=cancellation,
            child_pidfd=handoff.child_pidfd,
        )
        try:
            reused = _syscall(
                _libc(), _architecture().pidfd_getfd,
                handoff.child_pidfd, handoff.remote_fd, 0,
            )
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise NetworkBrokerRefused(
                    "network_broker_handoff_close_unproved",
                ) from exc
        else:
            os.close(reused)
            raise NetworkBrokerRefused("network_broker_handoff_fd_reused")
    except BaseException:
        try:
            if abort_child_on_failure:
                _abort_direct_child(
                    handoff.child_pid, handoff.child_pidfd,
                    deadline_monotonic=time.monotonic() + 2.0,
                )
        finally:
            try:
                os.close(handoff.listener_fd)
            except OSError:
                pass
            try:
                os.close(handoff.child_pidfd)
            except OSError:
                pass
        raise


def acknowledge_listener(ack_fd: int, *, child_pidfd: int,
                         deadline_monotonic: float, cancellation=None) -> None:
    if type(ack_fd) is not int or ack_fd < 3:
        raise NetworkBrokerRefused("network_broker_handoff_ack_invalid")
    _write_all_until(
        ack_fd, _HANDOFF_ACK, deadline_monotonic=deadline_monotonic,
        cancellation=cancellation, child_pidfd=child_pidfd,
    )
    os.close(ack_fd)


def _write_all(fd: int, body: bytes) -> None:
    view = memoryview(body)
    while view:
        try:
            written = os.write(fd, view)
        except InterruptedError:
            continue
        if written <= 0:
            raise NetworkBrokerError("network_broker_pipe_write_failed")
        view = view[written:]


def _read_exact(fd: int, size: int) -> bytes:
    body = bytearray()
    while len(body) < size:
        try:
            chunk = os.read(fd, size - len(body))
        except InterruptedError:
            continue
        if not chunk:
            raise NetworkBrokerError("network_broker_pipe_truncated")
        body.extend(chunk)
    return bytes(body)


def _pidfd_getfd(pidfd: int, remote_fd: int) -> int:
    try:
        return _syscall(_libc(), _architecture().pidfd_getfd, pidfd, remote_fd, 0)
    except OSError as exc:
        raise NetworkBrokerRefused("network_broker_pidfd_getfd_failed") from exc


def _read_bounded_file(path: str, limit: int) -> str:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    try:
        body = os.read(fd, limit + 1)
        if len(body) > limit or os.read(fd, 1):
            raise OSError("bounded proc record exceeded")
    finally:
        os.close(fd)
    return body.decode("ascii", "strict")


def _thread_group_number(tid: int, *, validate) -> int:
    if type(tid) is not int or tid <= 0:
        raise NetworkBrokerRefused("network_broker_notification_tid_invalid")
    validate()
    try:
        body = _read_bounded_file(f"/proc/{tid}/status", _MAX_PROC_STATUS_BYTES)
    except (OSError, UnicodeError) as exc:
        raise NetworkBrokerRefused("network_broker_notification_identity_failed") from exc
    validate()
    values = [line.split(":", 1)[1].strip() for line in body.splitlines()
              if line.startswith("Tgid:")]
    if len(values) != 1 or not values[0].isascii() or not values[0].isdecimal():
        raise NetworkBrokerRefused("network_broker_notification_identity_failed")
    tgid = int(values[0])
    if tgid <= 0:
        raise NetworkBrokerRefused("network_broker_notification_identity_failed")
    validate()
    return tgid


def _thread_group_pidfd(tid: int, *, validate) -> int:
    tgid = _thread_group_number(tid, validate=validate)
    try:
        pidfd = os.pidfd_open(tgid, 0)
    except (AttributeError, OSError) as exc:
        raise NetworkBrokerRefused("network_broker_pidfd_open_failed") from exc
    try:
        validate()
        shared = _syscall(
            _libc(), _architecture().kcmp, tgid, tid, _KCMP_FILES, 0, 0,
        )
    except OSError as exc:
        os.close(pidfd)
        raise NetworkBrokerRefused("network_broker_kcmp_failed") from exc
    if shared != 0:
        os.close(pidfd)
        raise NetworkBrokerRefused("network_broker_separate_fd_table_refused")
    validate()
    return pidfd


def _duplicate_tracee_fd(tid: int, remote_fd: int, *, validate,
                         socket_only: bool = True) -> int:
    if type(remote_fd) is not int or remote_fd < 0:
        raise NetworkBrokerRefused("network_broker_tracee_fd_invalid")
    pidfd = _thread_group_pidfd(tid, validate=validate)
    try:
        duplicate = _pidfd_getfd(pidfd, remote_fd)
        validate()
    finally:
        os.close(pidfd)
    try:
        metadata = os.fstat(duplicate)
        if socket_only and not stat.S_ISSOCK(metadata.st_mode):
            raise NetworkBrokerRefused("network_broker_tracee_fd_not_socket")
        return duplicate
    except BaseException:
        os.close(duplicate)
        raise


def _require_same_tracee_ofd(tid: int, remote_fd: int, local_fd: int, *,
                             validate) -> None:
    """Prove the tracee slot still names the broker's exact open file."""
    if (type(remote_fd) is not int or remote_fd < 0
            or type(local_fd) is not int or local_fd < 0):
        raise NetworkBrokerRefused("network_broker_tracee_fd_invalid")
    tgid = _thread_group_number(tid, validate=validate)
    validate()
    try:
        same = _syscall(
            _libc(), _architecture().kcmp,
            os.getpid(), tgid, _KCMP_FILE, local_fd, remote_fd,
        )
    except OSError as exc:
        raise NetworkBrokerRefused("network_broker_fd_slot_revalidation_failed") from exc
    validate()
    if same != 0:
        raise NetworkBrokerRefused("network_broker_fd_slot_changed")


def _read_process(tid: int, address: int, size: int) -> bytes:
    if (type(address) is not int or address <= 0 or type(size) is not int
            or size < 0 or size > (1 << 24)):
        raise NetworkBrokerRefused("network_broker_tracee_memory_invalid")
    if size == 0:
        return b""
    body = ctypes.create_string_buffer(size)
    local = _IOVec(ctypes.cast(body, ctypes.c_void_p), size)
    remote = _IOVec(ctypes.c_void_p(address), size)
    library = _libc()
    operation = getattr(library, "process_vm_readv", None)
    if operation is None:
        raise NetworkBrokerRefused("network_broker_tracee_memory_api_unavailable")
    operation.argtypes = [
        ctypes.c_int, ctypes.POINTER(_IOVec), ctypes.c_ulong,
        ctypes.POINTER(_IOVec), ctypes.c_ulong, ctypes.c_ulong,
    ]
    operation.restype = ctypes.c_ssize_t
    ctypes.set_errno(0)
    observed = operation(
        tid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0,
    )
    if observed < 0:
        error = ctypes.get_errno()
        exc = OSError(error, os.strerror(error))
        raise NetworkBrokerRefused("network_broker_tracee_memory_read_failed") from exc
    if observed != size:
        raise NetworkBrokerRefused("network_broker_tracee_memory_read_partial")
    return body.raw


@dataclass(frozen=True)
class _Destination:
    family: int
    peer: str | None
    port: int | None
    raw: bytes
    unix_path: bytes | None = None
    netlink_pid: int | None = None
    netlink_groups: int | None = None


@dataclass
class _CopiedMessage:
    destination: _Destination | None
    name_buffer: object | None
    payload_buffers: tuple[object, ...]
    iovectors: object
    control_buffer: object | None
    passed_fds: tuple[int, ...]
    header: _MsgHdr


def _copy_destination(tid: int, pointer: int, length: int, *, validate=None) -> _Destination:
    if (type(length) is not int or length < 2
            or length > _MAX_SOCKADDR_BYTES):
        raise NetworkBrokerRefused("network_broker_sockaddr_length_invalid")
    raw = _read_process(tid, pointer, length)
    if validate is not None:
        validate()
    family = struct.unpack_from("=H", raw)[0]
    if family == socket.AF_INET:
        if length != 16:
            raise NetworkBrokerRefused("network_broker_sockaddr_length_invalid")
        port = struct.unpack_from("!H", raw, 2)[0]
        peer = socket.inet_ntop(socket.AF_INET, raw[4:8])
        return _Destination(family, peer, port, raw)
    if family == socket.AF_INET6:
        if length != 28:
            raise NetworkBrokerRefused("network_broker_sockaddr_length_invalid")
        port = struct.unpack_from("!H", raw, 2)[0]
        flowinfo = struct.unpack_from("=I", raw, 4)[0]
        scope_id = struct.unpack_from("=I", raw, 24)[0]
        if flowinfo != 0 or scope_id != 0:
            raise NetworkBrokerRefused("network_broker_ipv6_scope_refused")
        parsed = ipaddress.ip_address(socket.inet_ntop(socket.AF_INET6, raw[8:24]))
        return _Destination(family, str(parsed.ipv4_mapped or parsed), port, raw)
    if family == socket.AF_UNIX:
        value = raw[2:]
        if not value:
            path = b""
        elif value.startswith(b"\x00"):
            # Abstract names are length-delimited.  Every byte, including an
            # all-zero name, is identity; trimming turns a named endpoint into
            # a falsely admitted unnamed socket.
            path = value
        else:
            path = value.split(b"\x00", 1)[0]
        return _Destination(family, None, None, raw, path)
    if family == socket.AF_NETLINK:
        if length != 12:
            raise NetworkBrokerRefused("network_broker_sockaddr_length_invalid")
        netlink_pid, netlink_groups = struct.unpack_from("=II", raw, 4)
        return _Destination(
            family, None, None, raw, None, netlink_pid, netlink_groups,
        )
    if family == socket.AF_UNSPEC:
        if length != 2:
            raise NetworkBrokerRefused("network_broker_sockaddr_length_invalid")
        return _Destination(family, None, None, raw)
    raise NetworkBrokerRefused("network_broker_address_family_refused")


def _socket_metadata(fd: int) -> tuple[int, int, int]:
    handle = socket.socket(fileno=fd)
    try:
        domain = handle.getsockopt(socket.SOL_SOCKET, _SO_DOMAIN)
        kind = handle.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
        protocol = handle.getsockopt(socket.SOL_SOCKET, _SO_PROTOCOL)
    except OSError as exc:
        raise NetworkBrokerRefused("network_broker_socket_metadata_failed") from exc
    finally:
        handle.detach()
    return domain, kind, protocol


def _copy_payload(tid: int, pointer: int, length: int, *, validate) -> bytes:
    if type(length) is not int or not 0 <= length <= _MAX_SEND_BYTES:
        raise NetworkBrokerRefused("network_broker_send_size_invalid")
    if length == 0:
        validate()
        return b""
    body = _read_process(tid, pointer, length)
    validate()
    return body


def _copy_message(tid: int, pointer: int, *, validate, duplicate_fd) -> _CopiedMessage:
    raw_header = _read_process(tid, pointer, ctypes.sizeof(_MsgHdr))
    validate()
    remote = _MsgHdr.from_buffer_copy(raw_header)
    count = int(remote.iov_length)
    if not 0 <= count <= _MAX_IOVECTORS:
        raise NetworkBrokerRefused("network_broker_iovec_count_invalid")
    control_length = int(remote.control_length)
    if not 0 <= control_length <= _MAX_CONTROL_BYTES:
        raise NetworkBrokerRefused("network_broker_control_size_invalid")
    if bool(remote.control) != bool(control_length):
        raise NetworkBrokerRefused("network_broker_control_pointer_invalid")
    if count:
        table_size = count * ctypes.sizeof(_IOVec)
        iov_pointer = ctypes.cast(remote.iov, ctypes.c_void_p).value
        if not iov_pointer:
            raise NetworkBrokerRefused("network_broker_iovec_pointer_invalid")
        raw_iovectors = _read_process(tid, int(iov_pointer), table_size)
        validate()
        remote_iovectors = (_IOVec * count).from_buffer_copy(raw_iovectors)
    else:
        remote_iovectors = ()
    payloads = []
    total = 0
    for item in remote_iovectors:
        length = int(item.length)
        if length < 0 or total + length > _MAX_SEND_BYTES:
            raise NetworkBrokerRefused("network_broker_send_size_invalid")
        payloads.append(_copy_payload(
            tid, int(item.base or 0), length, validate=validate,
        ))
        total += length
    payload_buffers = tuple(ctypes.create_string_buffer(body) for body in payloads)
    local_iovectors = (_IOVec * count)(*[
        _IOVec(ctypes.cast(buffer, ctypes.c_void_p), len(body))
        for buffer, body in zip(payload_buffers, payloads)
    ])
    destination = None
    name_buffer = None
    name_pointer = None
    name_length = int(remote.name_length)
    if remote.name:
        destination = _copy_destination(
            tid, int(remote.name), name_length, validate=validate,
        )
        name_buffer = ctypes.create_string_buffer(destination.raw)
        name_pointer = ctypes.cast(name_buffer, ctypes.c_void_p)
    elif name_length != 0:
        raise NetworkBrokerRefused("network_broker_sockaddr_length_invalid")
    control_buffer = None
    passed_fds: list[int] = []
    try:
        if control_length:
            raw_control = bytearray(_read_process(
                tid, int(remote.control), control_length,
            ))
            validate()
            offset = 0
            while offset < control_length:
                remaining = control_length - offset
                if remaining < _CMSG_HEADER.size:
                    if any(raw_control[offset:]):
                        raise NetworkBrokerRefused("network_broker_control_record_invalid")
                    break
                cmsg_length, level, kind = _CMSG_HEADER.unpack_from(raw_control, offset)
                if (cmsg_length < _CMSG_HEADER.size
                        or cmsg_length > remaining):
                    raise NetworkBrokerRefused("network_broker_control_record_invalid")
                data_start = offset + _CMSG_HEADER.size
                data_end = offset + cmsg_length
                data = raw_control[data_start:data_end]
                if level != socket.SOL_SOCKET:
                    raise NetworkBrokerRefused("network_broker_control_record_refused")
                if kind in {_SCM_CREDENTIALS, _SCM_PIDFD}:
                    # The broker cannot truthfully impersonate the tracee's PID,
                    # and pidfds are process authority rather than payload.
                    raise NetworkBrokerRefused("network_broker_control_record_refused")
                if kind != _SCM_RIGHTS or not data or len(data) % 4:
                    raise NetworkBrokerRefused("network_broker_control_record_refused")
                remote_fds = struct.unpack(f"={len(data) // 4}i", data)
                if (len(passed_fds) + len(remote_fds) > _MAX_RIGHTS_FDS
                        or any(value < 0 for value in remote_fds)):
                    raise NetworkBrokerRefused("network_broker_rights_count_invalid")
                local_fds = []
                for remote_fd in remote_fds:
                    local_fd = duplicate_fd(remote_fd)
                    passed_fds.append(local_fd)
                    local_fds.append(local_fd)
                    validate()
                raw_control[data_start:data_end] = struct.pack(
                    f"={len(local_fds)}i", *local_fds,
                )
                aligned = (int(cmsg_length) + 7) & ~7
                if aligned > remaining:
                    if int(cmsg_length) != remaining:
                        raise NetworkBrokerRefused("network_broker_control_record_invalid")
                    offset = control_length
                else:
                    offset += aligned
            control_buffer = ctypes.create_string_buffer(bytes(raw_control))
        header = _MsgHdr(
            name_pointer, name_length,
            ctypes.cast(local_iovectors, ctypes.POINTER(_IOVec)) if count else None,
            count,
            ctypes.cast(control_buffer, ctypes.c_void_p) if control_buffer is not None else None,
            control_length, 0,
        )
        return _CopiedMessage(
            destination, name_buffer, payload_buffers, local_iovectors,
            control_buffer, tuple(passed_fds), header,
        )
    except BaseException:
        for local_fd in passed_fds:
            try:
                os.close(local_fd)
            except OSError:
                pass
        raise


@dataclass(frozen=True)
class BrokerDecision:
    sequence: int
    stage: str
    syscall: str
    tid: int
    peer: str | None
    port: int | None
    socket_type: int
    protocol: int
    decision: str
    reason: str
    result: str | None

    def to_dict(self) -> dict:
        return {
            "sequence": self.sequence, "stage": self.stage,
            "syscall": self.syscall,
            "tid": self.tid, "peer": self.peer, "port": self.port,
            "socket_type": self.socket_type, "protocol": self.protocol,
            "decision": self.decision, "reason": self.reason,
            "result": self.result,
        }


@dataclass(frozen=True)
class BrokerPolicy:
    request_id: str
    source_id: str
    tool: str
    block_private_targets: bool
    control_plane_cidrs: tuple[str, ...]
    initial_own_ips: tuple[str, ...]
    resolver_ips: tuple[str, ...]
    apex_domains: tuple[str, ...] = ()
    oos_patterns: tuple[str, ...] = ()
    effective_cidrs: tuple[str, ...] = ()
    approved_peers: tuple[str, ...] = ()
    control_helpers: tuple[tuple[str, int], ...] = ()
    control_clients: tuple[tuple[str, int], ...] = ()
    private_unix_roots: tuple[str, ...] = ()
    authority_class: str = "target"
    transport_profile: str = "test-exact-approved"
    peer_mode: str = "approved"
    resolver_mode: str = "mediated-explicit"
    public_control_endpoints: tuple[str, ...] = ()
    operator_control_endpoints: tuple[str, ...] = ()
    nuclei_protocol_lane: str = "none"
    # Worker-only authority.  It is deliberately absent from the serialized
    # policy: the worker creates and holds this endpoint after parsing the
    # parent-authenticated policy, before the tracee is released.
    dns_mediator_endpoint: tuple[str, int] | None = None

    @classmethod
    def from_json(cls, raw: str) -> "BrokerPolicy":
        from . import netguard
        from .network_policy import (
            NetworkPolicyError,
            _MAX_BROKER_POLICY_BYTES,
            _MAX_EXECUTABLE_BYTES as POLICY_MAX_EXECUTABLE_BYTES,
            _canonical_control_endpoints,
            _explicit_resolvers,
            _NUCLEI_DEFAULT_RESOLVERS,
            _public_resolvers,
            _resolver_snapshot,
            broker_transport_semantics,
            canonical_control_plane_cidrs,
            _validate_control_endpoint_authority,
            _validate_nuclei_protocol_lane,
        )

        if (type(raw) is not str
                or len(raw.encode("utf-8")) > _MAX_BROKER_POLICY_BYTES):
            raise NetworkBrokerRefused("network_broker_policy_invalid")
        try:
            document = json.loads(raw)
        except (TypeError, ValueError, NetworkPolicyError) as exc:
            raise NetworkBrokerRefused("network_broker_policy_invalid") from exc
        expected = {
            "schema_version", "request_id", "source_id", "tool",
            "authority_class", "transport_profile", "peer_mode",
            "resolver_mode",
            "block_private_targets", "control_plane_cidrs",
            "initial_own_ips", "resolver_ips", "proxy_inheritance",
            "apex_domains", "oos_patterns", "effective_cidrs",
            "approved_peers",
            "public_control_endpoints", "operator_control_endpoints",
            "nuclei_protocol_lane",
            "control_helpers", "control_clients", "private_unix_roots",
        }
        if type(document) is not dict or set(document) != expected:
            raise NetworkBrokerRefused("network_broker_policy_invalid")
        if (document["schema_version"] != "quarry.network-broker-policy.v1"
                or document["proxy_inheritance"] != "disabled"
                or type(document["request_id"]) is not str
                or _HEX32.fullmatch(document["request_id"]) is None
                or type(document["source_id"]) is not str
                or _SOURCE.fullmatch(document["source_id"]) is None
                or type(document["tool"]) is not str or not document["tool"]
                or "\x00" in document["tool"]
                or type(document["block_private_targets"]) is not bool):
            raise NetworkBrokerRefused("network_broker_policy_invalid")
        try:
            semantics = broker_transport_semantics(
                document["source_id"], document["tool"],
            )
        except NetworkPolicyError as exc:
            raise NetworkBrokerRefused("network_broker_policy_invalid") from exc
        if (semantics["resolver_mode"] == "mediated-public"
                and document.get("resolver_mode") == "mediated-explicit"):
            try:
                if tuple(document["resolver_ips"]) != _resolver_snapshot():
                    raise NetworkPolicyError("explicit resolver snapshot changed")
            except (TypeError, NetworkPolicyError) as exc:
                raise NetworkBrokerRefused("network_broker_policy_invalid") from exc
            semantics = {**semantics, "resolver_mode": "mediated-explicit"}
        if any(document.get(name) != value for name, value in semantics.items()):
            raise NetworkBrokerRefused("network_broker_policy_invalid")
        try:
            controls = canonical_control_plane_cidrs(document["control_plane_cidrs"])
            initial = netguard.canonical_ip_set(document["initial_own_ips"])
            resolvers = (
                _public_resolvers(document["resolver_ips"])
                if semantics["resolver_mode"] == "mediated-public"
                else _explicit_resolvers(document["resolver_ips"])
            )
        except (TypeError, ValueError, NetworkPolicyError) as exc:
            raise NetworkBrokerRefused("network_broker_policy_invalid") from exc
        if (not initial or not resolvers or len(resolvers) > 16
                or list(controls) != document["control_plane_cidrs"]
                or list(initial) != document["initial_own_ips"]
                or list(resolvers) != document["resolver_ips"]):
            raise NetworkBrokerRefused("network_broker_policy_invalid")
        if (semantics["transport_profile"] == "nuclei-authorized-http"
                and resolvers != _NUCLEI_DEFAULT_RESOLVERS):
            raise NetworkBrokerRefused("network_broker_policy_invalid")
        from . import normalize
        raw_apexes = document["apex_domains"]
        if type(raw_apexes) is not list or len(raw_apexes) > 1024:
            raise NetworkBrokerRefused("network_broker_policy_invalid")
        apexes = []
        for apex in raw_apexes:
            try:
                ipaddress.ip_address(apex)
            except (ValueError, TypeError):
                pass
            else:
                raise NetworkBrokerRefused("network_broker_policy_invalid")
            if type(apex) is not str or normalize.canon_host_strict(apex) != apex:
                raise NetworkBrokerRefused("network_broker_policy_invalid")
            apexes.append(apex)
        if apexes != sorted(set(apexes)):
            raise NetworkBrokerRefused("network_broker_policy_invalid")
        raw_patterns = document["oos_patterns"]
        if type(raw_patterns) is not list or len(raw_patterns) > 1024:
            raise NetworkBrokerRefused("network_broker_policy_invalid")
        patterns = []
        for pattern in raw_patterns:
            if (type(pattern) is not str or not pattern
                    or len(pattern.encode("utf-8")) > 4096 or "\x00" in pattern):
                raise NetworkBrokerRefused("network_broker_policy_invalid")
            try:
                compile_oos(pattern)
            except OOSRegexError as exc:
                raise NetworkBrokerRefused("network_broker_policy_invalid") from exc
            patterns.append(pattern)
        if patterns != sorted(set(patterns)):
            raise NetworkBrokerRefused("network_broker_policy_invalid")
        raw_effective = document["effective_cidrs"]
        if type(raw_effective) is not list or len(raw_effective) > 4096:
            raise NetworkBrokerRefused("network_broker_policy_invalid")
        effective = []
        try:
            for value in raw_effective:
                if type(value) is not str:
                    raise ValueError
                network = ipaddress.ip_network(value, strict=True)
                if str(network) != value.lower():
                    raise ValueError
                effective.append(str(network))
        except ValueError as exc:
            raise NetworkBrokerRefused("network_broker_policy_invalid") from exc
        if effective != sorted(set(effective), key=lambda value: (
                ipaddress.ip_network(value).version,
                int(ipaddress.ip_network(value).network_address),
                ipaddress.ip_network(value).prefixlen)):
            raise NetworkBrokerRefused("network_broker_policy_invalid")
        try:
            approved = netguard.canonical_ip_set(document["approved_peers"])
        except (TypeError, ValueError) as exc:
            raise NetworkBrokerRefused("network_broker_policy_invalid") from exc
        if (len(approved) > 4096 or list(approved) != document["approved_peers"]):
            raise NetworkBrokerRefused("network_broker_policy_invalid")
        try:
            public_controls = _canonical_control_endpoints(
                document["public_control_endpoints"],
            )
            operator_controls = _canonical_control_endpoints(
                document["operator_control_endpoints"],
            )
        except NetworkPolicyError as exc:
            raise NetworkBrokerRefused("network_broker_policy_invalid") from exc
        if set(public_controls) & set(operator_controls):
            raise NetworkBrokerRefused("network_broker_policy_invalid")
        try:
            _validate_control_endpoint_authority(
                semantics["transport_profile"], public_controls, operator_controls,
            )
            _validate_nuclei_protocol_lane(
                semantics["transport_profile"], document["nuclei_protocol_lane"],
            )
        except NetworkPolicyError as exc:
            raise NetworkBrokerRefused("network_broker_policy_invalid") from exc
        identities = []
        for name in ("control_helpers", "control_clients"):
            raw_identities = document[name]
            if type(raw_identities) is not list or len(raw_identities) > 4:
                raise NetworkBrokerRefused("network_broker_policy_invalid")
            parsed = []
            for identity in raw_identities:
                if (type(identity) is not dict or set(identity) != {"sha256", "bytes"}
                        or type(identity["sha256"]) is not str
                        or len(identity["sha256"]) != 64
                        or any(char not in "0123456789abcdef" for char in identity["sha256"])
                        or type(identity["bytes"]) is not int
                        or not 1 <= identity["bytes"]
                        <= POLICY_MAX_EXECUTABLE_BYTES):
                    raise NetworkBrokerRefused("network_broker_policy_invalid")
                parsed.append((identity["sha256"], identity["bytes"]))
            if len(set(parsed)) != len(parsed) or parsed != sorted(parsed):
                raise NetworkBrokerRefused("network_broker_policy_invalid")
            identities.append(tuple(parsed))
        raw_roots = document["private_unix_roots"]
        if type(raw_roots) is not list or len(raw_roots) > 8:
            raise NetworkBrokerRefused("network_broker_policy_invalid")
        roots = []
        for root in raw_roots:
            if (type(root) is not str or not root.startswith("/") or "\x00" in root
                    or root != os.path.normpath(root)
                    or len(os.fsencode(root)) > 4096):
                raise NetworkBrokerRefused("network_broker_policy_invalid")
            roots.append(root)
        if len(set(roots)) != len(roots) or roots != sorted(roots):
            raise NetworkBrokerRefused("network_broker_policy_invalid")
        return cls(
            request_id=document["request_id"], source_id=document["source_id"],
            tool=document["tool"],
            block_private_targets=document["block_private_targets"],
            control_plane_cidrs=controls, initial_own_ips=initial,
            resolver_ips=resolvers, apex_domains=tuple(apexes),
            oos_patterns=tuple(patterns), effective_cidrs=tuple(effective),
            approved_peers=approved,
            public_control_endpoints=public_controls,
            operator_control_endpoints=operator_controls,
            nuclei_protocol_lane=document["nuclei_protocol_lane"],
            control_helpers=identities[0],
            control_clients=identities[1], private_unix_roots=tuple(roots),
            **semantics,
        )

    @staticmethod
    def _endpoint(host: str, port: int) -> str:
        return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"

    def host_allowed(self, host: str, port: int | None = None) -> tuple[str, str]:
        """Decide the canonical HTTP authority before any DNS request."""
        from . import normalize

        if "%" in host:
            return "deny", "scoped IPv6 HTTP authority is not canonical"
        endpoint = self._endpoint(host, port) if type(port) is int else None
        if endpoint in self.public_control_endpoints:
            return "allow", "declared public OOB control endpoint"
        if endpoint in self.operator_control_endpoints:
            return "allow", "declared operator OOB control endpoint"
        if port == 53 and host in self.resolver_ips:
            return "deny", "DNS resolver is direct-only, never proxy authority"
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            canonical = normalize.canon_host_strict(host)
            if canonical is None or canonical != host:
                return "deny", "HTTP authority is not canonical"
            if not any(canonical == apex or canonical.endswith("." + apex)
                       for apex in self.apex_domains):
                return "deny", "HTTP authority is outside the active apex scope"
            if any(oos_search(pattern, canonical)
                   for pattern in self.oos_patterns):
                return "deny", "HTTP authority matches an out-of-scope rule"
            return "allow", "HTTP authority is inside the active apex scope"
        if (self.transport_profile == "nuclei-authorized-http"
                and str(address) in self.approved_peers):
            return "allow", "literal proxy authority is invocation-approved"
        if any(address.version == network.version and address in network
               for network in map(ipaddress.ip_network, self.effective_cidrs)):
            return "allow", "literal HTTP authority is inside effective CIDR scope"
        return "deny", "literal HTTP authority is outside effective CIDR scope"

    def decide_unix(self, path: bytes | None) -> tuple[str, str]:
        if not path:
            return "allow", "unnamed invocation-local Unix socket"
        if path.startswith(b"\x00"):
            return "deny", "abstract Unix socket is not invocation-owned"
        try:
            text = os.fsdecode(path)
        except (TypeError, UnicodeError):
            return "deny", "Unix socket path is malformed"
        if (not text.startswith("/") or text != os.path.normpath(text)
                or "\x00" in text):
            return "deny", "Unix socket path is not canonical"
        # Lexical containment is not endpoint authority: a same-UID tracee can
        # replace a pathname or one of its ancestors after validation but
        # before connect(2).  Until a listener is held and authenticated by the
        # boundary, every named Unix destination is refused.  Private roots are
        # still carried in policy for filesystem isolation, never as an egress
        # exception.
        return "deny", "named Unix socket lacks held endpoint authority"

    def is_chromium_singleton_path(self, path: bytes | None) -> bool:
        """Recognise only the attested private ProcessSingleton bind shape.

        This is a selector for abstract substitution, never permission to touch
        the filesystem pathname itself.
        """
        if not path or path.startswith(b"\x00"):
            return False
        try:
            text = os.fsdecode(path)
        except (TypeError, UnicodeError):
            return False
        if (not text.startswith("/") or text != os.path.normpath(text)
                or "\x00" in text):
            return False
        for root in self.private_unix_roots:
            try:
                relative = os.path.relpath(text, root)
            except ValueError:
                continue
            parts = relative.split(os.sep)
            if (len(parts) == 2 and parts[1] == "SingletonSocket"
                    and _CHROMIUM_SINGLETON_DIR.fullmatch(parts[0]) is not None):
                return True
        return False

    def _decide(self, peer: str, port: int, kind: int, protocol: int, *,
                mediated: bool,
                declared_control_endpoint: bool = False) -> tuple[str, str]:
        from . import netguard

        # Target-DNS tracees may reach only the worker-held loopback mediator.
        # It is a runtime capability rather than an input-policy endpoint.
        if self.transport_profile == "target-dns":
            endpoint = self.dns_mediator_endpoint
            base_kind = kind & 0xF
            expected = {
                socket.SOCK_STREAM: {0, socket.IPPROTO_TCP},
                socket.SOCK_DGRAM: {0, socket.IPPROTO_UDP},
            }
            if (endpoint is not None and (peer, port) == endpoint
                    and base_kind in expected
                    and protocol in expected[base_kind]):
                return "allow", "held loopback DNS mediator admitted"
            return "deny", "target DNS requires its held loopback mediator"
        # A small, source-derived set of tracees owns DNS transport directly.
        # Delegate its complete destination check to the DNS authority before
        # the ordinary peer path: explicit ambient resolvers can legitimately
        # be loopback/private, and decide_dns owns those exact exceptions.
        if not mediated and port == 53:
            if (self.authority_class == "public-provider"
                    or self.transport_profile in {"target-http-exact", "target-tls"}):
                return self.decide_dns(peer, port, kind, protocol)
        try:
            current_own = netguard.own_ips()
        except (OSError, ValueError) as exc:
            raise NetworkBrokerRefused("network_broker_interface_refresh_failed") from exc
        if not current_own:
            raise NetworkBrokerRefused("network_broker_interface_refresh_failed")
        address = ipaddress.ip_address(peer)
        if netguard.is_self_attack_ip(
                peer, own_ips=current_own,
                control_plane_cidrs=self.control_plane_cidrs):
            return "deny", "protected scanner/metadata/control-plane peer"
        base_kind = kind & 0xF
        expected_protocol = {
            socket.SOCK_STREAM: {0, socket.IPPROTO_TCP},
            socket.SOCK_DGRAM: {0, socket.IPPROTO_UDP},
        }
        if (base_kind not in expected_protocol
                or protocol not in expected_protocol[base_kind]):
            return "deny", "socket type/protocol is outside TCP/UDP policy"
        if (address.is_unspecified or address.is_multicast
                or (address.version == 4 and int(address) == 0xFFFFFFFF)):
            return "deny", "unspecified/multicast/broadcast peer"
        if netguard.is_non_unicast_ip(peer):
            return "deny", "peer is not a unicast target address"
        if self.authority_class == "public-provider" \
                and (not address.is_global or netguard.is_private_ip(peer)):
            return "deny", "public provider peer is not global unicast"
        if (self.block_private_targets and netguard.is_private_ip(peer)
                and not (mediated and declared_control_endpoint
                         and self.authority_class == "operator-infrastructure")):
            return "deny", "private-target opt-out"
        if mediated:
            if self.authority_class == "target":
                return "allow", "peer admitted by scoped transport mediator"
            if self.authority_class == "public-provider":
                return "allow", "global-unicast public-provider peer admitted"
            if (self.authority_class == "operator-infrastructure"
                    and (peer in self.approved_peers
                         or declared_control_endpoint)):
                return "allow", "declared operator endpoint peer admitted"
            return "deny", "authority class has no mediated peer permission"
        if port == 53:
            return "deny", "DNS transport is outside this tracee profile"
        if (self.authority_class == "public-provider"
                and (base_kind != socket.SOCK_STREAM
                     or protocol not in {0, socket.IPPROTO_TCP})):
            return "deny", "public-provider datagram transport is unmediated"
        if self.peer_mode == "deny-all":
            return "deny", "transport profile has no direct peer authority"
        if self.peer_mode == "approved":
            if peer not in self.approved_peers:
                return "deny", "peer is not in the invocation-approved answer set"
            return "allow", "exact invocation-approved peer admitted"
        if self.peer_mode == "effective-cidr":
            if not any(address.version == network.version and address in network
                       for network in map(ipaddress.ip_network, self.effective_cidrs)):
                return "deny", "peer is outside the effective CIDR authority"
            return "allow", "peer is inside the effective CIDR authority"
        if self.peer_mode == "public-unicast" \
                and self.authority_class == "public-provider":
            return "allow", "global-unicast public-provider peer admitted"
        return "deny", "transport peer mode is invalid"

    def decide(self, peer: str, port: int, kind: int, protocol: int) -> tuple[str, str]:
        return self._decide(
            peer, port, kind, protocol, mediated=False,
        )

    def decide_resolved(self, peer: str, port: int, kind: int,
                        protocol: int) -> tuple[str, str]:
        """Classify a peer whose hostname/scope binding the pinned proxy owns."""
        return self._decide(
            peer, port, kind, protocol, mediated=True,
        )

    def decide_proxy_resolved(self, host: str, peer: str, port: int, kind: int,
                              protocol: int) -> tuple[str, str]:
        """Classify a proxy peer with its exact target/control authority."""
        from . import netguard

        endpoint = self._endpoint(host, port)
        declared_control = (
            endpoint in self.public_control_endpoints
            or endpoint in self.operator_control_endpoints
        )
        decision, reason = self._decide(
            peer, port, kind, protocol, mediated=True,
            declared_control_endpoint=declared_control,
        )
        if port == 53 and host in self.resolver_ips:
            return "deny", "DNS resolver is direct-only, never proxy authority"
        if decision != "allow":
            return decision, reason
        if endpoint in self.public_control_endpoints:
            address = ipaddress.ip_address(peer)
            if not address.is_global or netguard.is_private_ip(peer):
                return "deny", "public OOB control peer is not global unicast"
            return "allow", "declared public OOB control peer admitted"
        if endpoint in self.operator_control_endpoints:
            return "allow", "declared operator OOB control peer admitted"
        return decision, reason

    def decide_dns(self, peer: str, port: int, kind: int,
                   protocol: int) -> tuple[str, str]:
        """Authorize only Quarry's validating DNS mediator, never a tracee."""
        from . import netguard

        try:
            interface = netguard.interface_snapshot()
            current_own = interface.protected_ips
            address = ipaddress.ip_address(peer)
            broadcast = netguard.is_local_broadcast_ip(
                peer, broadcast_ips=interface.broadcast_ips,
            )
        except (OSError, ValueError) as exc:
            raise NetworkBrokerRefused(
                "network_broker_interface_refresh_failed",
            ) from exc
        base_kind = kind & 0xF
        expected = {
            socket.SOCK_STREAM: {0, socket.IPPROTO_TCP},
            socket.SOCK_DGRAM: {0, socket.IPPROTO_UDP},
        }
        if (self.resolver_mode not in {"mediated-public", "mediated-explicit"}
                or port != 53 or peer not in self.resolver_ips
                or base_kind not in expected or protocol not in expected[base_kind]):
            return "deny", "resolver is outside mediated DNS authority"
        if broadcast:
            return "deny", "resolver is a limited or directed broadcast"
        protected = netguard.is_self_attack_ip(
            peer, own_ips=current_own,
            control_plane_cidrs=self.control_plane_cidrs,
        )
        if protected and not (
                self.resolver_mode == "mediated-explicit"
                and (address.is_loopback or peer in current_own)):
            return "deny", "protected scanner/metadata/control-plane resolver"
        explicit_unicast_exception = (
            self.resolver_mode == "mediated-explicit"
            and (address.is_loopback or peer in interface.unicast_ips
                 or netguard.is_private_ip(peer))
        )
        if (address.is_unspecified or address.is_multicast
                or address.is_link_local
                or (netguard.is_non_unicast_ip(peer)
                    and not explicit_unicast_exception)):
            return "deny", "resolver is not a usable unicast peer"
        if self.resolver_mode == "mediated-public" \
                and (not address.is_global or netguard.is_private_ip(peer)):
            return "deny", "ambient private resolver lacks explicit authority"
        return "allow", "configured resolver admitted only for DNS mediation"

    def decide_dns_question(self, payload: bytes) -> tuple[str, str]:
        """Validate the complete one-question DNS UDP query for this source.

        No compression, response sections, EDNS options, or trailing bytes are
        accepted.  dnsx emits one empty 4096-byte EDNS0 OPT record; accepting
        that exact inert suffix preserves compatibility without creating a
        second question or extension channel.
        """
        from . import normalize

        if self.transport_profile != "target-dns":
            return "allow", "DNS payload is not a target-DNS tracee payload"
        allowed_qtypes = _DNS_SOURCE_QTYPES.get(self.source_id)
        if allowed_qtypes is None:
            return "deny", "target DNS source has no query authority"
        if type(payload) is not bytes or not 17 <= len(payload) <= 512:
            return "deny", "DNS UDP payload length is invalid"
        try:
            flags, questions, answers, authority, additional = struct.unpack_from(
                "!HHHHH", payload, 2,
            )
        except struct.error:
            return "deny", "DNS UDP header is truncated"
        # Query, standard opcode, and exactly one IN question; no optional
        # records makes the bounded parser and the sent wire image identical.
        if (flags & ~0x0100 or questions != 1
                or answers or authority or additional not in {0, 1}):
            return "deny", "DNS packet is not one standard query"
        cursor = 12
        labels = []
        while True:
            if cursor >= len(payload):
                return "deny", "DNS question name is truncated"
            size = payload[cursor]
            cursor += 1
            if size == 0:
                break
            # Compression turns the question into an indirect tracee-memory
            # parser and has no place in a request generated by these tools.
            if size > 63 or size & 0xC0 or cursor + size > len(payload):
                return "deny", "DNS question name is compressed or malformed"
            label = payload[cursor:cursor + size]
            cursor += size
            try:
                text = label.decode("ascii")
            except UnicodeDecodeError:
                return "deny", "DNS question name is not ASCII"
            if not text or text.lower() != text:
                return "deny", "DNS question name is not canonical"
            labels.append(text)
            if sum(len(item) + 1 for item in labels) > 253:
                return "deny", "DNS question name exceeds its bound"
        if cursor + 4 > len(payload):
            return "deny", "DNS question has trailing or missing fields"
        qtype, qclass = struct.unpack_from("!HH", payload, cursor)
        cursor += 4
        if additional:
            if cursor + _DNS_EMPTY_OPT.size != len(payload):
                return "deny", "DNS question has malformed EDNS framing"
            owner, record_type, udp_size, ttl, options = \
                _DNS_EMPTY_OPT.unpack_from(payload, cursor)
            if (owner != 0 or record_type != 41
                    or udp_size != _DNS_EMPTY_OPT_UDP_SIZE
                    or ttl != 0 or options != 0):
                return "deny", "DNS question has unsupported EDNS options"
        elif cursor != len(payload):
            return "deny", "DNS question has trailing or missing fields"
        if qclass != 1 or qtype not in allowed_qtypes:
            return "deny", "DNS question type is outside source authority"
        name = ".".join(labels)
        if qtype == _DNS_QTYPE_PTR:
            address = self._ptr_question_address(name)
            if address is None:
                return "deny", "PTR question is not a canonical reverse address"
            if not any(address.version == network.version and address in network
                       for network in map(ipaddress.ip_network, self.effective_cidrs)):
                return "deny", "PTR question is outside effective CIDR authority"
            return "allow", "PTR question is inside effective CIDR authority"
        if self.source_id == "osint.dmarc":
            if not any(name == f"_dmarc.{apex}" for apex in self.apex_domains):
                return "deny", "DMARC question is outside active apex authority"
            return "allow", "DMARC question is inside active apex authority"
        if normalize.canon_host_strict(name) != name:
            return "deny", "DNS question name is not canonical"
        if not any(name == apex or name.endswith("." + apex)
                   for apex in self.apex_domains):
            return "deny", "DNS question is outside active apex authority"
        if any(oos_search(pattern, name) for pattern in self.oos_patterns):
            return "deny", "DNS question matches an out-of-scope rule"
        return "allow", "DNS question is inside active apex authority"

    @staticmethod
    def _ptr_question_address(name: str) -> ipaddress._BaseAddress | None:
        """Decode one uncompressed in-addr.arpa/ip6.arpa name exactly."""
        labels = name.split(".")
        try:
            if len(labels) == 6 and labels[-2:] == ["in-addr", "arpa"]:
                octets = labels[:4]
                if any(not item.isdecimal() or str(int(item)) != item
                       or not 0 <= int(item) <= 255 for item in octets):
                    return None
                return ipaddress.ip_address(".".join(reversed(octets)))
            if len(labels) == 34 and labels[-2:] == ["ip6", "arpa"]:
                nibbles = labels[:32]
                if any(len(item) != 1 or item not in "0123456789abcdef"
                       for item in nibbles):
                    return None
                return ipaddress.ip_address("".join(reversed(nibbles)))
        except ValueError:
            pass
        return None

    def dns_name_allowed(self, name: str) -> tuple[str, str]:
        """Authorize one canonical DNS question owned by Nuclei's SOCKS lane."""
        from . import normalize

        if (self.transport_profile != "nuclei-authorized-http"
                or self.nuclei_protocol_lane != "http,dns"):
            return "deny", "DNS question is outside the Nuclei protocol lane"
        if type(name) is not str or normalize.canon_host_strict(name) != name:
            return "deny", "DNS question name is not canonical"
        if any(name == apex or name.endswith("." + apex)
               for apex in self.apex_domains):
            if any(oos_search(pattern, name) for pattern in self.oos_patterns):
                return "deny", "DNS question matches an out-of-scope rule"
            return "allow", "DNS question is inside the active apex scope"

        def endpoint_host(endpoint: str) -> str:
            if endpoint.startswith("["):
                return endpoint[1:endpoint.index("]")]
            return endpoint.rsplit(":", 1)[0]

        suffixes = tuple(endpoint_host(value) for value in (
            self.public_control_endpoints + self.operator_control_endpoints
        ))
        if any(name == suffix or name.endswith("." + suffix)
               for suffix in suffixes):
            return "allow", "DNS question is inside declared OOB suffix authority"
        return "deny", "DNS question is outside target/OOB authority"


@dataclass
class _ControlListener:
    fd: int
    peer: str
    port: int
    identity: tuple[int, int]
    request_id: str
    owner_tgid: int
    owner_fd: int
    owner_token: object
    client_identities: tuple[tuple[str, int], ...]
    client_tgids: tuple[int, ...]
    purpose: str
    authentication: bytes | None = None
    requested_unix: bytes | None = None
    actual_unix: bytes | None = None


@dataclass
class _ControlGrant:
    listener_identity: tuple[int, int]
    listener_owner_token: object
    request_id: str
    owner_token: object
    client_fd: int
    client_identity: tuple[int, int]
    client_tgid: int
    executable_identity: tuple[str, int]
    family: int
    client_endpoint: object
    server_endpoint: object
    armed: bool = False
    committed: bool = False


class ControlEndpointRegistry:
    """Worker-local cross-listener registry for one external browser channel."""

    def __init__(self):
        self._lock = threading.Lock()
        self._condition = threading.Condition(self._lock)
        self._endpoints: dict[tuple[str, str, int], _ControlListener] = {}
        self._grants: list[_ControlGrant] = []

    def register(self, control: _ControlListener) -> None:
        key = (control.request_id, control.peer, control.port)
        with self._condition:
            if key in self._endpoints:
                raise NetworkBrokerRefused("network_broker_control_endpoint_duplicate")
            self._endpoints[key] = control
            self._condition.notify_all()

    def lookup(self, request_id: str, peer: str, port: int) -> _ControlListener | None:
        with self._condition:
            return self._endpoints.get((request_id, peer, port))

    def discard(self, control: _ControlListener) -> None:
        key = (control.request_id, control.peer, control.port)
        with self._condition:
            if self._endpoints.get(key) is control:
                self._endpoints.pop(key, None)
            try:
                self._discard_grants_locked(
                    lambda grant: grant.listener_identity == control.identity,
                )
            finally:
                self._condition.notify_all()

    def discard_owner(self, owner_token: object) -> None:
        with self._condition:
            stale = [key for key, value in self._endpoints.items()
                     if value.owner_token is owner_token]
            for key in stale:
                self._endpoints.pop(key, None)
            try:
                self._discard_grants_locked(
                    lambda grant: grant.owner_token is owner_token
                    or grant.listener_owner_token is owner_token,
                )
            finally:
                self._condition.notify_all()

    @staticmethod
    def _grant_fd_closed(grant: _ControlGrant) -> bool:
        """Prove the owned descriptor is gone without touching a reused fd."""
        try:
            observed = os.fstat(grant.client_fd)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                return True
            raise NetworkBrokerRefused(
                "network_broker_control_grant_close_unverified",
            ) from exc
        return (observed.st_dev, observed.st_ino) != grant.client_identity

    def _close_grant_locked(self, grant: _ControlGrant) -> None:
        if self._grant_fd_closed(grant):
            return
        close_fault = None
        try:
            os.close(grant.client_fd)
        except OSError as exc:
            close_fault = exc
        try:
            closed = self._grant_fd_closed(grant)
        except NetworkBrokerRefused as exc:
            if close_fault is None:
                close_fault = exc
            closed = False
        if not closed:
            raise NetworkBrokerRefused(
                "network_broker_control_grant_close_failed",
            ) from close_fault

    def _discard_grants_locked(self, predicate) -> None:
        retained: list[_ControlGrant] = []
        failures: list[BaseException] = []
        cancellation = None
        for grant in self._grants:
            if predicate(grant):
                try:
                    self._close_grant_locked(grant)
                except BaseException as exc:
                    retained.append(grant)
                    failures.append(exc)
                    if not isinstance(exc, Exception) and cancellation is None:
                        cancellation = exc
            else:
                retained.append(grant)
        self._grants = retained
        if cancellation is not None:
            raise cancellation
        if failures:
            raise NetworkBrokerRefused(
                "network_broker_control_grant_close_failed",
            ) from failures[0]

    @staticmethod
    def _connection_endpoints(fd: int, family: int) -> tuple[object, object]:
        handle = socket.socket(fileno=fd)
        try:
            client = handle.getsockname()
            server = handle.getpeername()
        finally:
            handle.detach()
        if family in {socket.AF_INET, socket.AF_INET6}:
            try:
                client_address = ipaddress.ip_address(client[0])
                server_address = ipaddress.ip_address(server[0])
                client = (
                    str(getattr(client_address, "ipv4_mapped", None)
                        or client_address), int(client[1]),
                )
                server = (
                    str(getattr(server_address, "ipv4_mapped", None)
                        or server_address), int(server[1]),
                )
            except (ValueError, TypeError, IndexError) as exc:
                raise NetworkBrokerRefused(
                    "network_broker_control_connection_unverified",
                ) from exc
        return client, server

    def authorize_connection(
            self, control: _ControlListener, *, client_fd: int,
            client_tgid: int, executable_identity: tuple[str, int],
            owner_token: object) -> _ControlGrant:
        """Hold one connected OFD and mint one accept-consumable grant."""
        held = -1
        try:
            family, kind, protocol = _socket_metadata(client_fd)
            if (kind & 0xF != socket.SOCK_STREAM
                    or family not in {socket.AF_INET, socket.AF_INET6, socket.AF_UNIX}
                    or (family in {socket.AF_INET, socket.AF_INET6}
                        and protocol not in {0, socket.IPPROTO_TCP})
                    or (family == socket.AF_UNIX and protocol != 0)):
                raise NetworkBrokerRefused(
                    "network_broker_control_connection_unverified",
                )
            client_endpoint, server_endpoint = self._connection_endpoints(
                client_fd, family,
            )
            if family in {socket.AF_INET, socket.AF_INET6}:
                if server_endpoint != (control.peer, control.port):
                    raise NetworkBrokerRefused(
                        "network_broker_control_connection_unverified",
                    )
            elif server_endpoint != control.actual_unix:
                raise NetworkBrokerRefused(
                    "network_broker_control_connection_unverified",
                )
            held = os.dup(client_fd)
            grant = _ControlGrant(
                control.identity, control.owner_token, control.request_id,
                owner_token, held, _socket_identity(client_fd), client_tgid,
                executable_identity, family, client_endpoint, server_endpoint,
            )
            with self._condition:
                if len(self._grants) >= _MAX_CONTROL_GRANTS:
                    raise NetworkBrokerRefused(
                        "network_broker_control_grant_capacity_exhausted",
                    )
                self._grants.append(grant)
                self._condition.notify_all()
            held = -1
            return grant
        finally:
            if held >= 0:
                os.close(held)

    def arm_connection(self, grant: _ControlGrant) -> None:
        with self._condition:
            if not any(observed is grant for observed in self._grants):
                raise NetworkBrokerRefused(
                    "network_broker_control_grant_missing",
                )
            try:
                if (_socket_identity(grant.client_fd) != grant.client_identity
                        or self._connection_endpoints(
                            grant.client_fd, grant.family,
                        ) != (grant.client_endpoint, grant.server_endpoint)):
                    raise NetworkBrokerRefused(
                        "network_broker_control_grant_changed",
                    )
            except OSError as exc:
                raise NetworkBrokerRefused(
                    "network_broker_control_grant_changed",
                ) from exc
            grant.armed = True
            self._condition.notify_all()

    def commit_connection(self, grant: _ControlGrant) -> None:
        """Expose a replied connection only after its terminal trace exists."""
        with self._condition:
            if (not grant.armed
                    or not any(observed is grant for observed in self._grants)):
                raise NetworkBrokerRefused(
                    "network_broker_control_grant_missing",
                )
            grant.committed = True
            self._condition.notify_all()

    def revoke_connection(self, grant: _ControlGrant) -> None:
        with self._condition:
            try:
                for index, observed in enumerate(self._grants):
                    if observed is grant:
                        self._close_grant_locked(grant)
                        self._grants.pop(index)
                        break
            finally:
                self._condition.notify_all()

    def consume_connection(
            self, control: _ControlListener, *, accepted_fd: int,
            deadline_monotonic: float,
            stop_event: threading.Event) -> _ControlGrant | None:
        """Atomically consume the exact one-shot grant for an accepted OFD."""
        family, kind, protocol = _socket_metadata(accepted_fd)
        if (kind & 0xF != socket.SOCK_STREAM
                or family not in {socket.AF_INET, socket.AF_INET6, socket.AF_UNIX}
                or (family in {socket.AF_INET, socket.AF_INET6}
                    and protocol not in {0, socket.IPPROTO_TCP})
                or (family == socket.AF_UNIX and protocol != 0)):
            return None
        accepted_local, accepted_peer = self._connection_endpoints(
            accepted_fd, family,
        )
        peer_tgid = peer_uid = peer_gid = None
        if family == socket.AF_UNIX:
            handle = socket.socket(fileno=accepted_fd)
            try:
                raw = handle.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            finally:
                handle.detach()
            try:
                peer_tgid, peer_uid, peer_gid = struct.unpack("=iii", raw)
            except struct.error:
                return None
        with self._condition:
            while True:
                if stop_event.is_set():
                    return None
                for index, grant in enumerate(tuple(self._grants)):
                    if (grant.listener_identity != control.identity
                            or grant.request_id != control.request_id
                            or grant.family != family or not grant.committed
                            or grant.client_endpoint != accepted_peer
                            or grant.server_endpoint != accepted_local
                            or (family == socket.AF_UNIX and (
                                peer_tgid != os.getpid()
                                or peer_uid != os.geteuid()
                                or peer_gid != os.getegid()
                            ))):
                        continue
                    try:
                        identity = _socket_identity(grant.client_fd)
                    except (OSError, NetworkBrokerError) as exc:
                        # An identity read can race an earlier close whose
                        # result was uncertain.  Reap only after the separate
                        # descriptor liveness check proves that this exact
                        # grant fd is gone (or has been reused).  In
                        # particular, do not use endpoint validation below as
                        # a reason to close or discard an otherwise live
                        # grant.
                        try:
                            closed = self._grant_fd_closed(grant)
                        except NetworkBrokerRefused as probe_exc:
                            raise NetworkBrokerRefused(
                                "network_broker_control_grant_close_failed",
                            ) from probe_exc
                        if not closed:
                            raise NetworkBrokerRefused(
                                "network_broker_control_grant_changed",
                            ) from exc
                        self._grants.pop(index)
                        self._condition.notify_all()
                        continue
                    if identity != grant.client_identity:
                        self._grants.pop(index)
                        self._condition.notify_all()
                        continue
                    try:
                        endpoints = self._connection_endpoints(grant.client_fd, family)
                    except (OSError, NetworkBrokerError):
                        continue
                    if endpoints != (grant.client_endpoint, grant.server_endpoint):
                        continue
                    selected = grant
                    try:
                        self._close_grant_locked(selected)
                    except BaseException:
                        self._condition.notify_all()
                        raise
                    self._grants.pop(index)
                    self._condition.notify_all()
                    return selected
                remaining = deadline_monotonic - time.monotonic()
                if remaining <= 0:
                    return None
                self._condition.wait(timeout=min(0.02, remaining))

    def register_worker_listener(
            self, *, request_id: str, listener_fd: int,
            client_identities: tuple[tuple[str, int], ...], purpose: str,
            owner_token: object,
            client_tgids: tuple[int, ...] = ()) -> _ControlListener:
        """Register one already-listening worker-owned loopback endpoint."""
        if (_HEX32.fullmatch(request_id) is None
                or purpose not in {
                    "pinned-browser-proxy", "browser-devtools-pipe",
                }
                or not client_identities
                or tuple(sorted(set(client_identities))) != client_identities
                or type(client_tgids) is not tuple
                or tuple(sorted(set(client_tgids))) != client_tgids
                or any(type(tgid) is not int or not 1 <= tgid < (1 << 30)
                       for tgid in client_tgids)):
            raise NetworkBrokerRefused(
                "network_broker_control_endpoint_registration_invalid",
            )
        try:
            domain, kind, protocol = _socket_metadata(listener_fd)
            identity = _socket_identity(listener_fd)
            handle = socket.socket(fileno=listener_fd)
            try:
                observed = handle.getsockname()
                accepting = handle.getsockopt(
                    socket.SOL_SOCKET, socket.SO_ACCEPTCONN,
                ) == 1
            finally:
                handle.detach()
            address = ipaddress.ip_address(observed[0])
            peer = str(getattr(address, "ipv4_mapped", None) or address)
            port = int(observed[1])
        except (OSError, ValueError, TypeError, IndexError) as exc:
            raise NetworkBrokerRefused(
                "network_broker_control_endpoint_registration_invalid",
            ) from exc
        if (domain not in {socket.AF_INET, socket.AF_INET6}
                or kind & 0xF != socket.SOCK_STREAM
                or protocol not in {0, socket.IPPROTO_TCP}
                or peer not in {"127.0.0.1", "::1"}
                or not 1 <= port <= 65535 or not accepting):
            raise NetworkBrokerRefused(
                "network_broker_control_endpoint_registration_invalid",
            )
        held = os.dup(listener_fd)
        control = _ControlListener(
            held, peer, port, identity, request_id, os.getpid(), listener_fd,
            owner_token, client_identities, client_tgids, purpose, os.urandom(32),
        )
        try:
            self.register(control)
        except BaseException:
            os.close(held)
            raise
        return control

    def close_worker_listener(self, control: _ControlListener) -> None:
        if type(control) is not _ControlListener \
                or control.owner_tgid != os.getpid() \
                or control.purpose not in {
                    "pinned-browser-proxy", "browser-devtools-pipe",
                }:
            raise NetworkBrokerRefused(
                "network_broker_control_endpoint_registration_invalid",
            )
        self.discard(control)
        try:
            observed = os.fstat(control.fd)
            if (observed.st_dev, observed.st_ino) != control.identity:
                return
            os.close(control.fd)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise NetworkBrokerRefused(
                    "network_broker_control_close_failed",
                ) from exc

    def worker_listener_closed(self, control: _ControlListener) -> bool:
        """Prove the retained listener OFD is gone without closing a reused fd."""
        if type(control) is not _ControlListener \
                or control.owner_tgid != os.getpid():
            raise NetworkBrokerRefused(
                "network_broker_control_endpoint_registration_invalid",
            )
        if self.lookup(control.request_id, control.peer, control.port) is control:
            return False
        try:
            observed = os.fstat(control.fd)
            return (observed.st_dev, observed.st_ino) != control.identity
        except OSError as exc:
            if exc.errno == errno.EBADF:
                return True
            raise NetworkBrokerRefused(
                "network_broker_control_close_unverified",
            ) from exc


def _socket_identity(fd: int) -> tuple[int, int]:
    observed = os.fstat(fd)
    if not stat.S_ISSOCK(observed.st_mode):
        raise NetworkBrokerRefused("network_broker_tracee_fd_not_socket")
    return observed.st_dev, observed.st_ino


def _hash_tracee_executable(tid: int, *, validate,
                            deadline_monotonic: float | None = None,
                            expected_sizes: tuple[int, ...] = (),
                            ) -> tuple[str, int]:
    if deadline_monotonic is None:
        deadline_monotonic = time.monotonic() + _MAX_EXECUTABLE_HASH_SECONDS
    if (type(deadline_monotonic) not in {int, float}
            or not math.isfinite(deadline_monotonic)):
        raise NetworkBrokerRefused("network_broker_helper_identity_failed")
    validate()
    try:
        fd = os.open(
            f"/proc/{tid}/exe", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as exc:
        raise NetworkBrokerRefused("network_broker_helper_identity_failed") from exc
    try:
        observed = os.fstat(fd)
        if (not stat.S_ISREG(observed.st_mode)
                or not 1 <= observed.st_size <= _MAX_EXECUTABLE_BYTES
                or expected_sizes and observed.st_size not in expected_sizes):
            raise NetworkBrokerRefused("network_broker_helper_identity_failed")
        digest = hashlib.sha256()
        total = 0
        while total < observed.st_size:
            validate()
            if time.monotonic() >= deadline_monotonic:
                raise NetworkBrokerRefused(
                    "network_broker_helper_identity_deadline_expired",
                )
            block = os.read(fd, min(1024 * 1024, observed.st_size - total))
            expired = time.monotonic() >= deadline_monotonic
            if not block or len(block) > observed.st_size - total or expired:
                raise NetworkBrokerRefused(
                    "network_broker_helper_identity_deadline_expired"
                    if expired else "network_broker_helper_identity_changed",
                )
            digest.update(block)
            total += len(block)
        after = os.fstat(fd)
        if ((observed.st_dev, observed.st_ino, observed.st_size,
             observed.st_mtime_ns, observed.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_size,
                    after.st_mtime_ns, after.st_ctime_ns)):
            raise NetworkBrokerRefused("network_broker_helper_identity_changed")
    finally:
        os.close(fd)
    validate()
    return digest.hexdigest(), total


class NetworkBrokerSession:
    """One listener owner and bounded, cancellation-fenced broker thread."""

    def __init__(self, handoff: ListenerHandoff, policy: BrokerPolicy, *,
                 control_registry: ControlEndpointRegistry | None = None,
                 expected_profile: str,
                 deadline_monotonic: float,
                 cancellation_event: threading.Event | None = None,
                 effect_fence: NetworkEffectFence | None = None,
                 dns_mediator_authentication: bytes | None = None):
        if type(policy) is not BrokerPolicy:
            raise NetworkBrokerRefused("network_broker_policy_invalid")
        if type(handoff) is not ListenerHandoff:
            raise NetworkBrokerRefused("network_broker_handoff_identity_invalid")
        if (expected_profile not in _PROFILE_IDS
                or handoff.profile != expected_profile):
            raise NetworkBrokerRefused("network_broker_filter_profile_mismatch")
        _validate_pidfd(handoff.child_pidfd)
        if (type(deadline_monotonic) not in {int, float}
                or not math.isfinite(deadline_monotonic)
                or deadline_monotonic <= time.monotonic()):
            raise NetworkBrokerRefused("network_broker_deadline_invalid")
        if cancellation_event is not None \
                and not isinstance(cancellation_event, threading.Event):
            raise NetworkBrokerRefused("network_broker_cancellation_invalid")
        if effect_fence is not None and type(effect_fence) is not NetworkEffectFence:
            raise NetworkBrokerRefused("network_effect_fence_invalid")
        if (effect_fence is not None and cancellation_event is not None
                and effect_fence.event is not cancellation_event):
            raise NetworkBrokerRefused("network_effect_fence_event_mismatch")
        if policy.transport_profile == "target-dns":
            if (type(dns_mediator_authentication) is not bytes
                    or len(dns_mediator_authentication) != _DNS_MEDIATOR_AUTH_BYTES):
                raise NetworkBrokerRefused("network_dns_mediator_authentication_invalid")
        elif dns_mediator_authentication is not None:
            raise NetworkBrokerRefused("network_dns_mediator_authentication_invalid")
        listener_fd = handoff.listener_fd
        _validate_listener_fd(listener_fd)
        try:
            status_flags = fcntl.fcntl(listener_fd, fcntl.F_GETFL)
            fcntl.fcntl(listener_fd, fcntl.F_SETFL, status_flags | os.O_NONBLOCK)
        except OSError as exc:
            raise NetworkBrokerRefused("network_broker_listener_nonblock_failed") from exc
        self._listener_fd = listener_fd
        self._child_pidfd = handoff.child_pidfd
        self._profile = handoff.profile
        self._policy = policy
        # This runtime capability is intentionally not a BrokerPolicy field:
        # policy JSON is inherited by the tracee, while this token stays only
        # in the worker's mediator and broker objects.
        self._dns_mediator_authentication = dns_mediator_authentication
        self._deadline = float(deadline_monotonic)
        self._architecture = _architecture()
        self._local_stop = threading.Event()
        self._effect_fence = effect_fence or NetworkEffectFence(cancellation_event)
        self._shared_stop = self._effect_fence
        self._stop = _CombinedCancellation(
            self._local_stop, self._shared_stop,
        )
        self._effect_lock = self._effect_fence
        self._records_lock = threading.Lock()
        self._records: list[BrokerDecision] = []
        self._record_bytes = 0
        self._open_plans: dict[tuple[int, str], int] = {}
        self._dropped = 0
        self._fatal: str | None = None
        self._debug_exception: str | None = None
        self._listener_hup = False
        self._thread: threading.Thread | None = None
        self._operation_slots = threading.BoundedSemaphore(
            _MAX_NOTIFICATION_WORKERS,
        )
        self._operation_lock = threading.Lock()
        self._operation_threads: set[threading.Thread] = set()
        self._identity_lock = threading.Lock()
        self._control_listeners: dict[tuple[int, int], _ControlListener] = {}
        self._control_registry = control_registry or ControlEndpointRegistry()
        self._control_owner_token = object()
        self._control_connections: set[tuple[int, int]] = set()
        self._singleton_controls: dict[bytes, _ControlListener] = {}
        self._executable_cache: dict[tuple[int, ...], tuple[str, int]] = {}
        self._retained_lock = threading.Lock()
        self._retained_connections: set[socket.socket] = set()

    @property
    def fatal(self) -> str | None:
        return self._fatal

    def start(self) -> None:
        if self._thread is not None:
            raise NetworkBrokerError("network_broker_already_started")
        self._thread = threading.Thread(
            target=self._run, name="quarry-network-broker", daemon=False,
        )
        self._thread.start()

    def stop(self) -> None:
        """Abort/fence future effects, close the listener, and join."""
        self._local_stop.set()
        with self._effect_fence.settlement():
            self._control_registry.discard_owner(self._control_owner_token)
            for listener_control in tuple(self._control_listeners.values()):
                try:
                    os.close(listener_control.fd)
                except OSError as exc:
                    if exc.errno != errno.EBADF and self._fatal is None:
                        self._fatal = "network_broker_control_close_failed"
            self._control_listeners.clear()
            self._control_connections.clear()
            self._singleton_controls.clear()
            self._drain_retained_connections()
            listener = self._listener_fd
            self._listener_fd = -1
            if listener >= 0:
                try:
                    os.close(listener)
                except OSError as exc:
                    if exc.errno != errno.EBADF and self._fatal is None:
                        self._fatal = "network_broker_listener_close_failed"
            child_pidfd = self._child_pidfd
            self._child_pidfd = -1
            if child_pidfd >= 0:
                try:
                    os.close(child_pidfd)
                except OSError as exc:
                    if exc.errno != errno.EBADF and self._fatal is None:
                        self._fatal = "network_broker_pidfd_close_failed"
        deadline = time.monotonic() + _BROKER_SETTLEMENT_SECONDS
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(0.0, deadline - time.monotonic()))
            if thread.is_alive() and self._fatal is None:
                self._fatal = "network_broker_thread_settlement_failed"
        while True:
            with self._operation_lock:
                operations = tuple(
                    operation for operation in self._operation_threads
                    if operation is not threading.current_thread()
                )
            if not operations:
                break
            for operation in operations:
                operation.join(timeout=max(0.0, deadline - time.monotonic()))
            with self._operation_lock:
                alive = tuple(
                    operation for operation in self._operation_threads
                    if operation.is_alive()
                )
            if not alive:
                break
            if time.monotonic() >= deadline:
                self._fatal = self._fatal or (
                    "network_broker_operation_settlement_failed"
                )
                break

    def settle_after_tasks(self, *, deadline_monotonic: float) -> None:
        """Require kernel listener HUP after the authenticated task set empties."""
        if type(deadline_monotonic) not in {int, float} \
                or not math.isfinite(deadline_monotonic):
            raise NetworkBrokerRefused("network_broker_settlement_deadline_invalid")
        thread = self._thread
        if thread is None:
            raise NetworkBrokerRefused("network_broker_not_started")
        while thread.is_alive() and time.monotonic() < deadline_monotonic:
            thread.join(timeout=min(0.05, deadline_monotonic - time.monotonic()))
        if thread.is_alive() or not self._listener_hup:
            self._fatal = self._fatal or "network_broker_listener_hup_unproved"
            self.stop()
            return
        self.stop()

    def summary(self) -> dict:
        with self._records_lock:
            records = [record.to_dict() for record in self._records]
            dropped = self._dropped
            open_plans = len(self._open_plans)
        with self._operation_lock:
            active_operations = sum(
                operation.is_alive() for operation in self._operation_threads
            )
        with self._retained_lock:
            retained_connections = len(self._retained_connections)
        return {
            "schema_version": "quarry.network-broker-summary.v1",
            "request_id": self._policy.request_id,
            "profile": self._profile,
            "records": records,
            "dropped_records": dropped,
            "open_plans": open_plans,
            "fatal": self._fatal,
            "listener_hup": self._listener_hup,
            "active_operations": active_operations,
            "retained_connections": retained_connections,
            "complete": (
                self._fatal is None and self._listener_fd < 0
                and dropped == 0
                and open_plans == 0
                and self._listener_hup
                and (self._thread is None or not self._thread.is_alive())
                and active_operations == 0
                and retained_connections == 0
            ),
        }

    def _retain_connected(self, fd: int) -> socket.socket:
        held = socket.socket(fileno=os.dup(fd))
        try:
            self._effect_fence.track_socket(held)
            with self._retained_lock:
                # Every successful connect consumes at least two journal rows;
                # the journal limit therefore bounds retained descriptors too.
                if len(self._retained_connections) >= _MAX_DECISIONS // 2:
                    raise NetworkBrokerRefused(
                        "network_broker_retained_connection_capacity",
                    )
                self._retained_connections.add(held)
            return held
        except BaseException:
            self._effect_fence.close_tracked_socket(held, shutdown=False)
            raise

    def _release_retained(self, handle: socket.socket, *, shutdown: bool = True) -> None:
        self._effect_fence.close_tracked_socket(handle, shutdown=shutdown)
        with self._retained_lock:
            self._retained_connections.discard(handle)

    def _drain_retained_connections(self) -> None:
        with self._retained_lock:
            retained = tuple(self._retained_connections)
        for handle in retained:
            self._effect_fence.close_tracked_socket(handle)
            with self._retained_lock:
                self._retained_connections.discard(handle)

    def _record(self, *, syscall: str, tid: int, peer, port, kind: int,
                protocol: int, decision: str, reason: str,
                stage: str = "settled", result: str | None = None) -> bool:
        if stage not in {"planned", "admitted", "settled"}:
            self._fatal = "network_broker_decision_stage_invalid"
            self._stop.set()
            return False
        failed = None
        with self._records_lock:
            sequence = len(self._records) + self._dropped
            record = BrokerDecision(
                sequence, stage, syscall, tid, peer, port, kind, protocol,
                decision, reason, result,
            )
            encoded = json.dumps(
                record.to_dict(), ensure_ascii=True, sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            if len(encoded) > _MAX_RECORD_BYTES:
                failed = "network_broker_decision_record_oversize"
            else:
                key = (tid, syscall)
                reserved = sum(self._open_plans.values())
                used_bytes = getattr(self, "_record_bytes", 0)
                if stage == "planned":
                    # Reserve the admitted+terminal worst-case footprint before
                    # the plan can authorize any effect.  Bind/listen/send use
                    # only the terminal row and release the spare at settlement.
                    if key in self._open_plans:
                        failed = "network_broker_decision_plan_duplicate"
                    elif len(self._records) + reserved + 3 > _MAX_DECISIONS:
                        failed = "network_broker_decision_record_overflow"
                    elif (used_bytes + len(encoded) + 1
                          + (reserved + 2) * (_MAX_RECORD_BYTES + 1)
                          > _MAX_DECISION_SUMMARY_BYTES):
                        failed = "network_broker_decision_record_overflow"
                    else:
                        self._records.append(record)
                        self._record_bytes = used_bytes + len(encoded) + 1
                        self._open_plans[key] = 2
                elif stage == "admitted":
                    remaining = self._open_plans.get(key, 0)
                    if remaining < 1:
                        failed = "network_broker_decision_plan_missing"
                    elif (used_bytes + len(encoded) + 1
                          + (reserved - 1) * (_MAX_RECORD_BYTES + 1)
                          > _MAX_DECISION_SUMMARY_BYTES):
                        failed = "network_broker_decision_record_overflow"
                    else:
                        self._records.append(record)
                        self._record_bytes = used_bytes + len(encoded) + 1
                        self._open_plans[key] = remaining - 1
                elif key in self._open_plans:
                    remaining = self._open_plans.pop(key)
                    if remaining < 1:
                        failed = "network_broker_decision_plan_exhausted"
                    elif (used_bytes + len(encoded) + 1
                          + (reserved - remaining) * (_MAX_RECORD_BYTES + 1)
                          > _MAX_DECISION_SUMMARY_BYTES):
                        failed = "network_broker_decision_record_overflow"
                    else:
                        self._records.append(record)
                        self._record_bytes = used_bytes + len(encoded) + 1
                elif (len(self._records) + reserved < _MAX_DECISIONS
                      and used_bytes + len(encoded) + 1
                      + reserved * (_MAX_RECORD_BYTES + 1)
                      <= _MAX_DECISION_SUMMARY_BYTES):
                    self._records.append(record)
                    self._record_bytes = used_bytes + len(encoded) + 1
                else:
                    failed = "network_broker_decision_record_overflow"
            if failed is not None:
                self._dropped += 1
                self._fatal = self._fatal or failed
        if failed is not None:
            # Never wait on the effect fence while holding the record lock: an
            # in-flight effect may be trying to write its terminal row.
            self._stop.set()
            return False
        return True

    def _journal_capacity(self, count: int) -> bool:
        if type(count) is not int or count < 0:
            self._fatal = "network_broker_decision_reservation_invalid"
            self._stop.set()
            return False
        with self._records_lock:
            available = (
                _MAX_DECISIONS - len(self._records)
                - sum(self._open_plans.values())
            )
            used_bytes = getattr(self, "_record_bytes", 0)
            available_bytes = (
                _MAX_DECISION_SUMMARY_BYTES - used_bytes
                - sum(self._open_plans.values()) * (_MAX_RECORD_BYTES + 1)
            )
        if (available < count
                or available_bytes < count * (_MAX_RECORD_BYTES + 1)):
            self._fatal = "network_broker_decision_record_overflow"
            self._stop.set()
            return False
        return True

    def _settle_abandoned_notification(self, notification: _SeccompNotif,
                                       result: str) -> None:
        """Close a reserved plan when a handler exits on a fault/cancel edge.

        The reservation is itself durable authority: leaving it open would let
        cleanup turn a post-plan failure into an apparently complete summary.
        A TID cannot have two instances of the same syscall in flight, so the
        ``(tid, syscall)`` key exactly identifies the pending notification.
        """
        names = {
            self._architecture.connect: "connect",
            self._architecture.sendto: "sendto",
            self._architecture.sendmsg: "sendmsg",
            self._architecture.bind: "bind",
            self._architecture.listen: "listen",
            self._architecture.accept: "accept",
            self._architecture.accept4: "accept4",
        }
        syscall = names.get(int(notification.data.nr), "unknown")
        key = (int(notification.pid), syscall)
        with self._records_lock:
            if key not in self._open_plans:
                return
            planned = next(
                (record for record in reversed(self._records)
                 if record.tid == key[0] and record.syscall == key[1]
                 and record.stage == "planned"),
                None,
            )
        if planned is None:
            self._fatal = self._fatal or "network_broker_decision_plan_lost"
            self._stop.set()
            return
        self._record(
            syscall=planned.syscall, tid=planned.tid, peer=planned.peer,
            port=planned.port, kind=planned.socket_type,
            protocol=planned.protocol, decision="deny",
            reason="broker operation did not reach an authenticated commit",
            stage="settled", result=result,
        )

    def _run(self) -> None:
        try:
            poller = select.poll()
            poller.register(
                self._listener_fd,
                select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL,
            )
            while (not self._local_stop.is_set()
                   and time.monotonic() < self._deadline):
                listener = self._listener_fd
                if listener < 0:
                    break
                try:
                    events = poller.poll(50)
                except (OSError, ValueError):
                    if self._stop.is_set():
                        break
                    raise
                if not events:
                    continue
                mask = 0
                for observed_fd, observed_mask in events:
                    if observed_fd != listener:
                        raise NetworkBrokerError("network_broker_poll_identity_failed")
                    mask |= observed_mask
                if mask & (select.POLLHUP | select.POLLERR | select.POLLNVAL):
                    self._listener_hup = bool(mask & select.POLLHUP)
                    if self._listener_hup:
                        with self._effect_fence.settlement():
                            self._drain_retained_connections()
                    break
                if not mask & select.POLLIN:
                    continue
                notification = _SeccompNotif()
                try:
                    _ioctl(listener, _SECCOMP_IOCTL_NOTIF_RECV, notification)
                except OSError as exc:
                    if exc.errno in {errno.EINTR, errno.EAGAIN, errno.ENOENT}:
                        continue
                    if self._stop.is_set() and exc.errno in {errno.EBADF, errno.EINVAL}:
                        break
                    raise
                self._dispatch(notification)
            if time.monotonic() >= self._deadline and not self._listener_hup:
                self._fatal = self._fatal or "network_broker_deadline_expired"
                self._stop.set()
            listener = self._listener_fd
            self._listener_fd = -1
            if listener >= 0:
                os.close(listener)
        except BaseException as exc:
            self._debug_exception = repr(exc)
            if not self._stop.is_set():
                self._fatal = self._fatal or (
                    str(exc) if isinstance(exc, NetworkBrokerError)
                    else "network_broker_loop_failed"
                )
            self._stop.set()
            listener = self._listener_fd
            self._listener_fd = -1
            if listener >= 0:
                try:
                    os.close(listener)
                except OSError:
                    pass

    def _dispatch(self, notification: _SeccompNotif) -> None:
        if time.monotonic() >= self._deadline:
            self._record(
                syscall="unknown", tid=notification.pid, peer=None, port=None,
                kind=0, protocol=0, decision="deny",
                reason="broker invocation deadline expired",
                stage="settled", result="ETIMEDOUT",
            )
            self._respond(notification.id, error=errno.ETIMEDOUT)
            return
        if not self._operation_slots.acquire(blocking=False):
            self._fatal = self._fatal or (
                "network_broker_notification_capacity_exhausted"
            )
            # Capacity loss means the boundary cannot classify this syscall.
            # Fence the whole invocation before acknowledging the refusal so a
            # later notification cannot proceed under partial authority.
            self._stop.set()
            self._record(
                syscall="unknown", tid=notification.pid, peer=None, port=None,
                kind=0, protocol=0, decision="deny",
                reason="broker notification capacity exhausted",
                stage="settled", result="EBUSY",
            )
            self._respond(notification.id, error=errno.EBUSY)
            return

        def operation() -> None:
            current = threading.current_thread()
            try:
                self._handle(notification)
            except BaseException as exc:
                if not self._stop.is_set():
                    self._fatal = self._fatal or (
                        str(exc) if isinstance(exc, NetworkBrokerError)
                        else "network_broker_operation_failed"
                    )
                    try:
                        self._respond(notification.id, error=errno.EPERM)
                    except OSError:
                        pass
                    self._stop.set()
            finally:
                self._settle_abandoned_notification(
                    notification,
                    "operation-cancelled" if self._stop.is_set()
                    else "operation-aborted",
                )
                with self._operation_lock:
                    self._operation_threads.discard(current)
                self._operation_slots.release()

        worker = threading.Thread(
            target=operation, name="quarry-network-operation", daemon=False,
        )
        with self._operation_lock:
            self._operation_threads.add(worker)
        try:
            worker.start()
        except BaseException:
            with self._operation_lock:
                self._operation_threads.discard(worker)
            self._operation_slots.release()
            self._fatal = self._fatal or "network_broker_operation_start_failed"
            self._respond(notification.id, error=errno.EPERM)
            self._stop.set()

    def _handle(self, notification: _SeccompNotif) -> None:
        number = notification.data.nr
        if number == self._architecture.connect:
            self._handle_connect(notification)
            return
        if number == self._architecture.sendto:
            self._handle_sendto(notification)
            return
        if number == self._architecture.sendmsg:
            self._handle_sendmsg(notification)
            return
        if number == self._architecture.bind:
            self._handle_bind(notification)
            return
        if number == self._architecture.listen:
            self._handle_listen(notification)
            return
        if number in {self._architecture.accept, self._architecture.accept4}:
            self._handle_accept(notification, accept4=number == self._architecture.accept4)
            return
        self._record(
            syscall="unknown", tid=notification.pid, peer=None, port=None,
            kind=0, protocol=0, decision="deny",
            reason="unknown broker syscall is not admitted",
        )
        self._respond(notification.id, error=errno.EPERM)

    def _tracee_identity(self, tid: int, notification_id: int,
                         allowed: tuple[tuple[str, int], ...],
                         ) -> tuple[str, int]:
        if not allowed:
            raise NetworkBrokerRefused("network_broker_helper_identity_failed")

        def validate() -> None:
            if self._stop.is_set():
                raise NetworkBrokerRefused(
                    "network_broker_helper_identity_cancelled",
                )
            self._require_valid(notification_id)

        # One notification hashes a given tracee at a time.  The cache becomes
        # visible only after the before/hash/after executable stamp is stable.
        with self._identity_lock:
            validate()

            def snapshot() -> tuple[int, ...]:
                try:
                    fd = os.open(
                        f"/proc/{tid}/exe",
                        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
                    )
                except OSError as exc:
                    raise NetworkBrokerRefused(
                        "network_broker_helper_identity_failed",
                    ) from exc
                try:
                    observed = os.fstat(fd)
                    if (not stat.S_ISREG(observed.st_mode)
                            or observed.st_size not in {
                                size for _digest, size in allowed
                            }):
                        raise NetworkBrokerRefused(
                            "network_broker_helper_identity_failed",
                        )
                    return (
                        observed.st_dev, observed.st_ino, observed.st_mode,
                        observed.st_size, observed.st_mtime_ns,
                        observed.st_ctime_ns,
                    )
                finally:
                    os.close(fd)

            stamp = snapshot()
            validate()
            cached = self._executable_cache.get(stamp)
            if cached is not None:
                return cached
            identity = _hash_tracee_executable(
                tid, validate=validate,
                deadline_monotonic=min(
                    self._deadline,
                    time.monotonic() + _MAX_EXECUTABLE_HASH_SECONDS,
                ),
                expected_sizes=tuple(sorted({size for _digest, size in allowed})),
            )
            validate()
            if snapshot() != stamp:
                raise NetworkBrokerRefused(
                    "network_broker_helper_identity_changed",
                )
            self._executable_cache[stamp] = identity
            return identity

    def _identity_allowed(self, tid: int, notification_id: int,
                          allowed: tuple[tuple[str, int], ...]) -> bool:
        if not allowed:
            return False
        return self._tracee_identity(tid, notification_id, allowed) in allowed

    def _helper_allowed(self, tid: int, notification_id: int) -> bool:
        return self._identity_allowed(
            tid, notification_id, self._policy.control_helpers,
        )

    def _client_allowed(self, tid: int, notification_id: int) -> bool:
        return self._identity_allowed(
            tid, notification_id, self._policy.control_clients,
        )

    def _handle_bind(self, notification: _SeccompNotif) -> None:
        tid = int(notification.pid)
        remote_fd = int(notification.data.args[0])
        self._require_valid(notification.id)
        destination = _copy_destination(
            tid, int(notification.data.args[1]), int(notification.data.args[2]),
            validate=lambda: self._require_valid(notification.id),
        )
        duplicate = _duplicate_tracee_fd(
            tid, remote_fd,
            validate=lambda: self._require_valid(notification.id),
        )
        try:
            self._require_valid(notification.id)
            domain, kind, protocol = _socket_metadata(duplicate)
            unix_decision, unix_reason = self._policy.decide_unix(
                destination.unix_path,
            ) if destination.family == socket.AF_UNIX else ("deny", "not Unix")
            singleton_shape = (
                destination.family == domain == socket.AF_UNIX
                and kind & 0xF == socket.SOCK_STREAM
                and protocol == 0
                and self._policy.is_chromium_singleton_path(
                    destination.unix_path,
                )
            )
            # No netlink endpoint is admitted.  Even NETLINK_ROUTE permits
            # addressed user peers/groups and mutation messages that cannot be
            # classified as read-only at the sockaddr boundary.
            local_netlink = False
            helper = self._helper_allowed(tid, notification.id) \
                if singleton_shape else False
            singleton = (
                singleton_shape and helper and not self._singleton_controls
            )
            if not local_netlink and not singleton:
                if self._respond(notification.id, error=errno.EPERM):
                    self._record(
                        syscall="bind", tid=tid, peer=destination.peer,
                        port=destination.port, kind=kind, protocol=protocol,
                        decision="deny", reason=(
                            unix_reason if destination.family == socket.AF_UNIX
                            else "unclassified listener bind"
                        ),
                    )
                return
            effect_reason = (
                "local netlink route socket" if local_netlink else
                "broker-substituted Chromium ProcessSingleton endpoint"
            )
            if not self._record(
                    syscall="bind", tid=tid, peer=destination.peer,
                    port=destination.port, kind=kind, protocol=protocol,
                    decision="allow", reason=effect_reason,
                    stage="planned", result=None):
                self._respond(notification.id, error=errno.ECANCELED)
                return
            with self._effect_lock:
                if self._stop.is_set():
                    self._respond(notification.id, error=errno.ECANCELED)
                    return
                self._require_valid(notification.id)
                _require_same_tracee_ofd(
                    tid, remote_fd, duplicate,
                    validate=lambda: self._require_valid(notification.id),
                )
                bound_destination = destination
                if singleton:
                    result = -1
                    error = errno.EADDRINUSE
                    for _attempt in range(_SINGLETON_BIND_ATTEMPTS):
                        actual_path = (
                            b"\x00quarry.ps." + self._policy.request_id.encode("ascii")
                            + b"." + os.urandom(16).hex().encode("ascii")
                        )
                        actual_raw = struct.pack("=H", socket.AF_UNIX) + actual_path
                        candidate = _Destination(
                            socket.AF_UNIX, None, None, actual_raw, actual_path,
                        )
                        buffer = ctypes.create_string_buffer(candidate.raw)
                        ctypes.set_errno(0)
                        result = _libc().bind(
                            duplicate, ctypes.byref(buffer), len(candidate.raw),
                        )
                        error = ctypes.get_errno() if result < 0 else 0
                        if result == 0:
                            bound_destination = candidate
                            break
                        if error != errno.EADDRINUSE:
                            break
                    if result < 0 and error == errno.EADDRINUSE:
                        raise NetworkBrokerRefused(
                            "network_broker_singleton_name_exhausted",
                        )
                else:
                    buffer = ctypes.create_string_buffer(destination.raw)
                    ctypes.set_errno(0)
                    result = _libc().bind(
                        duplicate, ctypes.byref(buffer), len(destination.raw),
                    )
                    error = ctypes.get_errno() if result < 0 else 0
                if result == 0:
                    identity = _socket_identity(duplicate)
                    if singleton:
                        handle = socket.socket(fileno=duplicate)
                        try:
                            observed = handle.getsockname()
                        finally:
                            handle.detach()
                        if observed != bound_destination.unix_path:
                            raise NetworkBrokerRefused(
                                "network_broker_singleton_endpoint_unverified",
                            )
                        peer, port = "unix-singleton", 0
                    else:
                        peer, port = "netlink", 0
                    if not local_netlink:
                        held = os.dup(duplicate)
                        owner_tgid = _thread_group_number(
                            tid, validate=lambda: self._require_valid(notification.id),
                        )
                        control = _ControlListener(
                            held, peer, port, identity,
                            self._policy.request_id, owner_tgid,
                            int(notification.data.args[0]), self._control_owner_token,
                            self._policy.control_helpers,
                            (owner_tgid,),
                            "chromium-process-singleton",
                            None,
                            destination.unix_path if singleton else None,
                            bound_destination.unix_path if singleton else None,
                        )
                        try:
                            if singleton:
                                self._singleton_controls[
                                    destination.unix_path
                                ] = control
                            self._control_listeners[identity] = control
                        except BaseException:
                            os.close(held)
                            raise
            _require_same_tracee_ofd(
                tid, remote_fd, duplicate,
                validate=lambda: self._require_valid(notification.id),
            )
            self._record(
                syscall="bind", tid=tid,
                peer=(peer if result == 0 else destination.peer),
                port=(port if result == 0 else destination.port),
                kind=kind, protocol=protocol, decision="allow",
                reason=effect_reason, stage="settled",
                result=("ok" if result == 0 else f"errno:{error}"),
            )
            self._respond(notification.id, value=int(result), error=error)
        finally:
            os.close(duplicate)

    def _handle_listen(self, notification: _SeccompNotif) -> None:
        tid = int(notification.pid)
        remote_fd = int(notification.data.args[0])
        self._require_valid(notification.id)
        duplicate = _duplicate_tracee_fd(
            tid, remote_fd,
            validate=lambda: self._require_valid(notification.id),
        )
        try:
            self._require_valid(notification.id)
            _domain, kind, protocol = _socket_metadata(duplicate)
            control = self._control_listeners.get(_socket_identity(duplicate))
            helper = self._helper_allowed(tid, notification.id)
            backlog = int(notification.data.args[1])
            if control is None or not helper or not 0 <= backlog <= 65535:
                if self._respond(notification.id, error=errno.EPERM):
                    self._record(
                        syscall="listen", tid=tid, peer=None, port=None,
                        kind=kind, protocol=protocol, decision="deny",
                        reason="listener was not an admitted control endpoint",
                    )
                return
            if not self._record(
                    syscall="listen", tid=tid, peer=control.peer,
                    port=control.port, kind=kind, protocol=protocol,
                    decision="allow",
                    reason="authenticated browser-helper control listener",
                    stage="planned", result=None):
                self._respond(notification.id, error=errno.ECANCELED)
                return
            with self._effect_lock:
                if self._stop.is_set():
                    self._respond(notification.id, error=errno.ECANCELED)
                    return
                self._require_valid(notification.id)
                _require_same_tracee_ofd(
                    tid, remote_fd, duplicate,
                    validate=lambda: self._require_valid(notification.id),
                )
                ctypes.set_errno(0)
                result = _libc().listen(duplicate, backlog)
                error = ctypes.get_errno() if result < 0 else 0
            _require_same_tracee_ofd(
                tid, remote_fd, duplicate,
                validate=lambda: self._require_valid(notification.id),
            )
            self._record(
                syscall="listen", tid=tid, peer=control.peer, port=control.port,
                kind=kind, protocol=protocol, decision="allow",
                reason="authenticated browser-helper control listener",
                stage="settled",
                result=("ok" if result == 0 else f"errno:{error}"),
            )
            self._respond(notification.id, value=int(result), error=error)
        finally:
            os.close(duplicate)

    def _handle_accept(self, notification: _SeccompNotif, *, accept4: bool) -> None:
        """Refuse target-owned accepts; worker control listeners own ingress.

        Seccomp ADDFD can atomically inject the return descriptor, but it cannot
        atomically commit the tracee's two optional sockaddr output writes with
        that return.  The accepted browser topology therefore uses Chromium's
        DevTools pipe and a worker-owned WebSocket listener.  ProcessSingleton
        may retain its substituted held listener, but no queued foreign or
        second-instance connection is ever delivered into Chromium.
        """
        tid = int(notification.pid)
        self._require_valid(notification.id)
        duplicate = _duplicate_tracee_fd(
            tid, int(notification.data.args[0]),
            validate=lambda: self._require_valid(notification.id),
        )
        try:
            self._require_valid(notification.id)
            _domain, kind, protocol = _socket_metadata(duplicate)
            if self._respond(notification.id, error=errno.EPERM):
                self._record(
                    syscall="accept4" if accept4 else "accept", tid=tid,
                    peer=None, port=None, kind=kind, protocol=protocol,
                    decision="deny",
                    reason="target-owned network and Unix accepts are refused",
                )
        finally:
            os.close(duplicate)

    def _control_endpoint(self, tid: int, notification_id: int, fd: int,
                          destination: _Destination, domain: int, kind: int,
                          protocol: int) -> _ControlListener | None:
        if (destination.peer not in {"127.0.0.1", "::1"}
                or destination.port is None
                or destination.family != domain
                or kind & 0xF != socket.SOCK_STREAM
                or protocol not in {0, socket.IPPROTO_TCP}):
            return None
        control = self._control_registry.lookup(
            self._policy.request_id, destination.peer, destination.port,
        )
        if control is None:
            return None
        client_tgid = _thread_group_number(
            tid, validate=lambda: self._require_valid(notification_id),
        )
        if control.client_tgids and client_tgid not in control.client_tgids:
            raise NetworkBrokerRefused("network_broker_control_client_tgid_unverified")
        if not self._identity_allowed(
                tid, notification_id, control.client_identities):
            raise NetworkBrokerRefused("network_broker_control_client_unverified")
        owner_duplicate = -1
        try:
            if control.owner_tgid == os.getpid():
                owner_duplicate = os.dup(control.owner_fd)
            else:
                pidfd = os.pidfd_open(control.owner_tgid, 0)
                try:
                    owner_duplicate = _pidfd_getfd(pidfd, control.owner_fd)
                finally:
                    os.close(pidfd)
            if (_socket_identity(owner_duplicate) != control.identity
                    or _socket_identity(control.fd) != control.identity
                    or _socket_metadata(owner_duplicate) != (domain, kind, protocol)):
                raise NetworkBrokerRefused("network_broker_control_endpoint_unverified")
            handle = socket.socket(fileno=control.fd)
            try:
                observed = handle.getsockname()
                accepting = handle.getsockopt(
                    socket.SOL_SOCKET, socket.SO_ACCEPTCONN,
                ) == 1
            finally:
                handle.detach()
            address = ipaddress.ip_address(observed[0])
            peer = str(getattr(address, "ipv4_mapped", None) or address)
            if (peer, int(observed[1])) != (destination.peer, destination.port) \
                    or not accepting:
                raise NetworkBrokerRefused("network_broker_control_endpoint_unverified")
            self._require_valid(notification_id)
            return control
        except (OSError, ValueError, TypeError, IndexError) as exc:
            self._control_registry.discard(control)
            raise NetworkBrokerRefused(
                "network_broker_control_endpoint_unverified",
            ) from exc
        finally:
            if owner_duplicate >= 0:
                os.close(owner_duplicate)

    def _singleton_endpoint(self, tid: int, notification_id: int,
                            destination: _Destination, domain: int, kind: int,
                            protocol: int) -> _ControlListener | None:
        if (destination.family != domain or domain != socket.AF_UNIX
                or kind & 0xF != socket.SOCK_STREAM or protocol != 0
                or destination.unix_path is None
                or destination.unix_path.startswith(b"\x00")):
            return None
        control = self._singleton_controls.get(destination.unix_path)
        if control is None:
            return None
        if (control.request_id != self._policy.request_id
                or control.requested_unix != destination.unix_path
                or control.actual_unix is None
                or not control.actual_unix.startswith(b"\x00")
                or not self._helper_allowed(tid, notification_id)):
            raise NetworkBrokerRefused(
                "network_broker_singleton_client_unverified",
            )
        owner_duplicate = -1
        try:
            if control.owner_tgid == os.getpid():
                owner_duplicate = os.dup(control.owner_fd)
            else:
                pidfd = os.pidfd_open(control.owner_tgid, 0)
                try:
                    owner_duplicate = _pidfd_getfd(pidfd, control.owner_fd)
                finally:
                    os.close(pidfd)
            if (_socket_identity(owner_duplicate) != control.identity
                    or _socket_identity(control.fd) != control.identity
                    or _socket_metadata(owner_duplicate)
                    != (socket.AF_UNIX, socket.SOCK_STREAM, 0)):
                raise NetworkBrokerRefused(
                    "network_broker_singleton_endpoint_unverified",
                )
            handle = socket.socket(fileno=control.fd)
            try:
                observed = handle.getsockname()
                accepting = handle.getsockopt(
                    socket.SOL_SOCKET, socket.SO_ACCEPTCONN,
                ) == 1
            finally:
                handle.detach()
            if observed != control.actual_unix or not accepting:
                raise NetworkBrokerRefused(
                    "network_broker_singleton_endpoint_unverified",
                )
            self._require_valid(notification_id)
            return control
        except (OSError, ValueError, TypeError, IndexError) as exc:
            self._singleton_controls.pop(destination.unix_path, None)
            raise NetworkBrokerRefused(
                "network_broker_singleton_endpoint_unverified",
            ) from exc
        finally:
            if owner_duplicate >= 0:
                os.close(owner_duplicate)

    def _decide_peer(self, peer: str, port: int, kind: int,
                     protocol: int) -> tuple[str, str]:
        if self._profile == "browser":
            return "deny", "browser target egress requires the pinned proxy"
        return self._policy.decide(peer, port, kind, protocol)

    def _target_dns_client_allowed(self, tid: int, notification_id: int,
                                   peer: str | None, port: int | None,
                                   kind: int, protocol: int) -> tuple[str, str]:
        """Bind the held DNS endpoint to the attested DNS executable set."""
        decision, reason = self._policy.decide(
            peer or "", port if port is not None else -1, kind, protocol,
        )
        if decision != "allow":
            return decision, reason
        if not self._client_allowed(tid, notification_id):
            return "deny", "DNS mediator client executable is not attested"
        return "allow", "attested DNS client reached held loopback mediator"

    def _target_dns_payload_allowed(self, destination: _Destination | None,
                                    kind: int, protocol: int,
                                    payload: bytes) -> tuple[str, str]:
        if destination is None:
            return "deny", "target DNS requires a connected mediator endpoint"
        base_kind = kind & 0xF
        if (base_kind == socket.SOCK_STREAM
                and protocol in {0, socket.IPPROTO_TCP}):
            # TCP carries a two-byte DNS length prefix; the mediator validates
            # the complete framed question before any resolver exchange.
            return "allow", "TCP DNS framing is validated by the mediator"
        if (base_kind == socket.SOCK_DGRAM
                and protocol in {0, socket.IPPROTO_UDP}):
            return self._policy.decide_dns_question(payload)
        return "deny", "target DNS socket metadata is invalid"

    def _inject_target_dns_bytes(self, fd: int, notification_id: int,
                                 body: bytes,
                                 destination: _Destination | None = None) -> int:
        """Write a worker-only mediator capability on the tracee's OFD.

        This runs while the caller holds the same effect fence as its emulated
        syscall, so an addressed UDP envelope cannot be separated from the
        query by another brokered effect.  Datagram writes must be exact;
        stream preambles may require bounded partial-write retries.
        """
        if type(body) is not bytes or not body:
            return errno.EINVAL
        buffer = ctypes.create_string_buffer(body)
        offset = 0
        while offset < len(body):
            if destination is None:
                operation = lambda: _libc().send(
                    fd, ctypes.byref(buffer, offset), len(body) - offset,
                    getattr(socket, "MSG_NOSIGNAL", 0)
                    | getattr(socket, "MSG_DONTWAIT", 0),
                )
            else:
                address = ctypes.create_string_buffer(destination.raw)
                operation = lambda: _libc().sendto(
                    fd, ctypes.byref(buffer, offset), len(body) - offset,
                    getattr(socket, "MSG_DONTWAIT", 0), ctypes.byref(address),
                    len(destination.raw),
                )
            result, error = self._send_cancellable(fd, notification_id, operation)
            if result < 0 or error:
                return error or errno.EIO
            if result <= 0 or (destination is not None and result != len(body)):
                return errno.EIO
            offset += result
        return 0

    def _inject_target_dns_connected_authentication(self, fd: int,
                                                     notification_id: int,
                                                     kind: int, protocol: int) -> int:
        authentication = self._dns_mediator_authentication
        if type(authentication) is not bytes or len(authentication) != _DNS_MEDIATOR_AUTH_BYTES:
            return errno.EPERM
        base_kind = kind & 0xF
        if base_kind == socket.SOCK_STREAM and protocol in {0, socket.IPPROTO_TCP}:
            magic = _DNS_MEDIATOR_TCP_AUTH_MAGIC
        elif base_kind == socket.SOCK_DGRAM and protocol in {0, socket.IPPROTO_UDP}:
            magic = _DNS_MEDIATOR_UDP_PERSISTENT_AUTH_MAGIC
        else:
            return errno.EPERM
        return self._inject_target_dns_bytes(fd, notification_id, magic + authentication)

    def _inject_target_dns_addressed_query(self, fd: int, notification_id: int,
                                           destination: _Destination,
                                           kind: int, protocol: int,
                                           payload: bytes) -> int:
        authentication = self._dns_mediator_authentication
        if (type(authentication) is not bytes
                or len(authentication) != _DNS_MEDIATOR_AUTH_BYTES
                or (kind & 0xF) != socket.SOCK_DGRAM
                or protocol not in {0, socket.IPPROTO_UDP}):
            return errno.EPERM
        return self._inject_target_dns_bytes(
            fd, notification_id,
            _DNS_MEDIATOR_UDP_QUERY_AUTH_MAGIC + authentication + payload,
            destination,
        )

    def _classify_destination(self, fd: int, domain: int, kind: int,
                              protocol: int,
                              destination: _Destination | None, *, tid: int,
                              notification_id: int) -> tuple[_Destination | None, str, str]:
        if destination is not None:
            if destination.family not in {socket.AF_UNSPEC, domain}:
                raise NetworkBrokerRefused("network_broker_socket_family_mismatch")
            if destination.peer is None:
                if destination.family == socket.AF_UNIX:
                    decision, reason = self._policy.decide_unix(destination.unix_path)
                    return destination, decision, reason
                if destination.family == socket.AF_NETLINK:
                    if (destination.netlink_pid, destination.netlink_groups) != (0, 0):
                        return destination, "deny", "addressed netlink peer/group refused"
                    return destination, "deny", "netlink route authority is unsupported"
                if destination.family == socket.AF_UNSPEC:
                    return destination, "deny", "AF_UNSPEC socket operation refused"
                return destination, "deny", "unclassified non-IP socket operation"
            if self._control_endpoint(
                    tid, notification_id, fd, destination,
                    domain, kind, protocol) is not None:
                return destination, "allow", "invocation-owned browser control channel"
            decision, reason = self._decide_peer(
                destination.peer, destination.port, kind, protocol,
            )
            return destination, decision, reason
        if domain not in {socket.AF_INET, socket.AF_INET6}:
            if domain == socket.AF_UNIX:
                return None, "allow", "connected invocation-local Unix socket"
            if domain == socket.AF_NETLINK:
                return None, "deny", "connected netlink authority is unsupported"
            return None, "deny", "unclassified connected socket operation"
        handle = socket.socket(fileno=fd)
        try:
            observed = handle.getpeername()
        except OSError as exc:
            raise NetworkBrokerRefused("network_broker_connected_peer_unverified") from exc
        finally:
            handle.detach()
        try:
            address = ipaddress.ip_address(observed[0])
            peer = str(getattr(address, "ipv4_mapped", None) or address)
            port = int(observed[1])
        except (ValueError, TypeError, IndexError) as exc:
            raise NetworkBrokerRefused("network_broker_connected_peer_unverified") from exc
        connected = _Destination(domain, peer, port, b"")
        if _socket_identity(fd) in self._control_connections:
            return connected, "allow", "connected browser control channel"
        decision, reason = self._decide_peer(peer, port, kind, protocol)
        return connected, decision, reason

    def _handle_sendto(self, notification: _SeccompNotif) -> None:
        tid = int(notification.pid)
        remote_fd = int(notification.data.args[0])
        self._require_valid(notification.id)
        length = int(notification.data.args[2])
        payload = _copy_payload(
            tid, int(notification.data.args[1]), length,
            validate=lambda: self._require_valid(notification.id),
        )
        pointer = int(notification.data.args[4])
        address_length = int(notification.data.args[5])
        if pointer:
            destination = _copy_destination(
                tid, pointer, address_length,
                validate=lambda: self._require_valid(notification.id),
            )
        elif address_length == 0:
            destination = None
        else:
            raise NetworkBrokerRefused("network_broker_sockaddr_length_invalid")
        addressed = destination is not None
        flags = int(notification.data.args[3])
        if flags & _MSG_ZEROCOPY or flags > 0x7FFFFFFF:
            raise NetworkBrokerRefused("network_broker_send_flags_refused")
        duplicate = _duplicate_tracee_fd(
            tid, remote_fd,
            validate=lambda: self._require_valid(notification.id),
        )
        try:
            self._require_valid(notification.id)
            domain, kind, protocol = _socket_metadata(duplicate)
            destination, decision, reason = self._classify_destination(
                duplicate, domain, kind, protocol, destination,
                tid=tid, notification_id=notification.id,
            )
            peer = None if destination is None else destination.peer
            port = None if destination is None else destination.port
            if decision == "allow" and self._policy.transport_profile == "target-dns":
                decision, reason = self._target_dns_client_allowed(
                    tid, notification.id, peer, port, kind, protocol,
                )
                if decision == "allow":
                    decision, reason = self._target_dns_payload_allowed(
                        destination, kind, protocol, payload,
                    )
            if decision != "allow":
                if self._respond(notification.id, error=errno.EPERM):
                    self._record(
                        syscall="sendto", tid=tid, peer=peer, port=port,
                        kind=kind, protocol=protocol, decision=decision,
                        reason=reason,
                    )
                return
            buffer = ctypes.create_string_buffer(payload)
            name_buffer = (
                ctypes.create_string_buffer(destination.raw)
                if destination is not None and destination.raw else None
            )
            if not self._record(
                    syscall="sendto", tid=tid, peer=peer, port=port,
                    kind=kind, protocol=protocol, decision=decision,
                    reason=reason, stage="planned", result=None):
                self._respond(notification.id, error=errno.ECANCELED)
                return
            with self._effect_lock:
                if self._stop.is_set():
                    self._respond(notification.id, error=errno.ECANCELED)
                    return
                self._require_valid(notification.id)
                _require_same_tracee_ofd(
                    tid, remote_fd, duplicate,
                    validate=lambda: self._require_valid(notification.id),
                )
                if (self._policy.transport_profile == "target-dns" and addressed
                        and (kind & 0xF) == socket.SOCK_DGRAM):
                    error = self._inject_target_dns_addressed_query(
                        duplicate, notification.id, destination, kind, protocol, payload,
                    )
                    result = len(payload) if error == 0 else -1
                else:
                    result, error = self._send_cancellable(
                        duplicate, notification.id,
                        lambda: _libc().sendto(
                            duplicate, ctypes.byref(buffer), len(payload),
                            flags | getattr(socket, "MSG_DONTWAIT", 0),
                            ctypes.byref(name_buffer) if name_buffer is not None else None,
                            len(destination.raw) if name_buffer is not None else 0,
                        ),
                    )
            _require_same_tracee_ofd(
                tid, remote_fd, duplicate,
                validate=lambda: self._require_valid(notification.id),
            )
            self._record(
                syscall="sendto", tid=tid, peer=peer, port=port,
                kind=kind, protocol=protocol, decision=decision, reason=reason,
                stage="settled",
                result=(str(result) if error == 0 else f"errno:{error}"),
            )
            self._respond(notification.id, value=result, error=error)
        finally:
            os.close(duplicate)

    def _handle_sendmsg(self, notification: _SeccompNotif) -> None:
        tid = int(notification.pid)
        remote_fd = int(notification.data.args[0])
        self._require_valid(notification.id)
        message = _copy_message(
            tid, int(notification.data.args[1]),
            validate=lambda: self._require_valid(notification.id),
            duplicate_fd=lambda remote_fd: _duplicate_tracee_fd(
                tid, remote_fd,
                validate=lambda: self._require_valid(notification.id),
                socket_only=False,
            ),
        )
        try:
            addressed = message.destination is not None
            flags = int(notification.data.args[2])
            if flags & _MSG_ZEROCOPY or flags > 0x7FFFFFFF:
                raise NetworkBrokerRefused("network_broker_send_flags_refused")
            duplicate = _duplicate_tracee_fd(
                tid, remote_fd,
                validate=lambda: self._require_valid(notification.id),
            )
            try:
                self._require_valid(notification.id)
                domain, kind, protocol = _socket_metadata(duplicate)
                if message.passed_fds:
                    if domain != socket.AF_UNIX:
                        raise NetworkBrokerRefused(
                            "network_broker_rights_nonlocal_refused",
                        )
                    for passed_fd in message.passed_fds:
                        self._validate_passed_fd(passed_fd)
                        self._require_valid(notification.id)
                destination, decision, reason = self._classify_destination(
                    duplicate, domain, kind, protocol, message.destination,
                    tid=tid, notification_id=notification.id,
                )
                peer = None if destination is None else destination.peer
                port = None if destination is None else destination.port
                if decision == "allow" and self._policy.transport_profile == "target-dns":
                    decision, reason = self._target_dns_client_allowed(
                        tid, notification.id, peer, port, kind, protocol,
                    )
                    if decision == "allow":
                        payload = b"".join(
                            bytes(buffer)[:int(vector.length)]
                            for buffer, vector in zip(
                                message.payload_buffers, message.iovectors,
                            )
                        )
                        decision, reason = self._target_dns_payload_allowed(
                            destination, kind, protocol, payload,
                        )
                if decision != "allow":
                    if self._respond(notification.id, error=errno.EPERM):
                        self._record(
                            syscall="sendmsg", tid=tid, peer=peer, port=port,
                            kind=kind, protocol=protocol, decision=decision,
                            reason=reason,
                        )
                    return
                if not self._record(
                        syscall="sendmsg", tid=tid, peer=peer, port=port,
                        kind=kind, protocol=protocol, decision=decision,
                        reason=reason, stage="planned", result=None):
                    self._respond(notification.id, error=errno.ECANCELED)
                    return
                with self._effect_lock:
                    if self._stop.is_set():
                        self._respond(notification.id, error=errno.ECANCELED)
                        return
                    self._require_valid(notification.id)
                    _require_same_tracee_ofd(
                        tid, remote_fd, duplicate,
                        validate=lambda: self._require_valid(notification.id),
                    )
                    if (self._policy.transport_profile == "target-dns" and addressed
                            and (kind & 0xF) == socket.SOCK_DGRAM):
                        error = self._inject_target_dns_addressed_query(
                            duplicate, notification.id, destination, kind, protocol,
                            payload,
                        )
                        result = len(payload) if error == 0 else -1
                    else:
                        result, error = self._send_cancellable(
                            duplicate, notification.id,
                            lambda: _libc().sendmsg(
                                duplicate, ctypes.byref(message.header),
                                flags | getattr(socket, "MSG_DONTWAIT", 0),
                            ),
                        )
                _require_same_tracee_ofd(
                    tid, remote_fd, duplicate,
                    validate=lambda: self._require_valid(notification.id),
                )
                self._record(
                    syscall="sendmsg", tid=tid, peer=peer, port=port,
                    kind=kind, protocol=protocol, decision=decision, reason=reason,
                    stage="settled",
                    result=(str(result) if error == 0 else f"errno:{error}"),
                )
                self._respond(notification.id, value=result, error=error)
            finally:
                os.close(duplicate)
        finally:
            for passed_fd in message.passed_fds:
                os.close(passed_fd)

    def _validate_passed_fd(self, fd: int) -> None:
        """Refuse process/listener authority and unclassified network sockets."""
        try:
            target = os.readlink(f"/proc/self/fd/{fd}")
            observed = os.fstat(fd)
        except OSError as exc:
            raise NetworkBrokerRefused("network_broker_rights_fd_invalid") from exc
        if target == "anon_inode:seccomp notify" or target.startswith("anon_inode:[pidfd]"):
            raise NetworkBrokerRefused("network_broker_rights_authority_refused")
        if not stat.S_ISSOCK(observed.st_mode):
            return
        domain, _kind, _protocol = _socket_metadata(fd)
        if domain == socket.AF_UNIX:
            return
        if domain not in {socket.AF_INET, socket.AF_INET6}:
            raise NetworkBrokerRefused("network_broker_rights_socket_refused")
        handle = socket.socket(fileno=fd)
        try:
            connected = handle.getpeername()
        except OSError as exc:
            raise NetworkBrokerRefused("network_broker_rights_socket_unconnected") from exc
        finally:
            handle.detach()
        try:
            address = ipaddress.ip_address(connected[0])
            peer = str(getattr(address, "ipv4_mapped", None) or address)
            port = int(connected[1])
        except (ValueError, TypeError, IndexError) as exc:
            raise NetworkBrokerRefused("network_broker_rights_socket_unverified") from exc
        decision, _reason = self._policy.decide(peer, port, _kind, _protocol)
        if decision != "allow":
            raise NetworkBrokerRefused("network_broker_rights_socket_refused")

    def _send_cancellable(self, fd: int, notification_id: int,
                          operation) -> tuple[int, int]:
        original = fcntl.fcntl(fd, fcntl.F_GETFL)
        blocking = not original & os.O_NONBLOCK
        # Callers add MSG_DONTWAIT to this one send operation.  This remains
        # bounded without transiently changing O_NONBLOCK on the shared OFD.
        while (not self._stop.is_set()
               and time.monotonic() < self._deadline):
            self._require_valid(notification_id)
            ctypes.set_errno(0)
            with self._effect_lock:
                if self._stop.is_set():
                    return -1, errno.ECANCELED
                self._require_valid(notification_id)
                result = operation()
            error = ctypes.get_errno() if result < 0 else 0
            if result >= 0 or error not in {errno.EAGAIN, errno.EWOULDBLOCK}:
                return int(result), error
            if not blocking:
                return int(result), error
            select.select((), (fd,), (), 0.05)
        return -1, (
            errno.ETIMEDOUT if time.monotonic() >= self._deadline
            else errno.ECANCELED
        )

    def _handle_connect(self, notification: _SeccompNotif) -> None:
        tid = int(notification.pid)
        remote_fd = int(notification.data.args[0])
        self._require_valid(notification.id)
        destination = _copy_destination(
            tid, int(notification.data.args[1]), int(notification.data.args[2]),
            validate=lambda: self._require_valid(notification.id),
        )
        duplicate = _duplicate_tracee_fd(
            tid, remote_fd,
            validate=lambda: self._require_valid(notification.id),
        )
        control_grant = None
        connected_effect = False
        retained = None
        try:
            self._require_valid(notification.id)
            domain, kind, protocol = _socket_metadata(duplicate)
            if destination.family not in {socket.AF_UNSPEC, domain}:
                raise NetworkBrokerRefused("network_broker_socket_family_mismatch")
            control = self._control_endpoint(
                tid, notification.id, duplicate, destination,
                domain, kind, protocol,
            ) if destination.peer is not None else None
            singleton_control = self._singleton_endpoint(
                tid, notification.id, destination,
                domain, kind, protocol,
            ) if destination.family == socket.AF_UNIX else None
            if self._policy.transport_profile == "target-dns":
                decision, reason = self._target_dns_client_allowed(
                    tid, notification.id, destination.peer, destination.port,
                    kind, protocol,
                )
            elif control is not None:
                decision, reason = (
                    "allow", "invocation-owned browser control channel",
                )
            elif singleton_control is not None:
                decision, reason = (
                    "deny", "Chromium second-instance singleton channel refused",
                )
            elif destination.peer is None:
                if destination.family == socket.AF_UNIX:
                    decision, reason = self._policy.decide_unix(destination.unix_path)
                elif destination.family == socket.AF_NETLINK:
                    if (destination.netlink_pid, destination.netlink_groups) != (0, 0):
                        decision, reason = "deny", "addressed netlink peer/group refused"
                    else:
                        decision, reason = "deny", "netlink route authority is unsupported"
                elif destination.family == socket.AF_UNSPEC:
                    decision, reason = "deny", "AF_UNSPEC socket operation refused"
                else:
                    decision, reason = "deny", "unclassified non-IP socket operation"
            else:
                decision, reason = self._decide_peer(
                    destination.peer, destination.port, kind, protocol,
                )
            if decision != "allow":
                if self._respond(notification.id, error=errno.EPERM):
                    self._record(
                        syscall="connect", tid=tid, peer=destination.peer,
                        port=destination.port, kind=kind, protocol=protocol,
                        decision=decision, reason=reason,
                    )
                return
            if not self._record(
                    syscall="connect", tid=tid, peer=destination.peer,
                    port=destination.port, kind=kind, protocol=protocol,
                    decision=decision, reason=reason,
                    stage="planned", result=None):
                self._respond(notification.id, error=errno.ECANCELED)
                return
            with self._effect_lock:
                if self._stop.is_set():
                    self._respond(notification.id, error=errno.ECANCELED)
                    return
                self._require_valid(notification.id)
                _require_same_tracee_ofd(
                    tid, remote_fd, duplicate,
                    validate=lambda: self._require_valid(notification.id),
                )
                result, error, selected_peer = self._connect(
                    duplicate, destination, stop=self._stop,
                    notification_id=notification.id,
                )
                connected_effect = result == 0
                if connected_effect:
                    try:
                        # Acquire cancellation authority before releasing the
                        # connect fence.  There is no connected-but-untracked
                        # OFD interval for a concurrent cancel to miss.
                        retained = self._retain_connected(duplicate)
                    except NetworkBrokerError:
                        handle = socket.socket(fileno=duplicate)
                        try:
                            handle.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                        finally:
                            handle.detach()
                        connected_effect = False
                        self._fatal = "network_broker_connection_retention_failed"
                        raise
            _require_same_tracee_ofd(
                tid, remote_fd, duplicate,
                validate=lambda: self._require_valid(notification.id),
            )
            if result == 0 and selected_peer is not None \
                    and control is None and singleton_control is None:
                final_decision, final_reason = self._decide_peer(
                    selected_peer, destination.port, kind, protocol,
                )
                if final_decision != "allow":
                    if retained is not None:
                        self._release_retained(retained)
                        retained = None
                    result, error = -1, errno.EPERM
                    decision, reason = final_decision, final_reason
            if result == 0 and self._policy.transport_profile == "target-dns":
                # The tracee never sees this capability.  It is written on
                # the broker's duplicate before connect(2) is acknowledged,
                # making the mediator's first TCP bytes / connected-UDP
                # datagram an attested broker effect.
                with self._effect_lock:
                    if self._stop.is_set():
                        result, error = -1, errno.ECANCELED
                    else:
                        self._require_valid(notification.id)
                        _require_same_tracee_ofd(
                            tid, remote_fd, duplicate,
                            validate=lambda: self._require_valid(notification.id),
                        )
                        error = self._inject_target_dns_connected_authentication(
                            duplicate, notification.id, kind, protocol,
                        )
                        result = 0 if error == 0 else -1
                if result != 0 and retained is not None:
                    self._release_retained(retained)
                    retained = None
            if result != 0:
                self._record(
                    syscall="connect", tid=tid,
                    peer=selected_peer or destination.peer,
                    port=destination.port, kind=kind, protocol=protocol,
                    decision=decision, reason=reason, stage="settled",
                    result=f"errno:{error}",
                )
                self._respond(notification.id, error=error)
                return
            if not self._record(
                    syscall="connect", tid=tid,
                    peer=selected_peer or destination.peer,
                    port=destination.port, kind=kind, protocol=protocol,
                    decision=decision, reason=reason, stage="admitted",
                    result="peer-connected"):
                if retained is not None:
                    self._release_retained(retained)
                    retained = None
                self._respond(notification.id, error=errno.ECANCELED)
                return
            grant_control = (
                control if control is not None
                and control.purpose in {
                    "pinned-browser-proxy", "browser-devtools-pipe",
                }
                else None
            )
            if result == 0 and grant_control is not None:
                try:
                    client_tgid = _thread_group_number(
                        tid, validate=lambda: self._require_valid(notification.id),
                    )
                    executable_identity = self._tracee_identity(
                        tid, notification.id, grant_control.client_identities,
                    )
                    control_grant = self._control_registry.authorize_connection(
                        grant_control, client_fd=duplicate,
                        client_tgid=client_tgid,
                        executable_identity=executable_identity,
                        owner_token=self._control_owner_token,
                    )
                except (OSError, NetworkBrokerError):
                    if retained is not None:
                        self._release_retained(retained)
                        retained = None
                    result, error = -1, errno.EPERM
                    self._fatal = "network_broker_control_grant_failed"
                    self._stop.set()
            if (result == 0 and control is not None
                    and control.purpose in {
                        "pinned-browser-proxy", "browser-devtools-pipe",
                    }):
                authentication = control.authentication
                if authentication is None or len(authentication) != 32:
                    raise NetworkBrokerRefused(
                        "network_broker_control_authentication_invalid",
                    )
                magic = (
                    b"QBP1" if control.purpose == "pinned-browser-proxy"
                    else b"QCD1"
                )
                auth_buffer = ctypes.create_string_buffer(
                    magic + authentication,
                )
                auth_total = 0
                auth_error = 0
                while auth_total < 36:
                    auth_result, auth_error = self._send_cancellable(
                        duplicate, notification.id,
                        lambda: _libc().send(
                            duplicate, ctypes.byref(auth_buffer, auth_total),
                            36 - auth_total,
                            getattr(socket, "MSG_NOSIGNAL", 0)
                            | getattr(socket, "MSG_DONTWAIT", 0),
                        ),
                    )
                    if auth_result <= 0 or auth_error:
                        break
                    auth_total += auth_result
                if auth_total != 36 or auth_error:
                    if retained is not None:
                        self._release_retained(retained)
                        retained = None
                    result, error = -1, auth_error or errno.EIO
                    self._fatal = "network_broker_control_authentication_failed"
                    self._stop.set()
            if result == 0 and control is not None:
                self._control_connections.add(_socket_identity(duplicate))
            if not self._journal_capacity(1):
                if control_grant is not None:
                    self._control_registry.revoke_connection(control_grant)
                if retained is not None:
                    self._release_retained(retained)
                    retained = None
                self._respond(notification.id, error=errno.ECANCELED)
                return
            responded = self._respond(
                notification.id, value=result, error=error,
            )
            if retained is not None and not responded:
                self._release_retained(retained)
                retained = None
            final_result = (
                "notification-cancelled" if not responded else
                "ok" if result == 0 else f"errno:{error}"
            )
            if control_grant is not None:
                if responded and result == 0:
                    try:
                        self._control_registry.arm_connection(control_grant)
                    except NetworkBrokerError:
                        self._control_registry.revoke_connection(control_grant)
                        self._fatal = "network_broker_control_grant_arm_failed"
                        self._stop.set()
                        final_result = "control-grant-arm-failed"
                else:
                    self._control_registry.revoke_connection(control_grant)
            recorded = self._record(
                syscall="connect", tid=tid,
                peer=selected_peer or destination.peer,
                port=destination.port, kind=kind, protocol=protocol,
                decision=("allow" if final_result == "ok" else "deny"),
                reason=reason, stage="settled", result=final_result,
            )
            if control_grant is not None:
                if recorded and final_result == "ok":
                    try:
                        self._control_registry.commit_connection(control_grant)
                    except NetworkBrokerError:
                        self._control_registry.revoke_connection(control_grant)
                        self._fatal = "network_broker_control_grant_commit_failed"
                        self._effect_fence.cancel()
                        recorded = False
                else:
                    self._control_registry.revoke_connection(control_grant)
            if retained is not None:
                # Holding a duplicate after the notification would suppress FIN
                # when the tracee closes its last socket reference.  Retention is
                # only a post-effect rollback guard through response, terminal
                # trace, and control-grant commit.  After commit the parent-owned
                # cgroup kill+empty authority is required for cancellation.
                if (self._policy.transport_profile == "target-dns"
                        and (kind & 0xF) == socket.SOCK_DGRAM
                        and protocol in {0, socket.IPPROTO_UDP}
                        and recorded and final_result == "ok"):
                    # Connected UDP's persistent auth is bound to this exact
                    # source port.  Keep a broker-owned duplicate until the
                    # normal session settlement drains it.
                    retained = None
                else:
                    self._release_retained(
                        retained,
                        shutdown=not (recorded and final_result == "ok"),
                    )
                    retained = None
            if not recorded and connected_effect:
                self._effect_fence.cancel()
        except BaseException:
            if control_grant is not None:
                self._control_registry.revoke_connection(control_grant)
            if retained is not None:
                self._release_retained(retained)
                retained = None
            if connected_effect:
                self._effect_fence.cancel()
            raise
        finally:
            os.close(duplicate)

    def _connect(self, fd: int, destination: _Destination,
                 *, stop: threading.Event,
                 notification_id: int) -> tuple[int, int, str | None]:
        original = fcntl.fcntl(fd, fcntl.F_GETFL)
        if not original & os.O_NONBLOCK:
            # connect(2) has no per-call nonblocking flag.  Changing F_SETFL on
            # a pidfd_getfd duplicate would transiently change the tracee's
            # shared OFD.  The accepted external-tool envelope therefore uses
            # nonblocking INET sockets; a blocking shape is refused before the
            # kernel connect effect and must be caught by per-lane H1.
            return -1, errno.EOPNOTSUPP, None
        library = _libc()
        buffer = ctypes.create_string_buffer(destination.raw)
        ctypes.set_errno(0)
        result = library.connect(fd, ctypes.byref(buffer), len(destination.raw))
        error = ctypes.get_errno() if result < 0 else 0
        if error in {errno.EINPROGRESS, errno.EALREADY}:
            while (not stop.is_set()
                   and time.monotonic() < self._deadline):
                self._require_valid(notification_id)
                _readable, writable, exceptional = select.select(
                    (), (fd,), (fd,), 0.05,
                )
                if writable or exceptional:
                    handle = socket.socket(fileno=fd)
                    try:
                        pending = handle.getsockopt(
                            socket.SOL_SOCKET, socket.SO_ERROR,
                        )
                    finally:
                        handle.detach()
                    result, error = (
                        (0, 0) if pending == 0 else (-1, pending)
                    )
                    break
            else:
                return -1, (
                    errno.ETIMEDOUT if time.monotonic() >= self._deadline
                    else errno.ECANCELED
                ), None
        if result < 0:
            return int(result), error, None
        selected = None
        if destination.peer is not None:
            handle = socket.socket(fileno=fd)
            try:
                observed = handle.getpeername()
            except OSError as exc:
                raise NetworkBrokerRefused(
                    "network_broker_connected_peer_unverified",
                ) from exc
            finally:
                handle.detach()
            try:
                parsed = ipaddress.ip_address(observed[0])
                if (isinstance(parsed, ipaddress.IPv6Address)
                        and parsed.scope_id is not None):
                    raise ValueError("scoped IPv6 peer")
                if (len(observed) > 2
                        and (int(observed[2]) != 0 or int(observed[3]) != 0)):
                    raise ValueError("noncanonical IPv6 peer tuple")
                selected = str(getattr(parsed, "ipv4_mapped", None) or parsed)
                selected_port = int(observed[1])
            except (ValueError, TypeError, IndexError) as exc:
                raise NetworkBrokerRefused(
                    "network_broker_connected_peer_unverified",
                ) from exc
            if (selected, selected_port) != (destination.peer, destination.port):
                raise NetworkBrokerRefused(
                    "network_broker_connected_peer_mismatch",
                )
        return int(result), error, selected

    def _require_valid(self, identifier: int) -> None:
        value = ctypes.c_uint64(identifier)
        _ioctl(self._listener_fd, _SECCOMP_IOCTL_NOTIF_ID_VALID, value)

    def _respond(self, identifier: int, *, value: int = 0, error: int = 0) -> bool:
        response = _SeccompNotifResp(
            identifier, value if error == 0 else 0,
            -abs(error) if error else 0, 0,
        )
        try:
            _ioctl(self._listener_fd, _SECCOMP_IOCTL_NOTIF_SEND, response)
            return True
        except OSError as exc:
            if exc.errno not in {errno.ENOENT, errno.EBADF}:
                raise
            return False


def _ioctl(fd: int, command: int, structure) -> int:
    ctypes.set_errno(0)
    result = _libc().ioctl(fd, command, ctypes.byref(structure))
    if result < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return int(result)


def complete_backend() -> bool:
    """True only after every trapped addressed-send syscall has an emulator."""
    return True


__all__ = (
    "BrokerPolicy", "ControlEndpointRegistry", "ListenerHandoff",
    "NetworkBrokerError", "NetworkBrokerRefused",
    "NetworkBrokerSession", "NetworkEffectFence", "acknowledge_listener",
    "acquire_worker_subreaper",
    "attest_exec_fds", "child_install_and_report", "complete_backend",
    "duplicate_reported_listener", "install_listener",
    "reap_adopted_descendants", "seal_worker_identity",
    "verify_listener_bootstrap",
)
