"""Bounded custody for the development suite's cooperative Python _task worker.

The caller selects actual Python (no intermediate launcher) for its own worker,
which reads exactly b"go\\n" from stdin
before starting any descendants, refuses any other input, and never escapes its
inherited Linux session/group. Windows jobs disallow breakaway. This is not a
sandbox for arbitrary commands. There are no retries or elevation paths.
Windows requires CPython's _winapi.CreateProcess/STARTUPINFO adapter and the
documented Windows Job APIs; missing support refuses execution. Jobs allow at
most 16 active processes, without automatic growth. Suspended creation also
contains Python venv bootstrap redirectors before releasing the stdin gate.
"""
from dataclasses import dataclass
import math
import os
import signal
import subprocess
import sys
import threading
import time


MAX_OUTPUT = 16 * 1024 * 1024
MAX_TIMEOUT = 900
MAX_ACTIVE_PROCESSES = 16
_CLEANUP_SECONDS = 5
_JOIN_SECONDS = 1


@dataclass(frozen=True)
class WorkerResult:
    args: object
    returncode: int
    stdout: bytes
    stderr: bytes
    duration_seconds: float


class WorkerError(RuntimeError):
    """Primary failure plus bounded output and independent cleanup failures."""

    def __init__(self, command, primary, cleanup, stdout, stderr, duration, code):
        super().__init__(f"worker failed: {type(primary).__name__}: {primary}")
        self.args_command = command
        self.primary_cause = primary
        self.cleanup_errors = tuple(cleanup)
        self.cleanup_unresolved = bool(cleanup)
        self.stdout = self.output = stdout
        self.stderr = stderr
        self.duration_seconds = duration
        self.returncode = code
        for error in cleanup:
            self.add_note(f"cleanup: {type(error).__name__}: {error}")


class OutputLimitExceeded(RuntimeError):
    pass


if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes as wt
    import _winapi
    import msvcrt

    # Windows SDK winnt.h layouts (including pointer-sized SIZE_T/ULONG_PTR):
    # https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information
    class _BasicLimit(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64),
                    ("PerJobUserTimeLimit", ctypes.c_int64), ("LimitFlags", wt.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", wt.DWORD), ("Affinity", ctypes.c_size_t),
                    ("PriorityClass", wt.DWORD), ("SchedulingClass", wt.DWORD)]

    class _IoCounters(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint64) for name in
                    ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                     "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

    class _ExtendedLimit(ctypes.Structure):
        _fields_ = [("BasicLimitInformation", _BasicLimit), ("IoInfo", _IoCounters),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t)]

    class _Accounting(ctypes.Structure):
        _fields_ = [(name, ctypes.c_int64) for name in
                    ("TotalUserTime", "TotalKernelTime", "ThisPeriodTotalUserTime",
                     "ThisPeriodTotalKernelTime")] + [(name, wt.DWORD) for name in
                    ("TotalPageFaultCount", "TotalProcesses", "ActiveProcesses",
                     "TotalTerminatedProcesses")]

    class _ProcessIds(ctypes.Structure):
        _fields_ = [("NumberOfAssignedProcesses", wt.DWORD),
                    ("NumberOfProcessIdsInList", wt.DWORD),
                    ("ProcessIdList", ctypes.c_size_t * MAX_ACTIVE_PROCESSES)]

    _kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    for _name, _arguments, _result in (
        ("CreateJobObjectW", [ctypes.c_void_p, wt.LPCWSTR], wt.HANDLE),
        ("SetInformationJobObject", [wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD], wt.BOOL),
        ("QueryInformationJobObject", [wt.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                        wt.DWORD, ctypes.POINTER(wt.DWORD)], wt.BOOL),
        ("AssignProcessToJobObject", [wt.HANDLE, wt.HANDLE], wt.BOOL),
        ("TerminateJobObject", [wt.HANDLE, wt.UINT], wt.BOOL),
        ("CloseHandle", [wt.HANDLE], wt.BOOL),
        ("WaitForSingleObject", [wt.HANDLE, wt.DWORD], wt.DWORD),
        ("GetExitCodeProcess", [wt.HANDLE, ctypes.POINTER(wt.DWORD)], wt.BOOL),
        ("ResumeThread", [wt.HANDLE], wt.DWORD),
        ("TerminateProcess", [wt.HANDLE, wt.UINT], wt.BOOL),
        ("OpenProcess", [wt.DWORD, wt.BOOL, wt.DWORD], wt.HANDLE),
        ("IsProcessInJob", [wt.HANDLE, wt.HANDLE, ctypes.POINTER(wt.BOOL)], wt.BOOL),
        ("PeekNamedPipe", [wt.HANDLE, ctypes.c_void_p, wt.DWORD, ctypes.c_void_p,
                           ctypes.POINTER(wt.DWORD), ctypes.c_void_p], wt.BOOL),
    ):
        getattr(_kernel, _name).argtypes = _arguments
        getattr(_kernel, _name).restype = _result

    def _wincheck(ok):
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())

    class _WindowsProcess:
        """Keep CreateProcess's thread HANDLE until Job assignment completes.

        Popen discards that handle, so CREATE_SUSPENDED cannot safely be used
        through Popen. Reuse its CPython CreateProcess/STARTUPINFO adapter with
        an explicit inherited-handle list; no other handles enter the worker.
        Suspension also contains venv redirectors which spawn an interpreter
        before Python _task code can reach the stdin gate.
        """
        def __init__(self, command, *, cwd, env, **unused):
            self._handle = self._thread = None
            files, descriptors = [], []
            try:
                for _ in range(3):
                    descriptors.extend(os.pipe())
                stdin_r, stdin_w, stdout_r, stdout_w, stderr_r, stderr_w = descriptors
                child_fds = (stdin_r, stdout_w, stderr_w)
                handles = [msvcrt.get_osfhandle(fd) for fd in child_fds]
                for handle in handles:
                    os.set_handle_inheritable(handle, True)
                info = subprocess.STARTUPINFO()
                info.dwFlags = 0x100 | 1  # USESTDHANDLES | USESHOWWINDOW
                info.wShowWindow = 0  # SW_HIDE
                info.hStdInput, info.hStdOutput, info.hStdError = handles
                info.lpAttributeList = {"handle_list": handles}
                for fd, mode in ((stdin_w, "wb"), (stdout_r, "rb"), (stderr_r, "rb")):
                    files.append(os.fdopen(fd, mode, buffering=0))
                    descriptors.remove(fd)
                self.stdin, self.stdout, self.stderr = files
                argv = [os.fsdecode(arg) for arg in command]
                self._handle, self._thread, self.pid, _ = _winapi.CreateProcess(
                    None, subprocess.list2cmdline(argv), None, None, True,
                    0x4, env, None if cwd is None else os.fsdecode(cwd), info)  # CREATE_SUSPENDED
            except BaseException:
                for stream in files:
                    stream.close()
                raise
            finally:
                for fd in descriptors:
                    os.close(fd)

        def resume(self):
            if _kernel.ResumeThread(self._thread) != 1:
                raise ctypes.WinError(ctypes.get_last_error())
            handle, self._thread = self._thread, None
            _wincheck(_kernel.CloseHandle(handle))

        def kill(self):
            _wincheck(_kernel.TerminateProcess(self._handle, 1))

        def wait(self, timeout):
            result = _kernel.WaitForSingleObject(self._handle, max(1, math.ceil(timeout * 1000)))
            if result == 258:
                raise TimeoutError("worker process reap deadline")
            if result != 0:
                raise ctypes.WinError(ctypes.get_last_error())
            code = wt.DWORD()
            _wincheck(_kernel.GetExitCodeProcess(self._handle, ctypes.byref(code)))
            return code.value

        def close(self):
            errors = []
            for name in ("_thread", "_handle"):
                handle = getattr(self, name)
                if handle is not None:
                    setattr(self, name, None)
                    try:
                        _wincheck(_kernel.CloseHandle(handle))
                    except BaseException as error:
                        errors.append(error)
            if errors:
                raise errors[0]

    class _WindowsOwner:
        def __init__(self):
            self.process = None
            self.assigned = False
            self.job = _kernel.CreateJobObjectW(None, None)
            _wincheck(self.job)
            try:
                limits = _ExtendedLimit()
                limits.BasicLimitInformation.LimitFlags = 0x2000 | 0x8  # KILL_ON_JOB_CLOSE | ACTIVE_PROCESS
                limits.BasicLimitInformation.ActiveProcessLimit = MAX_ACTIVE_PROCESSES
                _wincheck(_kernel.SetInformationJobObject(
                    self.job, 9, ctypes.byref(limits), ctypes.sizeof(limits)))
            except BaseException:
                self.close()
                raise

        def spawn(self, command, **kwargs):
            self.process = _WindowsProcess(command, **kwargs)
            _wincheck(_kernel.AssignProcessToJobObject(self.job, self.process._handle))
            self.assigned = True
            self.process.resume()
            return self.process

        def poll(self):
            status = _kernel.WaitForSingleObject(self.process._handle, 0)
            if status == 258:  # WAIT_TIMEOUT
                return None
            if status != 0:
                raise ctypes.WinError(ctypes.get_last_error())
            code = wt.DWORD()
            _wincheck(_kernel.GetExitCodeProcess(self.process._handle, ctypes.byref(code)))
            return code.value

        def active(self):
            info, size = _Accounting(), wt.DWORD()
            _wincheck(_kernel.QueryInformationJobObject(
                self.job, 1, ctypes.byref(info), ctypes.sizeof(info), ctypes.byref(size)))
            if size.value != ctypes.sizeof(info):
                raise RuntimeError("job accounting layout/size mismatch")
            return info.ActiveProcesses

        def descendants(self):
            return self.active() != 0  # Called only after the worker exits.

        def settle(self):
            if self.process is None:
                return
            deadline = time.monotonic() + _CLEANUP_SECONDS
            if self.assigned:
                handles, errors = [], []
                try:
                    try:
                        ids = _ProcessIds()
                        _wincheck(_kernel.QueryInformationJobObject(
                            self.job, 3, ctypes.byref(ids), ctypes.sizeof(ids), None))
                        if not ids.NumberOfProcessIdsInList <= ids.NumberOfAssignedProcesses <= MAX_ACTIVE_PROCESSES:
                            raise RuntimeError("job process census capacity")
                        for pid in ids.ProcessIdList[:ids.NumberOfProcessIdsInList]:
                            # Read-only observers. Numeric IDs never authorize
                            # termination; the Job exclusively owns that action.
                            handle = _kernel.OpenProcess(0x101000, False, pid)
                            if not handle and ctypes.get_last_error() == 87:
                                continue  # Already exited before observer acquisition.
                            _wincheck(handle)
                            handles.append(handle)
                            member = wt.BOOL()
                            _wincheck(_kernel.IsProcessInJob(handle, self.job, ctypes.byref(member)))
                            if not member.value:
                                raise RuntimeError("job observer identity changed")
                    except BaseException as error:
                        errors.append(error)
                    # Always attempt termination even if observation was refused.
                    _wincheck(_kernel.TerminateJobObject(self.job, 1))
                    while self.active():
                        if time.monotonic() >= deadline:
                            raise TimeoutError("job ActiveProcesses did not reach zero")
                        time.sleep(.01)
                    # Job accounting can report zero during process teardown,
                    # before the process object's exit signal. Keep original
                    # handles through this bounded final observation.
                    for handle in handles:
                        status = _kernel.WaitForSingleObject(
                            handle, max(0, math.ceil((deadline - time.monotonic()) * 1000)))
                        if status != 0:
                            raise RuntimeError("job member exit observation failed/deadline")
                finally:
                    for handle in handles:
                        try:
                            _wincheck(_kernel.CloseHandle(handle))
                        except BaseException as error:
                            errors.append(error)
                if errors:
                    raise errors[0]
            else:
                # Assignment failed while the interpreter was still suspended.
                self.process.kill()
            self.process.wait(timeout=max(.001, deadline - time.monotonic()))

        def close(self):
            try:
                if self.job:
                    handle, self.job = self.job, None
                    _wincheck(_kernel.CloseHandle(handle))
            finally:
                if self.process is not None:
                    self.process.close()


class _LinuxOwner:
    def __init__(self):
        import linux_cpu
        self.cpu = linux_cpu
        self.process = None

    def spawn(self, command, **kwargs):
        self.process = self.cpu.spawn(command, file_limit=None, **kwargs)
        return self.process

    def poll(self):
        return self.process.poll()  # WNOWAIT; retain leader until group settlement.

    def descendants(self):
        child = self.process
        child._reserved()
        self.cpu._group_proc_visible()
        deadline = time.monotonic() + _CLEANUP_SECONDS
        with os.scandir("/proc") as entries:
            for count, entry in enumerate(entries, 1):
                if count > self.cpu.GROUP_SCAN_ENTRIES or time.monotonic() >= deadline:
                    raise RuntimeError("owned group census capacity/deadline")
                if not entry.name.isascii() or not entry.name.isdecimal():
                    continue
                try:
                    with open(os.path.join(entry.path, "stat"), "rb") as stream:
                        identity = self.cpu._group_stat(stream, int(entry.name))
                except (FileNotFoundError, ProcessLookupError):
                    continue
                if identity[1] == child.group and identity[0] != child.pid:
                    return True
        return False

    def settle(self):
        if self.process is None:
            return
        # Immediate KILL; no grace period, elevation, or PID-only fallback.
        self.cpu.signal_group(self.process, signal.SIGKILL, False)
        self.cpu.wait_group_exit(self.process)
        self.process.process.wait(timeout=_CLEANUP_SECONDS)
        self.process.stopped = True

    def close(self):
        pass


def _owner():
    if sys.platform == "win32":
        return _WindowsOwner()
    if sys.platform == "linux":
        return _LinuxOwner()
    raise RuntimeError("worker custody requires Windows jobs or Linux owned groups")


def _readable(pipe):
    """Return a nonblocking read allowance, or -1 for Windows pipe EOF."""
    if sys.platform == "win32":
        available = wt.DWORD()
        if not _kernel.PeekNamedPipe(msvcrt.get_osfhandle(pipe.fileno()), None, 0,
                                    None, ctypes.byref(available), None):
            code = ctypes.get_last_error()
            if code in (109, 232):  # BROKEN_PIPE / NO_DATA
                return -1
            raise ctypes.WinError(code)
        return min(4096, available.value)
    import select
    return 4096 if select.select([pipe], [], [], 0)[0] else 0


class _Capture:
    def __init__(self, limit):
        self.limit = limit
        self.buffers = [bytearray(), bytearray()]
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.overflow = threading.Event()
        self.errors = []
        self.threads = []

    def start(self, pipes):
        for index, pipe in enumerate(pipes):
            thread = threading.Thread(target=self.read, args=(index, pipe),
                                      name=f"suite-pipe-{index}", daemon=True)
            thread.start()
            self.threads.append(thread)

    def read(self, index, pipe):
        try:
            while not self.stop.is_set():
                ready = _readable(pipe)
                if ready == -1:
                    return
                if not ready:
                    self.stop.wait(.01)
                    continue
                # The sole reader for each pipe only reads when ready. Holding
                # this lock enforces one combined read/storage budget, including
                # the single overflow sentinel byte; no unbounded drain queue.
                with self.lock:
                    remaining = self.limit + 1 - sum(map(len, self.buffers))
                    if remaining <= 0:
                        return
                    raw = os.read(pipe.fileno(), min(ready, remaining))
                    self.buffers[index].extend(raw)
                    if sum(map(len, self.buffers)) > self.limit:
                        self.overflow.set()
                        return
                if not raw:
                    return
        except BaseException as error:
            with self.lock:
                self.errors.append(error)

    def join(self, deadline):
        for thread in self.threads:
            thread.join(max(0, deadline - time.monotonic()))
        return all(not thread.is_alive() for thread in self.threads)


def run_worker(command, *, timeout, limit=MAX_OUTPUT, cwd=None, env=None):
    """Run one handshake worker; return bytes or raise WorkerError with evidence.

    ``timeout`` is finite, positive and <=900 seconds; output allowance is one
    combined stdout/stderr budget, 1..16 MiB, plus one overflow sentinel byte.
    Cleanup has separate finite five-second group/job observation and reap
    bounds, and readers share a one-second final join bound. Nonzero exit,
    surviving descendants, timeout, output overflow, and failed proof are fatal.
    Caller owns trusted Python _task code and must serialize Linux child waits.
    """
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout) or not 0 < timeout <= MAX_TIMEOUT):
        raise ValueError("timeout must be finite and in (0, 900]")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 0 < limit <= MAX_OUTPUT:
        raise ValueError("combined output limit must be in [1, 16 MiB]")
    if not isinstance(command, (list, tuple)) or not command:
        raise ValueError("command must be a nonempty argv sequence for an owned _task worker")
    started = time.monotonic()
    deadline = started + timeout
    owner, child, primary, cleanup, code = None, None, None, [], None
    capture = _Capture(limit)
    try:
        owner = _owner()
        child = owner.spawn(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, bufsize=0, cwd=cwd, env=env)
        capture.start((child.stdout, child.stderr))
        if time.monotonic() >= deadline:
            raise subprocess.TimeoutExpired(command, timeout)
        if child.stdin.write(b"go\n") != 3:
            raise RuntimeError("incomplete worker go handshake")
        child.stdin.close()
        while True:
            if capture.overflow.is_set():
                raise OutputLimitExceeded(f"combined worker output exceeds {limit} bytes")
            if capture.errors:
                raise capture.errors[0]
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(command, timeout)
            code = owner.poll()
            if code is not None:
                if code:
                    raise subprocess.CalledProcessError(code, command)
                if owner.descendants():
                    raise RuntimeError("worker exited with remaining descendants")
                break
            time.sleep(min(.01, max(0, deadline - time.monotonic())))
    except BaseException as error:
        primary = error
    finally:
        if owner is not None:
            # spawn may have created a blocked child before Job assignment failed.
            child = child if child is not None else owner.process
            try:
                owner.settle()
            except BaseException as error:
                cleanup.append(error)
        # Drain only until EOF or this bounded deadline; never wait for a leaked
        # descendant to close a pipe indefinitely.
        if not capture.join(time.monotonic() + _JOIN_SECONDS):
            capture.stop.set()
            if not capture.join(time.monotonic() + _JOIN_SECONDS):
                cleanup.append(RuntimeError("pipe reader did not stop within join deadline"))
        capture.stop.set()
        if child is not None:
            for pipe in (child.stdin, child.stdout, child.stderr):
                try:
                    pipe.close()
                except BaseException as error:
                    cleanup.append(error)
        if owner is not None:
            try:
                owner.close()
            except BaseException as error:
                cleanup.append(error)
    stdout, stderr = (bytes(value) for value in capture.buffers)
    if primary is None:
        if capture.overflow.is_set():
            primary = OutputLimitExceeded(f"combined worker output exceeds {limit} bytes")
        elif capture.errors:
            primary = capture.errors[0]
        elif cleanup:
            primary = RuntimeError("worker cleanup failed")
    duration = time.monotonic() - started
    if primary is not None:
        raise WorkerError(command, primary, cleanup, stdout, stderr, duration, code) from primary
    return WorkerResult(command, code, stdout, stderr, duration)
