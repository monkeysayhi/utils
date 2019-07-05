import logging
import os
import pwd
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time

from .internal_exceptions import TimeoutError, ExecutionError, RemoteError, IllegalArgsError
from .traced_error import ErrorWrapper

DEFAULT_USER = pwd.getpwuid(os.getuid())[0]

DEFAULT_CONN_TIMEOUT = 5
DEFAULT_EXEC_TIMEOUT = 0

__TMPFS_ROOT = "/tmp"

# FIXME(msh) not concurrent safe in re-importing
__TMPDIR = os.path.join(__TMPFS_ROOT, "shell_tool", str(os.getpid()))
if os.path.exists(__TMPDIR):
    assert not os.path.islink(__TMPDIR)
    shutil.rmtree(__TMPDIR, ignore_errors=True)
    assert not os.path.exists(__TMPDIR)
os.makedirs(__TMPDIR)
os.chmod(__TMPDIR, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)


def __get_tmp_file(prefix="tmpfile"):
    thread_id = threading.currentThread().ident
    ts = int(time.time() * 1000)
    tmpfile = os.path.join(__TMPDIR, "%s-%d-%d" % (prefix, thread_id, ts))
    # it's not possible that threads with the same thread-id enter this func at the same time
    assert os.path.isdir(__TMPDIR)
    assert not os.path.exists(tmpfile)
    return tmpfile


def __redirect_to_null(cmd):
    APPEND_STR = "> /dev/null 2>&1"
    assert isinstance(cmd, (str, list, tuple))
    if isinstance(cmd, str):
        return cmd + " " + APPEND_STR
    else:
        return cmd + [APPEND_STR]


def is_process_exist(pname=None, pid=None, silent=True, suppress_timeout=False,
                     exec_timeout=DEFAULT_EXEC_TIMEOUT, no_o_e=True, ):
    assert pname is not None or pid is not None
    if pname is not None and pid is None:
        return is_process_exist_by_pname(pname, suppress_timeout=suppress_timeout, exec_timeout=exec_timeout)
    if pname is None and pid is not None:
        return is_process_exist_by_pid(pid, suppress_timeout=suppress_timeout, exec_timeout=exec_timeout)
    assert isinstance(pid, int)
    cmd_str = ("[ `ps aux | awk '{if($2 == %d) print $0}' | grep '%s' | grep -v grep | wc -l` -ge 1 ]"
               % (pid, pname))
    if no_o_e:
        cmd_str = __redirect_to_null(cmd_str)
    return exe(
        [cmd_str, ], silent=silent, suppress_timeout=suppress_timeout, shell=True,
        exec_timeout=exec_timeout,
    ) == 0


def is_process_exist_by_pname(pname, silent=True, suppress_timeout=False,
                              exec_timeout=DEFAULT_EXEC_TIMEOUT, no_o_e=True, ):
    cmd_str = "[ `ps aux | grep '%s' | grep -v grep | wc -l` -ge 1 ]" % pname
    if no_o_e:
        cmd_str = __redirect_to_null(cmd_str)
    return exe(
        [cmd_str, ], silent=silent, suppress_timeout=suppress_timeout, shell=True,
        exec_timeout=exec_timeout,
    ) == 0


def is_process_exist_by_pid(pid, silent=True, suppress_timeout=False,
                            exec_timeout=DEFAULT_EXEC_TIMEOUT, no_o_e=True, ):
    cmd_str = "ls -d /proc/%d/" % pid
    if no_o_e:
        cmd_str = __redirect_to_null(cmd_str)
    return exe(
        [cmd_str, ], silent=silent, suppress_timeout=suppress_timeout, shell=True,
        exec_timeout=exec_timeout,
    ) == 0


def is_remote_process_exist(host, pname,
                            silent=True, suppress_timeout=False,
                            user=DEFAULT_USER, conn_timeout=DEFAULT_CONN_TIMEOUT,
                            exec_timeout=DEFAULT_EXEC_TIMEOUT,
                            no_o_e=True):
    cmd_str = "[ `ps aux | grep '%s' | grep -v grep | grep -v 'sh -c' | wc -l` -ge 1 ]" % pname
    if no_o_e:
        cmd_str = __redirect_to_null(cmd_str)
    return ssh(
        host, cmd_str, silent=silent, suppress_timeout=suppress_timeout,
        user=user, conn_timeout=conn_timeout, exec_timeout=exec_timeout,
    ) == 0


def is_remote_service_active(host, service_name,
                             silent=True, suppress_timeout=False,
                             user=DEFAULT_USER, conn_timeout=DEFAULT_CONN_TIMEOUT,
                             exec_timeout=DEFAULT_EXEC_TIMEOUT,
                             no_o_e=True):
    # option --quiet cannot suppress stderr
    cmd = ["systemctl --user is-enabled %s" % service_name,
           "&&",
           "systemctl --user is-active %s" % service_name]
    if no_o_e:
        cmd[0] = __redirect_to_null(cmd[0])
        cmd[2] = __redirect_to_null(cmd[2])
    cmd_str = " ".join(cmd)
    return ssh(
        host, cmd_str, silent=silent, suppress_timeout=suppress_timeout,
        user=user, conn_timeout=conn_timeout, exec_timeout=exec_timeout,
    ) == 0


def stop_remote_service(host, service_name, silent=False, suppress_timeout=False,
                        user=DEFAULT_USER, conn_timeout=DEFAULT_CONN_TIMEOUT,
                        exec_timeout=DEFAULT_EXEC_TIMEOUT,
                        no_o_e=True, out=sys.stdout, err=sys.stderr, ):
    # make stop op idempotent
    __stop_remote_service_internal(
        host, service_name, silent=True, suppress_timeout=True,
        user=user, conn_timeout=conn_timeout, exec_timeout=exec_timeout,
        no_o_e=no_o_e, out=out, err=err,
    )
    if is_remote_service_active(host, service_name, silent=silent, suppress_timeout=suppress_timeout,
                                user=user, conn_timeout=conn_timeout, exec_timeout=exec_timeout,
                                no_o_e=no_o_e, ):
        if silent:
            logging.debug("Fail to stop remote service regularly, still active,"
                          " host: %s, service_name: %s" % (host, service_name,))
            return 1
        raise RemoteError("Fail to stop remote service regularly, still active,"
                          " host: %s, service_name: %s" % (host, service_name,))
    return 0


def __stop_remote_service_internal(host, service_name, silent=False, suppress_timeout=False,
                                   user=DEFAULT_USER, conn_timeout=DEFAULT_CONN_TIMEOUT,
                                   exec_timeout=DEFAULT_EXEC_TIMEOUT,
                                   no_o_e=True, out=sys.stdout, err=sys.stderr, ):
    # option --quiet cannot suppress stderr
    cmd = ["systemctl --user stop %s" % service_name,
           ";",
           "systemctl --user disable %s" % service_name]
    if no_o_e:
        cmd[0] = __redirect_to_null(cmd[0])
        cmd[2] = __redirect_to_null(cmd[2])
    cmd_str = " ".join(cmd)
    return ssh(host, cmd_str, silent=silent, suppress_timeout=suppress_timeout,
               user=user, conn_timeout=conn_timeout, exec_timeout=exec_timeout,
               out=out, err=err, )


def restart_remote_service(host, service_path, silent=False, suppress_timeout=False,
                           user=DEFAULT_USER, conn_timeout=DEFAULT_CONN_TIMEOUT,
                           exec_timeout=DEFAULT_EXEC_TIMEOUT,
                           no_o_e=True, out=sys.stdout, err=sys.stderr, ):
    # restart op cannot be idempotent
    ret = __restart_remote_service_internal(
        host, service_path, silent=silent, suppress_timeout=suppress_timeout,
        user=user, conn_timeout=conn_timeout, exec_timeout=exec_timeout,
        no_o_e=no_o_e, out=out, err=err,
    )
    if ret != 0:
        if silent:
            logging.debug("Fail to restart remote service,"
                          " host: %s, service_path: %s" % (host, service_path,))
            return ret
        raise RemoteError("Fail to restart remote service,"
                          " host: %s, service_path: %s" % (host, service_path,))
    service_name = os.path.basename(service_path)
    if not is_remote_service_active(host, service_name, silent=silent, suppress_timeout=suppress_timeout,
                                    user=user, conn_timeout=conn_timeout, exec_timeout=exec_timeout,
                                    no_o_e=no_o_e):
        if silent:
            logging.debug("Fail to restart remote service regularly, not active,"
                          " host: %s, service_name: %s" % (host, service_name,))
            return 1
        raise RemoteError("Fail to restart remote service regularly, not active,"
                          " host: %s, service_name: %s" % (host, service_name,))
    return 0


def __restart_remote_service_internal(host, service_path, silent=False, suppress_timeout=False,
                                      user=DEFAULT_USER, conn_timeout=DEFAULT_CONN_TIMEOUT,
                                      exec_timeout=DEFAULT_EXEC_TIMEOUT,
                                      no_o_e=True, out=sys.stdout, err=sys.stderr, ):
    service_name = os.path.basename(service_path)
    # option --quiet cannot suppress stderr
    cmd = ["systemctl --user --force enable %s" % service_path,
           "&&",
           "systemctl --user restart %s" % service_name]
    if no_o_e:
        cmd[0] = __redirect_to_null(cmd[0])
        cmd[2] = __redirect_to_null(cmd[2])
    cmd_str = " ".join(cmd)
    return ssh(host, cmd_str, silent=silent, suppress_timeout=suppress_timeout,
               user=user, conn_timeout=conn_timeout, exec_timeout=exec_timeout,
               out=out, err=err, )


def is_remote_dir_exist(host, dir_path, suppress_timeout=False,
                        user=DEFAULT_USER, conn_timeout=DEFAULT_CONN_TIMEOUT,
                        exec_timeout=DEFAULT_EXEC_TIMEOUT,
                        no_o_e=True, ):
    cmd_str = "[ -d %s ]" % dir_path
    if no_o_e:
        cmd_str = __redirect_to_null(cmd_str)
    return ssh(
        host, cmd_str, silent=True, suppress_timeout=suppress_timeout,
        user=user, conn_timeout=conn_timeout, exec_timeout=exec_timeout,
    ) == 0


def is_remote_file_exist(host, file_path, suppress_timeout=False,
                         user=DEFAULT_USER, conn_timeout=DEFAULT_CONN_TIMEOUT,
                         exec_timeout=DEFAULT_EXEC_TIMEOUT,
                         no_o_e=True, ):
    cmd_str = "[ -f %s ]" % file_path
    if no_o_e:
        cmd_str = __redirect_to_null(cmd_str)
    return ssh(
        host, cmd_str, silent=True, suppress_timeout=suppress_timeout,
        user=user, conn_timeout=conn_timeout, exec_timeout=exec_timeout,
    ) == 0


# FIXME(msh) failed sometimes when existing non-empty subdir
def remove_remote_path(host, path, suppress_timeout=False,
                       user=DEFAULT_USER, conn_timeout=DEFAULT_CONN_TIMEOUT,
                       exec_timeout=DEFAULT_EXEC_TIMEOUT,
                       no_o_e=True, ):
    cmd_str = "rm -rf %s" % path
    if no_o_e:
        cmd_str = __redirect_to_null(cmd_str)
    return ssh(host, cmd_str, silent=False, suppress_timeout=suppress_timeout,
               user=user, conn_timeout=conn_timeout, exec_timeout=exec_timeout)


def scp_from_local(local_file_path, host, file_path, silent=False, suppress_timeout=False,
                   user=DEFAULT_USER, conn_timeout=DEFAULT_CONN_TIMEOUT,
                   exec_timeout=DEFAULT_EXEC_TIMEOUT,
                   no_o_e=True, out=sys.stdout, err=sys.stderr, ):
    cmd = [
        "scp",
        "-o UserKnownHostsFile=/dev/null",
        "-o ConnectTimeout=%s" % conn_timeout,
        "-o StrictHostKeyChecking=no",
        "-o PasswordAuthentication=no",
        local_file_path,
        "%s@%s:%s" % (user, host, file_path,),
    ]
    if no_o_e:
        cmd.insert(1, "-q")
    return exec_command(cmd, silent=silent, suppress_timeout=suppress_timeout,
                        exec_timeout=exec_timeout, out=out, err=err)


def scp_to_local(host, file_path, local_file_path, silent=False, suppress_timeout=False,
                 user=DEFAULT_USER, conn_timeout=DEFAULT_CONN_TIMEOUT,
                 exec_timeout=DEFAULT_EXEC_TIMEOUT,
                 no_o_e=True, out=sys.stdout, err=sys.stderr, ):
    cmd = [
        "scp",
        "-o UserKnownHostsFile=/dev/null",
        "-o ConnectTimeout=%s" % conn_timeout,
        "-o StrictHostKeyChecking=no",
        "-o PasswordAuthentication=no",
        "%s@%s:%s" % (user, host, file_path,),
        local_file_path,
    ]
    if no_o_e:
        cmd.insert(1, "-q")
    return exec_command(cmd, silent=silent, suppress_timeout=suppress_timeout,
                        exec_timeout=exec_timeout, out=out, err=err)


def ssh(host, sub_cmd, silent=False, suppress_timeout=False,
        user=DEFAULT_USER, conn_timeout=DEFAULT_CONN_TIMEOUT,
        exec_timeout=DEFAULT_EXEC_TIMEOUT,
        out=sys.stdout, err=sys.stderr, ):
    return exec_command([
        "ssh",
        "-o UserKnownHostsFile=/dev/null",
        "-o ConnectTimeout=%s" % conn_timeout,
        "-o ServerAliveInterval=60",
        "-o TCPKeepAlive=yes",
        "-o LogLevel=quiet",
        "-o PasswordAuthentication=no",
        "-o StrictHostKeyChecking=no",
        "%s@%s" % (user, host,),
        "%s" % sub_cmd,
    ], silent=silent, suppress_timeout=suppress_timeout, exec_timeout=exec_timeout, out=out, err=err)


def ssh_with_out(host, sub_cmd, silent=False, suppress_timeout=False,
                 user=DEFAULT_USER, conn_timeout=DEFAULT_CONN_TIMEOUT,
                 exec_timeout=DEFAULT_EXEC_TIMEOUT,
                 err=sys.stderr, ):
    tmpfile = __get_tmp_file("ssh_with_out")
    try:
        with open(tmpfile, "w") as _wfile:
            ret = ssh(host, sub_cmd, silent=silent, suppress_timeout=suppress_timeout,
                      user=user, conn_timeout=conn_timeout, exec_timeout=exec_timeout,
                      out=_wfile, err=err)
        if not os.path.isfile(tmpfile):
            content = ""
        else:
            with open(tmpfile, "r") as _rfile:
                content = _rfile.read().strip()
        return [ret, content]
    finally:
        if os.path.isfile(tmpfile):
            os.remove(tmpfile)


def exe(cmd, silent=False, suppress_timeout=False, shell=False,
        exec_timeout=DEFAULT_EXEC_TIMEOUT, out=sys.stdout, err=sys.stderr, ):
    if isinstance(cmd, str):
        cmd = cmd.split(" ")
    if not isinstance(cmd, (list, tuple)):
        raise IllegalArgsError(
            "Type of cmd should be str, list or tuple, got: %s" % type(cmd).__name__)
    return exec_command(cmd, silent=silent, suppress_timeout=suppress_timeout, shell=shell,
                        exec_timeout=exec_timeout, out=out, err=err)


def exe_with_out(cmd, silent=False, suppress_timeout=False, shell=False,
                 exec_timeout=DEFAULT_EXEC_TIMEOUT, err=sys.stderr, ):
    tmpfile = __get_tmp_file("exe_with_out")
    try:
        with open(tmpfile, "w") as _wfile:
            ret = exe(cmd, silent=silent, suppress_timeout=suppress_timeout, shell=shell,
                      exec_timeout=exec_timeout, out=_wfile, err=err)
        if not os.path.isfile(tmpfile):
            content = ""
        else:
            with open(tmpfile, "r") as _rfile:
                content = _rfile.read().strip()
        return [ret, content]
    finally:
        if os.path.isfile(tmpfile):
            os.remove(tmpfile)


def exec_command(cmd, silent=False, suppress_timeout=False, shell=False,
                 exec_timeout=DEFAULT_EXEC_TIMEOUT, out=sys.stdout, err=sys.stderr,
                 kill_tree=True):
    _cmd_str = " ".join(cmd)

    rs = __exec_command_internal(
        cmd, out=out, err=err, shell=shell, exec_timeout=exec_timeout, kill_tree=kill_tree, )
    if rs[0]:
        if suppress_timeout:
            logging.info("Timeout to execute command: %s, exec_timeout: %ss" % (_cmd_str, exec_timeout,))
            return 1
        raise TimeoutError("Timeout to execute command: %s, exec_timeout: %ss" % (_cmd_str, exec_timeout,))

    ret = rs[1]
    if ret == 0:
        return 0
    if silent:
        logging.debug("Fail to execute command: %s, ret: %s" % (_cmd_str, ret))
        return ret
    raise ExecutionError("Fail to execute command: %s, ret: %s" % (_cmd_str, ret))


def __exec_command_internal(cmd, shell=False,
                            exec_timeout=DEFAULT_EXEC_TIMEOUT, out=sys.stdout, err=sys.stderr,
                            kill_tree=True):
    _cmd_str = " ".join(cmd)

    p = subprocess.Popen(cmd, stdout=out, stderr=err, shell=shell, )

    if exec_timeout is None or exec_timeout <= 0:
        return [False, p.wait()]

    start = int(time.time())
    now = int(time.time())
    while start + exec_timeout >= now and p.poll() is None:
        time.sleep(1)
        now = int(time.time())

    if start + exec_timeout >= now:
        ret = p.poll()
        logging.debug("done before exec_timeout, ret: %s" % ret)
        return [False, ret]

    pids = [p.pid]
    if kill_tree:
        try:
            child_pids = __get_child_process(p.pid, out=out, err=err, )
        except OSError as os_e:
            logging.warn("Timeout but fail to get child processes, ppid: %d" % int(p.pid))
            raise ErrorWrapper(os_e)
        pids.extend(child_pids)
    for pid in pids:
        # process might have died before getting to this line
        # so wrap to avoid OSError: no such process
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError as os_e:
            if os.path.isdir("/proc/%d" % int(pid)):
                logging.warn("Timeout but fail to kill process, still exist: %d, " % int(pid))
                raise ErrorWrapper(os_e)
            logging.debug("Timeout but no need to kill process, already no such process: %d" % int(pid))
    logging.debug("Killed all processes, ppid: %s" % p.pid)
    return [True, None]


def __get_child_process(pid, out=sys.stdout, err=sys.stderr, ):
    # FIXME(msh) maybe hang if existing too many child processes(almost wouldn't happen)
    cmd = "ps --no-headers -o pid --ppid %d" % pid
    p = subprocess.Popen(cmd, shell=True, stdout=out, stderr=err, )
    stdout, stderr = p.communicate()
    if stderr is None and stdout is None:
        return []
    if stderr is None and stdout is not None:
        return list(map(int, stdout.split()))
    if stderr is not None and stdout is None:
        raise OSError("Fail to execute cmd: %s, stderr: %s" % (cmd, stderr,))
    if stderr is not None and stdout is not None:
        raise OSError("Fail to execute cmd: %s, stderr: %s, stdout: %s" % (cmd, stderr, stdout,))
