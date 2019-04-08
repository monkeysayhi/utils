import logging
import os
import signal
import subprocess
import sys
import time

from traced_error import ErrorWrapper
from internal_exceptions import TimeoutError, ExecutionError, RemoteError

DEFAULT_USER = "msh"


def is_process_exist(pname, ):
    return exe(
        "if [ `ps aux | grep '%s' | grep -v grep | wc -l` -ne 0 ]; then exit 0; fi; exit 1" % pname,
        silent=True,
    ) == 0


def is_remote_process_exist(host, pname, user=DEFAULT_USER, timeout=3, ):
    return ssh(
        host,
        "if [ `ps aux | grep '%s' | grep -v grep | wc -l` -ne 0 ]; then exit 0; fi; exit 1" % pname,
        user=user, timeout=timeout, silent=True,
    ) == 0


def is_remote_service_active(host, service_name, user=DEFAULT_USER, timeout=3, ):
    return ssh(
        host,
        "systemctl --user is-active %s" % service_name,
        user=user, timeout=timeout, silent=True,
    ) == 0


def stop_remote_service(host, service_name, user=DEFAULT_USER, timeout=3, silent=False,
                        out=sys.stdout, err=sys.stderr, ):
    __stop_remote_service_internal(
        host, service_name, user=user, timeout=timeout, silent=silent,
        out=out, err=err,
    )
    if is_remote_service_active(host, service_name, user=user, timeout=timeout, ):
        if silent:
            logging.warn("Fail to stop remote service regularly, still active,"
                         " host: %s, service_name: %s" % (host, service_name,))
            return 1
        raise RemoteError("Fail to stop remote service regularly, still active,"
                          " host: %s, service_name: %s" % (host, service_name,))
    return 0


def __stop_remote_service_internal(host, service_name, user=DEFAULT_USER, timeout=3, silent=False,
                                   out=sys.stdout, err=sys.stderr, ):
    return ssh(
        host,
        "systemctl --user stop %s" % service_name
        + " && systemctl --user disable %s" % service_name,
        user=user, timeout=timeout, silent=silent,
        out=out, err=err,
    )


def restart_remote_service(host, service_path, user=DEFAULT_USER, timeout=3, silent=False,
                           out=sys.stdout, err=sys.stderr, ):
    __restart_remote_service_internal(
        host, service_path, user=user, timeout=timeout, silent=silent,
        out=out, err=err,
    )
    service_name = os.path.basename(service_path)
    if not is_remote_service_active(host, service_name, user=user, timeout=timeout, ):
        if silent:
            logging.warn("Fail to restart remote service regularly, not active,"
                         " host: %s, service_name: %s" % (host, service_name,))
            return 1
        raise RemoteError("Fail to restart remote service regularly, not active,"
                          " host: %s, service_name: %s" % (host, service_name,))
    return 0


def __restart_remote_service_internal(host, service_path, user=DEFAULT_USER, timeout=3, silent=False,
                                      out=sys.stdout, err=sys.stderr, ):
    service_name = os.path.basename(service_path)
    return ssh(
        host,
        "systemctl --user enable %s" % service_path
        + " && systemctl --user restart %s" % service_name,
        user=user, timeout=timeout, silent=silent,
        out=out, err=err,
    )


def is_remote_dir_exist(host, dir_path, user=DEFAULT_USER, timeout=3, ):
    return ssh(
        host,
        "test -d %s" % dir_path,
        user=user, timeout=timeout, silent=True,
    ) == 0


def is_remote_file_exist(host, file_path, user=DEFAULT_USER, timeout=3, ):
    return ssh(
        host,
        "test -f %s" % file_path,
        user=user, timeout=timeout, silent=True,
    ) == 0


def remove_remote_path(host, path, user=DEFAULT_USER, timeout=3, ):
    return ssh(
        host,
        "rm -rf %s" % path,
        user=user, timeout=timeout, silent=True,
    ) == 0


# TODO 20171016 monkeysayhi rename argv timeout and exec_timeout

def ssh(host, sub_cmd, user=DEFAULT_USER, timeout=3, silent=False,
        out=sys.stdout, err=sys.stderr, ):
    return exec_command([
        "ssh",
        "-o UserKnownHostsFile=/dev/null",
        "-o ConnectTimeout=%s" % timeout,
        "-o ServerAliveInterval=60",
        "-o TCPKeepAlive=yes",
        "-o LogLevel=quiet",
        "-o PasswordAuthentication=no",
        "-o StrictHostKeyChecking=no",
        "%s@%s" % (user, host,),
        "%s" % sub_cmd,
    ], silent=silent, out=out, err=err)


def scp_from_local(local_file_path, host, file_path, user=DEFAULT_USER, timeout=3, silent=False,
                   out=sys.stdout, err=sys.stderr, ):
    return exec_command([
        "scp",
        "-o UserKnownHostsFile=/dev/null",
        "-o ConnectTimeout=%s" % timeout,
        "-o StrictHostKeyChecking=no",
        "-o PasswordAuthentication=no",
        local_file_path,
        "%s@%s:%s" % (user, host, file_path,),
    ], silent=silent, out=out, err=err)


def scp_to_local(host, file_path, local_file_path, user=DEFAULT_USER, timeout=3, silent=False,
                 out=sys.stdout, err=sys.stderr, ):
    return exec_command([
        "scp",
        "-o UserKnownHostsFile=/dev/null",
        "-o ConnectTimeout=%s" % timeout,
        "-o StrictHostKeyChecking=no",
        "-o PasswordAuthentication=no",
        "%s@%s:%s" % (user, host, file_path,),
        local_file_path,
    ], silent=silent, out=out, err=err)


def exe(sub_cmd, silent=False,
        out=sys.stdout, err=sys.stderr, ):
    return exec_command([sub_cmd, ], silent=silent, out=out, err=err)


def exec_command(cmd, silent=False, out=sys.stdout, err=sys.stderr, shell=False,
                 exec_timeout=60, kill_tree=True, ):
    _cmd_str = " ".join(cmd)

    ret = 1
    try:
        ret = __exec_command_internal(
            cmd, out=out, err=err, shell=shell, exec_timeout=exec_timeout, kill_tree=kill_tree, )
    except TimeoutError as e:
        if silent:
            logging.warn("Fail to execute command: %s, ret: %s, cause: %s"
                         % (_cmd_str, ret, "(%s: %s)" % (type(e).__name__, e.message,)))
            return 1
        raise ExecutionError("Fail to execute command: %s, ret: %s" % (_cmd_str, ret), e)

    if ret == 0:
        return 0

    if silent:
        logging.warn("Fail to execute command: %s, ret: %s" % (_cmd_str, ret))
        return ret
    raise ExecutionError("Fail to execute command: %s, ret: %s" % (_cmd_str, ret))


def __exec_command_internal(cmd, out=sys.stdout, err=sys.stderr, shell=False,
                            exec_timeout=None, kill_tree=True, ):
    _cmd_str = " ".join(cmd)

    p = subprocess.Popen(cmd, stdout=out, stderr=err, shell=shell, )

    if exec_timeout is None or exec_timeout <= 0:
        return p.wait()

    start = int(time.time())
    now = int(time.time())
    while start + exec_timeout >= now and p.poll() is None:
        time.sleep(1)
        now = int(time.time())

    if start + exec_timeout >= now:
        ret = p.poll()
        logging.debug("done before exec_timeout, ret: %s" % ret)
        return ret

    logging.warn("Timeout to execute command: %s, exec_timeout: %s, killing" % (_cmd_str, exec_timeout,))
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
    logging.info("Killed all processes, ppid: %s" % p.pid)

    raise TimeoutError("Timeout to execute command: %s, exec_timeout: %s" % (_cmd_str, exec_timeout,))


def __get_child_process(pid, out=sys.stdout, err=sys.stderr, ):
    # FIXME 20171016 monkeysayhi maybe hang if existing too many child processes(almost wouldn't happen)
    cmd = "ps --no-headers -o pid --ppid %d" % pid
    p = subprocess.Popen(cmd, shell=True, stdout=out, stderr=err, )
    stdout, stderr = p.communicate()
    if stderr is None and stdout is None:
        return []
    if stderr is None and stdout is not None:
        return map(int, stdout.split())
    if stderr is not None and stdout is None:
        raise OSError("Fail to execute cmd: %s, stderr: %s" % (cmd, stderr,))
    if stderr is not None and stdout is not None:
        raise OSError("Fail to execute cmd: %s, stderr: %s, stdout: %s" % (cmd, stderr, stdout,))
