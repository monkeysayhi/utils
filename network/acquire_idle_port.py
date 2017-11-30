import socket


def acquire_idle_port():
    trying_socket = None
    idle_port = -1
    try:
        trying_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # given port = 0 , and os will random select a idle port
        trying_socket.bind(("", 0))
        idle_port = trying_socket.getsockname()[1]
    finally:
        if trying_socket is not None:
            trying_socket.close()
    return idle_port


if __name__ == '__main__':
    print acquire_idle_port()
