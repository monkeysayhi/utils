class BaseError(StandardError):
    pass


class IllegalArgsError(BaseError):
    pass


class IllegalStateError(BaseError):
    pass


class ExecutionError(BaseError):
    pass


class TimeoutError(BaseError):
    pass


class RemoteError(BaseError):
    pass


class RemoteOSError(RemoteError):
    pass


class RemoteIOError(RemoteError):
    pass


class UnknownError(BaseError):
    pass


class ConcurrentExecutionError(IllegalStateError):
    pass


class NotProcessingError(BaseError):
    pass
