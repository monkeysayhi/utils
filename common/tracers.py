import functools
import logging
import time

__TIME_FORMAT = "%Y-%m-%d-%X"


def __format_time(ts_s):
    return time.strftime(__TIME_FORMAT, time.localtime(ts_s))


def trace_time(func):
    """trace begin time, end time and cost time of a func call
    """

    @functools.wraps(func)
    def wrapper(*args, **kw):
        begin = time.time()
        logging.debug("begin at %s: %s()" % (__format_time(begin), func.__name__))
        result = func(*args, **kw)
        end = time.time()
        logging.debug(
            "end at %s, cost %.2fs: %s() -- return type: %s"
            % (__format_time(end), end - begin, func.__name__, type(result).__name__))
        return result

    return wrapper
