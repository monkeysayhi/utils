"""
A simple implementation of exception chain in Python 2.7.x.
Support only in single-thread model.

PS: Actually, I just test on Python 2.7.10 on my computer, but whatever, it just use the most basic api.

just run it, and u will get output like:

Traceback (most recent call last):
  File "/Users/monkeysayhi/PycharmProjects/Wheel/utils/exception_chain/traced_error.py", line 68, in <module>
    __test()
  File "/Users/monkeysayhi/PycharmProjects/Wheel/utils/exception_chain/traced_error.py", line 64, in __test
    raise MyError("test MyError", e)
__main__.MyError: test MyError

Caused by:

Traceback (most recent call last):
  File "/Users/monkeysayhi/PycharmProjects/Wheel/utils/exception_chain/traced_error.py", line 62, in __test
    zero_division()
  File "/Users/monkeysayhi/PycharmProjects/Wheel/utils/exception_chain/traced_error.py", line 58, in zero_division
    a = 1 / 0
ZeroDivisionError: integer division or modulo by zero
"""
import traceback


class TracedError(BaseException):
    def __init__(self, msg="", cause=None):
        trace_msg = msg
        if cause is not None:
            _spfile = SimpleFile()
            traceback.print_exc(file=_spfile)
            _cause_tm = _spfile.read()
            trace_msg += "\n" \
                         + "\nCaused by:\n\n" \
                         + _cause_tm
        super(TracedError, self).__init__(trace_msg)


class ErrorWrapper(TracedError):
    def __init__(self, cause=None):
        super(ErrorWrapper, self).__init__("Just wrapping cause", cause)


class SimpleFile(object):
    def __init__(self, ):
        super(SimpleFile, self).__init__()
        self.buffer = ""

    def write(self, str):
        self.buffer += str

    def read(self):
        return self.buffer


def __test():
    class MyError(TracedError):
        pass

    def zero_division():
        a = 1 / 0
        return a

    try:
        zero_division()
    except StandardError as e:
        raise MyError("test MyError", e)


if __name__ == "__main__":
    __test()
