"""Logging helpers for the A2A sandbox.

NoQueryAccessFormatter: uvicorn access-log formatter that strips the query
string from the logged request line. Bearer tokens travel in headers, but a
misbehaving client could still put a secret in the URL — it must never land
in a log file, even on a rejected (401) request.
"""
import logging
from copy import copy

from uvicorn.logging import AccessFormatter


class NoQueryAccessFormatter(AccessFormatter):
    def formatMessage(self, record: logging.LogRecord) -> str:
        recordcopy = copy(record)
        try:
            args = list(recordcopy.args or [])
            if len(args) >= 3 and isinstance(args[2], str):
                args[2] = args[2].split("?", 1)[0]
                recordcopy.args = tuple(args)
        except Exception:
            pass
        return super().formatMessage(recordcopy)
