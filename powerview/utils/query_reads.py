from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime


@dataclass
class QueryReads:
    read_at: datetime | None = None
    cached: bool = False

    def record(self, read_at, cached=False):
        self.read_at = min(self.read_at, read_at) if self.read_at else read_at
        self.cached = self.cached or cached


_reads = ContextVar('query_reads', default=None)


@contextmanager
def track_query_reads():
    reads = QueryReads()
    token = _reads.set(reads)
    try:
        yield reads
    finally:
        _reads.reset(token)


def record_query_read(read_at, cached=False):
    reads = _reads.get()
    if reads is not None:
        reads.record(read_at, cached)
