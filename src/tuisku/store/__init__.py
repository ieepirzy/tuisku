"""The evidence store: the only code that holds schema knowledge (ADR 0004).

Plain SQL through psycopg (async); no ORM. Functions take an open connection and leave
transaction boundaries to the caller unless they say otherwise.
"""
