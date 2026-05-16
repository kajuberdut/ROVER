# Originally yoyo-migrations by Oliver Cope (Apache License 2.0).
# Modified for ROVER as the shipship migration sub-module.

from .backends import get_backend_class
from .migrations import default_migration_table


class DatabaseURI:
    __slots__ = ("scheme", "username", "password", "hostname", "port", "database", "args")

    def __init__(self, scheme, username, password, hostname, port, database, args):
        self.scheme = scheme
        self.username = username
        self.password = password
        self.hostname = hostname
        self.port = port
        self.database = database
        self.args = args

    def __str__(self):
        parts = [self.scheme, "://"]
        if self.username:
            parts.append(self.username)
            if self.password:
                parts.append(f":{self.password}")
            parts.append("@")
        if self.hostname:
            parts.append(self.hostname)
        if self.port:
            parts.append(f":{self.port}")
        if self.database:
            parts.append(f"/{self.database}")
        return "".join(parts)

    def __repr__(self):
        # Never expose password in repr
        safe = str(self).replace(f":{self.password}@", ":***@") if self.password else str(self)
        return f"DatabaseURI({safe!r})"


def parse_uri(uri):
    """
    Parse a database URI string into a DatabaseURI object.

    Supports schemes: postgresql, postgresql+psycopg
    """
    import re

    match = re.match(
        r"""
        (?P<scheme>[^:]+)://
        (?:(?P<username>[^:@/]*)(?::(?P<password>[^@/]*))?@)?
        (?P<hostname>[^/:@?]*)?
        (?::(?P<port>\d+))?
        (?:/(?P<database>[^?]*))?
        (?:\?(?P<args>.*))?
        """,
        uri,
        re.VERBOSE,
    )
    if not match:
        raise ValueError(f"Could not parse database URI: {uri!r}")

    args = {}
    raw_args = match.group("args") or ""
    for part in raw_args.split("&"):
        if "=" in part:
            k, _, v = part.partition("=")
            args[k] = v

    port = match.group("port")
    return DatabaseURI(
        scheme=match.group("scheme"),
        username=match.group("username") or None,
        password=match.group("password") or None,
        hostname=match.group("hostname") or None,
        port=int(port) if port else None,
        database=match.group("database") or None,
        args=args,
    )


def get_backend(uri, migration_table=default_migration_table):
    """
    Connect to the database described by ``uri`` and return a backend instance.

    :param uri: A database URI string (eg ``postgresql+psycopg://user@host/db``)
    :param migration_table: Name of the migration tracking table
    """
    parsed = parse_uri(uri)
    backend_class = get_backend_class(parsed.scheme)
    return backend_class(parsed, migration_table)
