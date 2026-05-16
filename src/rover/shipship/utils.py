# Originally yoyo-migrations by Oliver Cope (Apache License 2.0).
# Modified for ROVER as the shipship migration sub-module.

import random
import re
import string
import typing as t
from collections import abc
from itertools import count


def plural(quantity, one, plural):
    """
    >>> plural(1, '%d dead frog', '%d dead frogs')
    '1 dead frog'
    >>> plural(2, '%d dead frog', '%d dead frogs')
    '2 dead frogs'
    """
    if quantity == 1:
        return one.replace("%d", "%d" % quantity)
    return plural.replace("%d", "%d" % quantity)


def get_random_string(length, chars=(string.ascii_letters + string.digits)):
    """
    Return a random string of ``length`` characters
    """
    rng = random.SystemRandom()
    return "".join(rng.choice(chars) for i in range(length))


def change_param_style(
    target_style: str, sql: str, bind_parameters: t.Optional[abc.Mapping[str, t.Any]]
) -> tuple[str, t.Union[abc.Mapping[str, t.Any], abc.Sequence[str]]]:
    """
    :param target_style: A DBAPI paramstyle value (eg 'qmark', 'format', etc)
    :param sql: An SQL str
    :param bind_parameters: A dict of bind parameters for the query

    :return: tuple of `(sql, bind_parameters)`. ``sql`` will be rewritten with
             the target paramstyle; ``bind_parameters`` will be a tuple or
             dict as required.
    """
    if target_style == "named":
        return sql, bind_parameters or {}
    positional = target_style in {"qmark", "numeric", "format"}
    if not bind_parameters:
        return (sql, (tuple() if positional else {}))

    _param_counter = count(1)

    def param_gen_qmark(name):
        return "?"

    def param_gen_numeric(name):
        return f":{next(_param_counter)}"

    def param_gen_format(name):
        return "%s"

    def param_gen_pyformat(name):
        return f"%({name})s"

    param_gen = {
        "qmark": param_gen_qmark,
        "numeric": param_gen_numeric,
        "format": param_gen_format,
        "pyformat": param_gen_pyformat,
    }[target_style]

    pattern = re.compile(
        # Don't match if preceded by backslash (an escape)
        # or ':' (an SQL cast, eg '::INT')
        r"(?<![:\\])"
        # one of the given bind_parameters
        r":(" + "|".join(re.escape(k) for k in bind_parameters) + r")"
        # followed by a non-word char, or end of string
        r"(?=\W|$)"
    )

    transformed_sql = pattern.sub(lambda match: param_gen(match.group(1)), sql)
    if positional:
        positional_params = []
        for match in pattern.finditer(sql):
            param_name = match.group(1)
            positional_params.append(bind_parameters[param_name])
        return transformed_sql, tuple(positional_params)
    return transformed_sql, bind_parameters
