# Copyright 2015 Oliver Cope
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import configparser
import logging
import sys
import typing as t

from yoyo import connections, default_migration_table

verbosity_levels = {
    0: logging.ERROR,
    1: logging.WARN,
    2: logging.INFO,
    3: logging.DEBUG,
}

min_verbosity = min(verbosity_levels)
max_verbosity = max(verbosity_levels)


class InvalidArgument(Exception):
    pass


def _empty_config() -> configparser.ConfigParser:
    """Return an empty ConfigParser. Used in batch mode where no config file is needed."""
    return configparser.ConfigParser()


def _update_argparser_defaults(parser, defaults):
    """
    Update an ArgumentParser's defaults.

    Unlike ArgumentParser.set_defaults this will only set defaults for
    arguments the parser has configured.
    """
    known_args = {action.dest for action in parser._actions}
    parser.set_defaults(**{k: v for k, v in defaults.items() if k in known_args})


def parse_args(
    argv=None,
) -> t.Tuple[configparser.ConfigParser, argparse.ArgumentParser, argparse.Namespace]:
    """
    Parse command line args.

    :return: tuple of ``(empty config, argument parser, parsed arguments)``
    """
    config_args = {
        "batch_mode": "getboolean",
        "sources": "get",
        "database": "get",
        "verbosity": "getint",
        "migration_table": "get",
    }

    globalparser, argparser, subparsers = make_argparser()

    # Initial parse to extract any global arguments
    global_args, _ = globalparser.parse_known_args(argv)

    # Always use an empty config — no yoyo.ini support in ROVER's batch mode
    config = _empty_config()

    defaults = {}
    for argname, getter in config_args.items():
        try:
            defaults[argname] = getattr(config, getter)("DEFAULT", argname)
        except configparser.NoOptionError:
            pass

    if "sources" in defaults:
        defaults["sources"] = defaults["sources"].split()

    _update_argparser_defaults(globalparser, defaults)
    _update_argparser_defaults(argparser, defaults)
    for subp in subparsers.choices.values():
        _update_argparser_defaults(subp, defaults)

    args = argparser.parse_args(argv)

    # Ensure global args (eg '-v') are recognised regardless of position
    args.__dict__.update(globalparser.parse_known_args(argv)[0].__dict__)

    return config, argparser, args


def make_argparser():
    """
    Return a top-level ArgumentParser parser object,
    plus a list of sub_parsers
    """
    global_parser = argparse.ArgumentParser(add_help=False)
    global_parser.add_argument(
        "--config", "-c", default=None, help="Path to config file (unused in batch mode)"
    )
    global_parser.add_argument(
        "-v",
        dest="verbosity",
        action="count",
        default=min_verbosity,
        help="Verbose output. Use multiple times to increase level of verbosity",
    )
    global_parser.add_argument(
        "-b",
        "--batch",
        dest="batch_mode",
        action="store_true",
        default=(not sys.stdout.isatty()),
        help="Run in batch mode. Turns off all user prompts",
    )

    argparser = argparse.ArgumentParser(prog="yoyo", parents=[global_parser])

    subparsers = argparser.add_subparsers(help="Commands help")

    from . import migrate

    migrate.install_argparsers(global_parser, subparsers)

    return global_parser, argparser, subparsers


def configure_logging(level):
    """
    Configure the python logging module with the requested loglevel
    """
    logging.basicConfig(level=verbosity_levels[level])


def get_backend(args, config):
    try:
        dburi = args.database
    except AttributeError:
        dburi = config.get("DEFAULT", "database")

    try:
        migration_table = args.migration_table
    except AttributeError:
        try:
            migration_table = config.get("DEFAULT", "migration_table")
        except configparser.NoOptionError:
            migration_table = default_migration_table

    if dburi is None:
        raise InvalidArgument("Please specify a database uri")

    return connections.get_backend(dburi, migration_table)


def main(argv=None):
    config, argparser, args = parse_args(argv)

    if getattr(args, "func", None) is None:
        argparser.print_usage(sys.stderr)
        argparser.exit(1)

    verbosity = args.verbosity
    verbosity = min(max_verbosity, max(min_verbosity, verbosity))
    configure_logging(verbosity)

    try:
        if vars(args).get("func"):
            exitcode = args.func(args, config)
    except InvalidArgument as e:
        argparser.error(e.args[0])

    return exitcode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
