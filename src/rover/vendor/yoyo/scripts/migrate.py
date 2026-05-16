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
import re

from yoyo import ancestors, default_migration_table, descendants, read_migrations
from yoyo.scripts.main import InvalidArgument, get_backend


def install_argparsers(global_parser, subparsers):
    # Standard options shared by the apply sub-command
    standard_options_parser = argparse.ArgumentParser(add_help=False)
    standard_options_parser.add_argument(
        "sources", nargs="*", help="Source directory of migration scripts"
    )
    standard_options_parser.add_argument(
        "-d",
        "--database",
        default=None,
        help="Database, eg 'postgresql+psycopg://user@host/db'",
    )
    standard_options_parser.add_argument(
        "--migration-table",
        dest="migration_table",
        action="store",
        default=default_migration_table,
        help="Name of table to use for storing migration metadata",
    )

    # Filtering options
    filter_parser = argparse.ArgumentParser(add_help=False)
    filter_parser.add_argument(
        "-m",
        "--match",
        help="Select migrations matching PATTERN (regular expression)",
        metavar="PATTERN",
    )
    filter_parser.add_argument(
        "-r",
        "--revision",
        help="Apply migration with id REVISION and all its dependencies",
        metavar="REVISION",
    )

    # Apply-specific options
    apply_parser = argparse.ArgumentParser(add_help=False, parents=[filter_parser])
    apply_parser.add_argument(
        "-a",
        "--all",
        dest="all",
        action="store_true",
        help="Select all migrations, regardless of whether they have been previously applied",
    )
    apply_parser.add_argument(
        "-f",
        "--force",
        dest="force",
        action="store_true",
        help="Force apply of steps even if previous steps have failed",
    )

    parser_apply = subparsers.add_parser(
        "apply",
        help="Apply migrations",
        parents=[global_parser, standard_options_parser, apply_parser],
    )
    parser_apply.set_defaults(func=apply, command_name="apply")


def filter_migrations(migrations, pattern):
    if not pattern:
        return migrations

    search = re.compile(pattern).search
    return migrations.filter(lambda m: search(m.id) is not None)


def migrations_to_revision(migrations, revision, direction):
    if not revision:
        return migrations
    assert direction in {"apply", "rollback"}

    targets = [m for m in migrations if revision in m.id]
    if len(targets) == 0:
        raise InvalidArgument("'{}' doesn't match any revisions.".format(revision))
    if len(targets) > 1:
        raise InvalidArgument(
            "'{}' matches multiple revisions. Please specify one of {}.".format(
                revision, ", ".join(m.id for m in targets)
            )
        )

    target = targets[0]

    if direction == "apply":
        deps = ancestors(target, migrations)
        target_plus_deps = deps | {target}
        migrations = migrations.filter(lambda m: m in target_plus_deps)
    else:
        deps = descendants(target, migrations)
        target_plus_deps = deps | {target}
        migrations = migrations.filter(lambda m: m in target_plus_deps)

    return migrations


def get_migrations(args, backend):
    sources = args.sources

    if not sources:
        raise InvalidArgument("Please specify the migration source directory")

    migrations = read_migrations(*sources)
    migrations = filter_migrations(migrations, args.match)
    migrations = migrations_to_revision(migrations, args.revision, "apply")
    migrations = backend.to_apply(migrations)
    return migrations


def apply(args, config) -> int:
    backend = get_backend(args, config)
    with backend.lock():
        migrations = get_migrations(args, backend)
        backend.apply_migrations(migrations, args.force)
    return 0
