# Originally yoyo-migrations by Oliver Cope (Apache License 2.0).
# Modified for ROVER as the shipship migration sub-module.

DatabaseErrors = []


def register(exception_class):
    DatabaseErrors.append(exception_class)


class BadMigration(Exception):
    """
    The migration file could not be compiled
    """


class MigrationConflict(Exception):
    """
    The migration id conflicts with another migration
    """


class LockTimeout(Exception):
    """
    Timeout was reached while acquiring the migration lock
    """
