"""Plugin modules — anything SIBAT can fire lives here.

A module is a Python file with a ``MODULE`` dict:
    MODULE = {
        "name": "example",
        "title": "Example module",
        "desc": "What it does",
        "risk": "info|low|medium|high",
        "targeted": True,   # takes a specific host/port
    }
and a ``run(guard, target, port=None)`` function returning list[Finding].
Every module MUST call guard.assert_target first — the loader strips
modules that don't.
"""
