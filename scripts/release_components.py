#!/usr/bin/env python3
"""Which artifact belongs to which release track.

The container image used to carry the relay, the admin CLI and the console
together, so shipping one console fix meant releasing the whole server again.
Two components now ship apart:

* ``server`` publishes on ``vMAJOR.MINOR.PATCH``: the relay and the admin CLI.
* ``admin`` publishes on ``admin-vMAJOR.MINOR.PATCH``: the console only.

A release that changes the database schema still ships both, because an older
console refuses to open a newer registry. Everything else ships alone.
"""

from __future__ import annotations

import re

SERVER = "server"
ADMIN = "admin"
COMPONENTS = (SERVER, ADMIN)

IMAGES = {
    SERVER: "sevenmirror-server",
    ADMIN: "sevenmirror-admin",
}
DOCKERFILES = {
    SERVER: "Dockerfile",
    ADMIN: "Dockerfile.admin",
}
ENTRYPOINTS = {
    SERVER: "/app/server",
    ADMIN: "/app/admin-web",
}
COMMANDS = {
    SERVER: ("server", "admin"),
    ADMIN: ("admin-web",),
}
TAG_PREFIXES = {
    SERVER: "v",
    ADMIN: "admin-v",
}

REGISTRY = "ghcr.io/huaxianyan"
SERVER_TAG = re.compile(r"v([0-9]+)\.([0-9]+)\.([0-9]+)")
ADMIN_TAG = re.compile(r"admin-v([0-9]+)\.([0-9]+)\.([0-9]+)")


def require_component(value: str) -> str:
    if value not in COMPONENTS:
        raise RuntimeError(f"unknown release component {value!r}, want one of {COMPONENTS}")
    return value


def image_repository(component: str) -> str:
    return f"{REGISTRY}/{IMAGES[require_component(component)]}"


def component_for_tag(tag: str) -> str:
    """The component a release tag belongs to, or a refusal.

    The admin prefix is checked first: ``admin-v1.0.0`` must not be read as a
    server tag that happens to start with letters.
    """
    if ADMIN_TAG.fullmatch(tag):
        return ADMIN
    if SERVER_TAG.fullmatch(tag):
        return SERVER
    raise RuntimeError(f"release tag {tag!r} is neither vMAJOR.MINOR.PATCH nor admin-vMAJOR.MINOR.PATCH")


def version_for_tag(tag: str) -> str:
    component = component_for_tag(tag)
    return tag[len(TAG_PREFIXES[component]):]
