"""Validation entry, including authentication and authorization

Author: buyiihoo
"""

from functools import wraps

from flask import _request_ctx_stack
from flask_jwt import current_identity, jwt_required
from werkzeug.local import LocalProxy

from .constants import AuthResourcesType as RT
from .elements import Entity, ResourceGroup, Rule

current_auth = LocalProxy(lambda: getattr(_request_ctx_stack.top, "current_auth", None))


class AuthError(Exception):
    pass


def auth_check(auth_name=None, filters=None, **kwargs):
    """This is a decorator for baisc auth related actions, including
    registering, calculating If a endpoint is used multiple times, considering
    creating one or more copies."""

    def _check_auth(auth_entity):
        def wrapper(fn):
            @wraps(fn)
            def decorator(*args, **kwargs):
                flag, auth_value = calculate(auth_entity)
                if flag:
                    _request_ctx_stack.top.current_auth = auth_value
                    return fn(*args, **kwargs)
                else:
                    raise AuthError("Not authorized")

            return decorator

        return wrapper

    def wrapper(fn):
        nonlocal auth_name
        if auth_name is None:
            _name = fn.__qualname__.split(".")
            auth_name = ".".join([fn.__module__, _name[0], _name[1].upper()])
        auth_entity = Entity(auth_name, selects=filters)
        auth.add_entity(auth_entity)
        if filters:
            for ent in filters:
                ent.qual_name = (
                    ent.parent.qual_name if ent.type == RT.DATA_FILTER else auth_name
                ) + ent.name
            auth.add_entities(filters)
        jwt_realm = kwargs.pop("realm", None)
        return jwt_required(realm=jwt_realm)(_check_auth(auth_entity)(fn))

    return wrapper


def calculate(checkpoint: Entity):
    if is_special(current_identity):
        return True, {}
    auth.check_version(current_identity)
    with auth.access_permisson:
        rules = Rule.get_all()
        attributes = current_identity.attributes
        result = ResourceGroup(int_value=0)
        for rule in rules:
            res = attributes * rule
            if not res:
                continue
            result = res and result + res or result
    return result.load_resource(checkpoint)


def is_special(identity):
    return identity.feature == identity.Feature.SUPER_ADMIN
