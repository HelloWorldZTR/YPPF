"""Shared exceptions for ``/api/`` response contract."""

from rest_framework import status
from rest_framework.exceptions import APIException


__all__ = [
    "APIError",
    "BusinessRuleViolation",
    "Conflict",
]


class APIError(APIException):
    """Base class for non-field API failures with a stable error code.

    Pass a feature-specific dotted ``code`` whenever the client may branch on
    the failure reason. The shared exception handler is responsible for
    rendering the exception as the documented ``code``/``message``/``errors``
    response body.
    """

    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = "服务器内部错误"
    default_code = "server.internal_error"


class BusinessRuleViolation(APIError):
    """An ordinary business precondition rejected the request."""

    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = "当前操作不满足业务条件"
    default_code = "business.rule_violation"


class Conflict(APIError):
    """The request conflicts with the current or concurrently changed state."""

    status_code = status.HTTP_409_CONFLICT
    default_detail = "资源状态发生冲突"
    default_code = "resource.conflict"
