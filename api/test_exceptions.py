"""Tests for the shared API exception classes."""

from django.test import SimpleTestCase
from rest_framework import status

from api.exceptions import APIError, BusinessRuleViolation, Conflict


class APIExceptionTestCase(SimpleTestCase):
    def test_api_error_defaults_to_safe_internal_server_error(self):
        error = APIError()

        self.assertEqual(error.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertEqual(str(error.detail), "服务器内部错误")
        self.assertEqual(error.get_codes(), "server.internal_error")

    def test_business_rule_violation_accepts_feature_code(self):
        error = BusinessRuleViolation(
            "签到尚未开放",
            code="activity.checkin_not_open",
        )

        self.assertEqual(error.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(str(error.detail), "签到尚未开放")
        self.assertEqual(error.get_codes(), "activity.checkin_not_open")

    def test_conflict_has_contract_defaults(self):
        error = Conflict()

        self.assertEqual(error.status_code, status.HTTP_409_CONFLICT)
        self.assertEqual(str(error.detail), "资源状态发生冲突")
        self.assertEqual(error.get_codes(), "resource.conflict")
