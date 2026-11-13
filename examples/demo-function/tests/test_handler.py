"""DEMO ONLY: shows that tests/ is left out of the deployment package."""

from unittest import mock

import handler


def test_handler_returns_status():
    with mock.patch("handler.requests.get", return_value=mock.Mock(status_code=204)):
        result = handler.handler({"url": "https://example.com"}, None)
    assert result["statusCode"] == 200
