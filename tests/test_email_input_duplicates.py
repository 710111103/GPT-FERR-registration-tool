from types import SimpleNamespace
from unittest.mock import MagicMock
from core.roxy_registration import _find_visible_email_input_js

def test_hidden_first_email_input_does_not_mask_visible_second():
    hidden=MagicMock(); hidden.is_visible.return_value=False
    visible=MagicMock(); visible.is_visible.return_value=True
    visible.is_enabled.return_value=True; visible.is_editable.return_value=True
    group=MagicMock(); group.count.return_value=2; group.nth.side_effect=lambda i: [hidden,visible][i]
    page=MagicMock(); page.locator.return_value=group
    driver=SimpleNamespace(page=page,execute_script=MagicMock(return_value=None))
    assert _find_visible_email_input_js(driver) is not None
    visible.is_editable.assert_called_once()
    driver.execute_script.assert_not_called()

def test_readonly_input_is_not_selected():
    field=MagicMock(); field.is_visible.return_value=True
    field.is_enabled.return_value=True;field.is_editable.return_value=False
    group=MagicMock(); group.count.return_value=1;group.nth.return_value=field
    page=MagicMock();page.locator.return_value=group
    driver=SimpleNamespace(page=page,execute_script=MagicMock(return_value=None))
    assert _find_visible_email_input_js(driver) is None
