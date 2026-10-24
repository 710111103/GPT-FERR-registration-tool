from pathlib import Path


def _index_html():
    return (Path(__file__).resolve().parents[1] / "webui" / "templates" / "index.html").read_text(encoding="utf-8")


def test_oss_protocol_is_available_in_registration_dropdown():
    html = _index_html()
    assert '<option value="oss_protocol">' in html
    for element_id in (
        "ossProtocolFieldsV2",
        "ossEmailSourceV2",
        "ossEmailV2",
        "ossRelayUrlV2",
        "ossProxyV2",
    ):
        assert f'id="{element_id}"' in html


def test_oss_protocol_is_not_duplicated_as_sidebar_link():
    html = _index_html()
    assert 'href="/oss-protocol-register"' not in html
    assert '独立协议注册 ↗' not in html


def test_oss_protocol_is_available_in_settings_registration_driver_dropdown():
    html = _index_html()
    choices = html.split("function registrationDriverChoices()", 1)[1].split("function getRegistrationDriverField()", 1)[0]
    assert "{ value: 'oss_protocol', label: 'OSS 独立协议注册' }" in choices


def test_job_submission_accepts_oss_protocol_driver():
    app_py = (Path(__file__).resolve().parents[1] / "webui" / "app.py").read_text(encoding="utf-8")
    assert '("protocol", "oss_protocol", "ant", "roxy", "cloak", "browser_use", "skyvern")' in app_py


def test_main_registration_dispatch_accepts_oss_protocol_driver():
    main_py = (Path(__file__).resolve().parents[1] / "main.py").read_text(encoding="utf-8")
    assert 'if driver_mode == "oss_protocol":' in main_py
    assert "run_oss_protocol_registration(" in main_py


def test_oss_protocol_uses_its_dedicated_api_and_polling_route():
    html = _index_html()
    assert "driver === 'oss_protocol'" in html
    assert "await startOssProtocolRegistration(startBtn, count, workers)" in html
    assert "api('/api/oss-protocol/register'" in html
    assert "api('/api/oss-protocol/batches/' + encodeURIComponent(batchId))" in html
    assert "api('/api/jobs'" in html


def test_oss_protocol_batch_limits_are_explained_and_applied():
    html = _index_html()
    assert "支持批量注册，单批最多 10 并发" in html
    assert "workers.max = '10'" in html
    assert "count.value = '1'" not in html
    assert "workers.value = '1'" not in html


def test_oss_protocol_status_panel_shows_job_metadata_and_logs():
    html = _index_html()
    assert 'class="oss-job-panel"' in html
    assert '任务 ID：${esc(job.job_id' in html
    assert '阶段：${esc(job.phase' in html
    assert '账号 ID：<b>${esc(job.account_id)' in html
    assert 'class="oss-job-log"' in html
    assert 'job.elapsed_seconds' in html


def test_oss_protocol_status_api_exposes_timeline_and_safe_logs():
    source = (Path(__file__).resolve().parents[1] / "webui" / "oss_protocol_page.py").read_text(encoding="utf-8")
    for field in ("job_id", "phase", "created_at", "started_at", "finished_at", "updated_at", "logs", "elapsed_seconds"):
        assert field in source
    assert "_safe_log" in source
    assert "[邮箱已隐藏]" in source


def test_oss_protocol_polling_retries_transient_fetch_failures():
    html = _index_html()
    assert "retryCount = 0" in html
    assert "nextRetry <= 15" in html
    assert "状态连接暂时中断，正在自动重连" in html
    assert "message.includes('批次不存在')" in html
    assert "pollOssProtocolBatch(batchId, startBtn, nextRetry)" in html


def test_oss_protocol_limits_real_auth_concurrency_to_two():
    source = (
        Path(__file__).resolve().parents[1]
        / "webui"
        / "oss_protocol_page.py"
    ).read_text(encoding="utf-8")
    assert "auth_workers = min(workers, 2)" in source

