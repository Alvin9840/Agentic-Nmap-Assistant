"""Unit tests for the Nmap subprocess executor."""

import asyncio

import pytest

from safe_nmap.server import scanner


@pytest.fixture(autouse=True)
def _clear_executable_cache():
    scanner._resolve_nmap_executable.cache_clear()
    yield
    scanner._resolve_nmap_executable.cache_clear()


class _FakeProcess:
    """Minimal stand-in for ``asyncio.subprocess.Process``."""

    def __init__(self, stdout=b"", stderr=b"", returncode=None, hang=False):
        self.returncode = returncode
        self._stdout = stdout
        self._stderr = stderr
        self._hang = hang
        self.terminated = False
        self.killed = False

    async def communicate(self):
        if self._hang:
            await asyncio.sleep(10)
        return self._stdout, self._stderr

    def terminate(self):
        self.terminated = True
        self._hang = False
        self.returncode = -15

    def kill(self):
        self.killed = True
        self._hang = False
        self.returncode = -9


async def test_run_nmap_success_returns_xml_output(monkeypatch):
    monkeypatch.setattr(scanner.shutil, "which", lambda name: "/usr/bin/nmap")

    async def fake_create_subprocess_exec(*args, **kwargs):
        return _FakeProcess(stdout=b"<nmaprun></nmaprun>", returncode=0)

    monkeypatch.setattr(scanner.asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    execution = await scanner.run_nmap(["nmap", "-sT", "127.0.0.1"], timeout_seconds=5)
    assert execution.nmap_started is True
    assert execution.xml_output == "<nmaprun></nmaprun>"
    assert execution.error_message is None


async def test_run_nmap_nonzero_exit_reports_detail_and_no_xml(monkeypatch):
    monkeypatch.setattr(scanner.shutil, "which", lambda name: "/usr/bin/nmap")

    async def fake_create_subprocess_exec(*args, **kwargs):
        return _FakeProcess(stderr=b"nmap: permission denied", returncode=1)

    monkeypatch.setattr(scanner.asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    execution = await scanner.run_nmap(["nmap", "-sT", "127.0.0.1"], timeout_seconds=5)
    assert execution.nmap_started is True
    assert execution.xml_output is None
    assert "permission denied" in execution.error_message


async def test_run_nmap_missing_executable_does_not_start_process(monkeypatch):
    monkeypatch.setattr(scanner.shutil, "which", lambda name: None)

    async def fail_if_called(*args, **kwargs):
        raise AssertionError("subprocess should not be started when nmap is missing")

    monkeypatch.setattr(scanner.asyncio, "create_subprocess_exec", fail_if_called)

    execution = await scanner.run_nmap(["nmap", "-sT", "127.0.0.1"], timeout_seconds=5)
    assert execution.nmap_started is False
    assert execution.xml_output is None
    assert "not found" in execution.error_message.lower()


async def test_run_nmap_timeout_terminates_process_and_reports_error(monkeypatch):
    monkeypatch.setattr(scanner.shutil, "which", lambda name: "/usr/bin/nmap")
    process = _FakeProcess(hang=True)

    async def fake_create_subprocess_exec(*args, **kwargs):
        return process

    monkeypatch.setattr(scanner.asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    execution = await scanner.run_nmap(["nmap", "-sT", "127.0.0.1"], timeout_seconds=0.05)
    assert execution.nmap_started is True
    assert execution.xml_output is None
    assert "timed out" in execution.error_message.lower()
    assert process.terminated is True


async def test_run_nmap_cancellation_terminates_process_and_propagates(monkeypatch):
    monkeypatch.setattr(scanner.shutil, "which", lambda name: "/usr/bin/nmap")
    process = _FakeProcess(hang=True)

    async def fake_create_subprocess_exec(*args, **kwargs):
        return process

    monkeypatch.setattr(scanner.asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    task = asyncio.ensure_future(
        scanner.run_nmap(["nmap", "-sT", "127.0.0.1"], timeout_seconds=30)
    )
    await asyncio.sleep(0.05)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task

    assert process.terminated is True


async def test_run_nmap_rejects_zero_timeout():
    with pytest.raises(ValueError):
        await scanner.run_nmap(["nmap"], timeout_seconds=0)


async def test_run_nmap_rejects_empty_arguments():
    with pytest.raises(ValueError):
        await scanner.run_nmap([], timeout_seconds=5)
