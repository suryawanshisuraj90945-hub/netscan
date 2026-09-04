import json
import logging
import sys
import uuid
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from sqlmodel import Session, SQLModel, create_engine, select
from sqlmodel.pool import StaticPool

from netscan.config import settings
from netscan.main import JsonFormatter, configure_logging


class TestJsonFormatter:
    """Tests for the JSON log formatter."""

    def test_basic_fields_present(self):
        """Test that basic required fields are present in JSON output."""
        formatter = JsonFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        record.created = datetime.now(timezone.utc).timestamp()

        output = formatter.format(record)
        log_data = json.loads(output)

        assert "timestamp" in log_data
        assert "level" in log_data
        assert "logger" in log_data
        assert "message" in log_data
        assert log_data["level"] == "INFO"
        assert log_data["logger"] == "test.logger"
        assert log_data["message"] == "Test message"

    def test_extra_fields_preserved(self):
        """Test that extra={...} structured fields are preserved in output."""
        formatter = JsonFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        record.created = datetime.now(timezone.utc).timestamp()
        record.scan_job_id = "test-job-id"
        record.subnet_cidr = "10.0.0.0/24"
        record.duration_ms = 1234

        output = formatter.format(record)
        log_data = json.loads(output)

        assert log_data["scan_job_id"] == "test-job-id"
        assert log_data["subnet_cidr"] == "10.0.0.0/24"
        assert log_data["duration_ms"] == 1234

    def test_exception_included(self):
        """Test that exception info is included when present."""
        formatter = JsonFormatter()
        try:
            raise ValueError("test error")
        except ValueError:
            exc_info = sys.exc_info()

        record = logging.LogRecord(
            name="test.logger",
            level=logging.ERROR,
            pathname="test.py",
            lineno=10,
            msg="Error occurred",
            args=(),
            exc_info=exc_info,
        )
        record.created = datetime.now(timezone.utc).timestamp()

        output = formatter.format(record)
        log_data = json.loads(output)

        assert "exception" in log_data
        assert "ValueError" in log_data["exception"]
        assert "test error" in log_data["exception"]

    def test_non_serializable_extra_converted_to_string(self):
        """Test that non-JSON-serializable extra fields are converted to strings."""
        formatter = JsonFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        record.created = datetime.now(timezone.utc).timestamp()
        record.custom_object = object()

        output = formatter.format(record)
        log_data = json.loads(output)

        assert "custom_object" in log_data
        assert isinstance(log_data["custom_object"], str)


class TestConfigureLogging:
    """Tests for logging configuration."""

    def test_json_formatter_used_when_debug_false(self):
        """Test that JSON formatter is used when DEBUG=False."""
        with patch.object(settings, "DEBUG", False):
            formatter = JsonFormatter()
            record = logging.LogRecord(
                name="test.logger",
                level=logging.INFO,
                pathname="test.py",
                lineno=10,
                msg="Test message",
                args=(),
                exc_info=None,
            )
            record.created = datetime.now(timezone.utc).timestamp()
            output = formatter.format(record)
            log_data = json.loads(output)
            assert "timestamp" in log_data
            assert "level" in log_data

    def test_human_readable_formatter_used_when_debug_true(self):
        """Test that human-readable formatter is used when DEBUG=True."""
        with patch.object(settings, "DEBUG", True):
            formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
            record = logging.LogRecord(
                name="test.logger",
                level=logging.INFO,
                pathname="test.py",
                lineno=10,
                msg="Test message",
                args=(),
                exc_info=None,
            )
            record.created = datetime.now(timezone.utc).timestamp()
            output = formatter.format(record)
            assert "INFO" in output
            assert "test.logger" in output
            assert "Test message" in output


class TestSchedulerLogging:
    """Tests for scheduler structured logging."""

    @pytest.fixture
    def db_engine(self):
        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        SQLModel.metadata.create_all(engine)
        yield engine
        engine.dispose()

    def test_scheduled_scan_configured_logged_with_structured_fields(self, db_engine, caplog):
        """Test that scheduled scan configuration is logged with structured fields."""
        from netscan.models import Subnet
        from netscan.services.scheduler_service import ScanScheduler

        subnet_id = uuid.uuid4()
        subnet_cidr = "10.0.3.0/29"
        interval_minutes = 30
        with Session(db_engine) as session:
            subnet = Subnet(
                id=subnet_id,
                cidr=subnet_cidr,
                name="SchedTest",
                is_active=True,
                scan_interval_minutes=interval_minutes,
            )
            session.add(subnet)
            session.commit()

            with caplog.at_level(logging.INFO):
                sched = ScanScheduler()
                sched.update_subnet_job(subnet)
                sched.shutdown()

        config_logs = [r for r in caplog.records if r.message == "Scheduled scan configured"]
        assert len(config_logs) == 1
        config_log = config_logs[0]
        assert hasattr(config_log, "subnet_id")
        assert hasattr(config_log, "subnet_cidr")
        assert hasattr(config_log, "interval_minutes")
        assert config_log.subnet_cidr == subnet_cidr
        assert config_log.interval_minutes == interval_minutes