import os
import tempfile

from app import create_app
from app.database import get_db


def test_dashboard_loads():
    fd, database = tempfile.mkstemp()
    app = create_app({"TESTING": True, "DATABASE": database})
    try:
        response = app.test_client().get("/")
        assert response.status_code == 200
        assert b"NetWatch" in response.data
    finally:
        os.close(fd)
        os.unlink(database)


def test_save_and_clear_inventory_archives_device_records():
    fd, database = tempfile.mkstemp()
    app = create_app({"TESTING": True, "DATABASE": database})
    try:
        with app.app_context():
            db = get_db()
            db.execute("INSERT INTO devices (ip_address, status, created_at) VALUES ('127.0.0.1', 'Up', 'now')")
            db.commit()
        response = app.test_client().post("/inventory/clear", follow_redirects=True)
        assert response.status_code == 200
        with app.app_context():
            assert get_db().execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 0
            assert get_db().execute("SELECT COUNT(*) FROM inventory_archives").fetchone()[0] == 1
    finally:
        os.close(fd)
        os.unlink(database)
