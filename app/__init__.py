import os
from pathlib import Path

from flask import Flask

from .database import init_app as init_database
from .routes import web


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("NETWATCH_SECRET_KEY", "dev-only-change-me"),
        DATABASE=str(Path(app.instance_path) / "netwatch.sqlite"),
        MONITOR_INTERVAL_SECONDS=60,
        DOWN_FAILURE_THRESHOLD=2,
        HIGH_LATENCY_THRESHOLD_MS=150,
        PACKET_LOSS_THRESHOLD_PCT=25,
    )
    if test_config:
        app.config.update(test_config)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    init_database(app)
    app.register_blueprint(web)
    return app
