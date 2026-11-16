from app import create_app
from app.monitoring import start_monitoring

app = create_app()

if __name__ == "__main__":
    start_monitoring(app)
    app.run(host="127.0.0.1", port=5000, debug=False)
