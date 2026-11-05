import uvicorn

from backend.config.settings import settings
from backend.main import app


if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=settings.PORT,
        ssl_certfile=settings.TLS_CERT_FILE,
        ssl_keyfile=settings.TLS_KEY_FILE,
    )
