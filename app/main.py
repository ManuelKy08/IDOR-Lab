import os
import threading
import webbrowser

PORT = 5097

from . import models as M  # noqa: E402
from . import create_app  # noqa: E402

app = create_app()
M.seed()
M.reset_users()


def post_bind():
    host = os.environ.get('LAB_HOST', '127.0.0.1')
    threading.Timer(0.8, lambda: webbrowser.open(f'http://127.0.0.1:{PORT}')).start()
    print(f'[*] IDOR Lab  →  http://127.0.0.1:{PORT}')
    print(f'[*] flag: {M.FLAG}')
    app.run(host=host, port=PORT, debug=False, use_reloader=False)


if __name__ == '__main__':
    post_bind()