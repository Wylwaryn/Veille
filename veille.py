import argparse
import base64
import hmac
import html
import os
import re
import tempfile
from email.parser import BytesParser
from email.policy import default
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, urlsplit
from uuid import uuid4


MAX_UPLOAD_BYTES = 20 * 1024 * 1024
FILE_ID = re.compile(r"^[0-9a-f]{32}$")


class VeilleHandler(BaseHTTPRequestHandler):
    password = ""
    storage_dir = Path("documents")

    def _authorized(self):
        credentials = base64.b64encode(f"veille:{self.password}".encode()).decode()
        expected = f"Basic {credentials}"
        if hmac.compare_digest(self.headers.get("Authorization", ""), expected):
            return True
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Veille", charset="UTF-8"')
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        return False

    def _send_html(self, content, status=200):
        body = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path != "/" and not path.startswith("/files/"):
            self.send_error(404)
            return
        if not self._authorized():
            return

        if path == "/":
            files = sorted(
                (
                    file
                    for file in self.storage_dir.iterdir()
                    if file.is_file() and not file.is_symlink()
                ),
                key=lambda file: file.stat().st_mtime,
                reverse=True,
            )
            links = "".join(
                f'<li><a href="/files/{file.name.split("_", 1)[0]}">'
                f"{html.escape(file.name.split('_', 1)[1])}</a></li>"
                for file in files
                if FILE_ID.fullmatch(file.name.split("_", 1)[0])
                and file.name.lower().endswith(".pdf")
                and "_" in file.name
            )
            self._send_html(
                "<!doctype html><html lang=\"fr\"><meta charset=\"utf-8\">"
                "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
                "<title>Veille — documents</title><h1>Documents PDF</h1>"
                "<form action=\"/upload\" method=\"post\" enctype=\"multipart/form-data\">"
                '<label>Déposer un PDF <input type="file" name="file" accept=".pdf,application/pdf" required></label>'
                '<button type="submit">Envoyer</button></form><ul>'
                f"{links}</ul></html>"
            )
            return

        file_id = path.removeprefix("/files/")
        if not FILE_ID.fullmatch(file_id):
            self.send_error(404)
            return
        file = next(
            (
                candidate
                for candidate in self.storage_dir.glob(f"{file_id}_*.pdf")
                if candidate.is_file() and not candidate.is_symlink()
            ),
            None,
        )
        if file is None:
            self.send_error(404)
            return
        data = file.read_bytes()
        filename = file.name.split("_", 1)[1]
        self.send_response(200)
        self.send_header("Content-Type", "application/pdf")
        self.send_header("Content-Length", str(len(data)))
        self.send_header(
            "Content-Disposition",
            f"attachment; filename*=UTF-8''{quote(filename, safe='')}",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if urlsplit(self.path).path != "/upload":
            self.send_error(404)
            return
        if not self._authorized():
            return
        try:
            content_length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self.send_error(400, "Content-Length invalide")
            return
        if content_length <= 0 or content_length > MAX_UPLOAD_BYTES:
            self.send_error(413, "Fichier trop volumineux")
            return

        content_type = self.headers.get("Content-Type", "")
        if not content_type.lower().startswith("multipart/form-data;"):
            self.send_error(400, "Format de formulaire invalide")
            return
        try:
            headers = (
                f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n"
            ).encode("ascii")
            message = BytesParser(policy=default).parsebytes(
                headers + self.rfile.read(content_length)
            )
        except (UnicodeEncodeError, ValueError):
            self.send_error(400, "Formulaire invalide")
            return
        if not message.is_multipart():
            self.send_error(400, "Formulaire invalide")
            return

        upload = next(
            (
                part
                for part in message.iter_parts()
                if part.get_param("name", header="content-disposition") == "file"
                and part.get_filename()
            ),
            None,
        )
        if upload is None:
            self.send_error(400, "Aucun fichier fourni")
            return
        filename = upload.get_filename().replace("\\", "/").rsplit("/", 1)[-1]
        filename = "".join(
            char for char in filename if ord(char) >= 32 and ord(char) != 127
        ).strip(" .")
        if not filename.lower().endswith(".pdf"):
            self.send_error(400, "Seuls les fichiers PDF sont acceptés")
            return
        name = filename[:-4].strip(" .")[:140].strip()
        filename = f"{name or 'document'}.pdf"
        data = upload.get_payload(decode=True)
        if not data or not data.startswith(b"%PDF-"):
            self.send_error(400, "Le fichier n'est pas un PDF valide")
            return

        self.storage_dir.mkdir(parents=True, exist_ok=True)
        destination = self.storage_dir / f"{uuid4().hex}_{filename}"
        temporary_path = None
        try:
            with tempfile.NamedTemporaryFile(
                dir=self.storage_dir, prefix=".upload-", delete=False
            ) as temporary:
                temporary_path = Path(temporary.name)
                temporary.write(data)
            os.replace(temporary_path, destination)
        except OSError:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
            self.send_error(500, "Impossible d'enregistrer le fichier")
            return
        self.send_response(303)
        self.send_header("Location", "/")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()


def main():
    parser = argparse.ArgumentParser(description="Partage privé de fichiers PDF.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument(
        "--storage",
        type=Path,
        default=Path(os.environ.get("VEILLE_STORAGE_DIR", "documents")),
    )
    args = parser.parse_args()
    password = os.environ.get("VEILLE_PASSWORD")
    if not password:
        parser.error("définissez VEILLE_PASSWORD avant de démarrer le serveur")
    args.storage.mkdir(parents=True, exist_ok=True)
    handler = type(
        "ConfiguredVeilleHandler",
        (VeilleHandler,),
        {"password": password, "storage_dir": args.storage},
    )
    server = ThreadingHTTPServer((args.host, args.port), handler)
    print(f"Veille écoute sur http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
