import base64
import http.client
import tempfile
import threading
import unittest
from pathlib import Path
from http.server import ThreadingHTTPServer

from veille import VeilleHandler


PDF = b"%PDF-1.4\nexample\n"


class VeilleTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        handler = type(
            "TestVeilleHandler",
            (VeilleHandler,),
            {
                "password": "test-secret",
                "storage_dir": Path(self.temp_dir.name),
            },
        )
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.connection = http.client.HTTPConnection(
            "127.0.0.1", self.server.server_port
        )
        token = base64.b64encode(b"veille:test-secret").decode()
        self.auth = {"Authorization": f"Basic {token}"}

    def tearDown(self):
        self.connection.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temp_dir.cleanup()

    def _upload(self, filename, data):
        boundary = "test-boundary"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            "Content-Type: application/pdf\r\n\r\n"
        ).encode() + data + f"\r\n--{boundary}--\r\n".encode()
        headers = {
            **self.auth,
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Content-Length": str(len(body)),
        }
        self.connection.request("POST", "/upload", body, headers)
        return self.connection.getresponse()

    def test_upload_lists_and_downloads_pdf(self):
        response = self._upload("../../rapport.pdf", PDF)
        self.assertEqual(response.status, 303)
        response.read()

        self.connection.request("GET", "/", headers=self.auth)
        response = self.connection.getresponse()
        page = response.read().decode()
        self.assertEqual(response.status, 200)
        self.assertIn("rapport.pdf", page)
        file_id = page.split("/files/", 1)[1].split('"', 1)[0]

        self.connection.request("GET", f"/files/{file_id}", headers=self.auth)
        response = self.connection.getresponse()
        self.assertEqual(response.status, 200)
        self.assertEqual(response.read(), PDF)
        self.assertIn("application/pdf", response.getheader("Content-Type"))

    def test_upload_rejects_non_pdf_content(self):
        response = self._upload("notes.pdf", b"not a PDF")
        self.assertEqual(response.status, 400)
        response.read()
        self.assertEqual(list(Path(self.temp_dir.name).iterdir()), [])

    def test_upload_requires_authentication(self):
        self.connection.request("GET", "/")
        response = self.connection.getresponse()
        self.assertEqual(response.status, 401)
        self.assertIn("Basic", response.getheader("WWW-Authenticate"))
        response.read()

    def test_upload_rejects_malformed_multipart_form(self):
        body = b"not a multipart form"
        self.connection.request(
            "POST",
            "/upload",
            body,
            {
                **self.auth,
                "Content-Type": "multipart/form-data; boundary=missing",
                "Content-Length": str(len(body)),
            },
        )
        response = self.connection.getresponse()
        self.assertEqual(response.status, 400)
        response.read()


if __name__ == "__main__":
    unittest.main()
