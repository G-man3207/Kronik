//! Reuses the browser acceptance's real TLS/code/PKCE/JWT provider, not an auth bypass.
//! Uses the prepared Python runtime pinned in scripts/requirements-oidc-tests.txt; no installs.

// A shared test helper carries the browser-acceptance surface; the integration
// test that calls every part of it does not live in this file.
#![allow(dead_code)]

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{Value, json};

const PROVIDER: &str = r#"
import importlib.metadata, json, runpy, signal, socket, ssl, sys, urllib.error, urllib.parse, urllib.request
from pathlib import Path
signal.alarm(180)
if sys.version_info < (3, 11):
    raise SystemExit('OIDC fixture requires prepared Python 3.11+')
for requirement in Path(sys.argv[1]).with_name('requirements-oidc-tests.txt').read_text().splitlines():
    if requirement and not requirement.startswith('#'):
        package, version = requirement.split('==', 1)
        if importlib.metadata.version(package) != version:
            raise SystemExit('Prepare the pinned OIDC test environment from CONTRIBUTING.md')
fixture = runpy.run_path(sys.argv[1], run_name='kronik_owned_oidc_fixture')
root = Path(sys.argv[2])
fixture['tls'](root)
with socket.socket() as reservation:
    reservation.bind(('127.0.0.1', 0))
    port = reservation.getsockname()[1]
origin = sys.argv[3]
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None
with fixture['Provider'](root, port, origin) as provider:
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(root / 'ca.pem'))))
    allowed = {provider.issuer, origin}
    print(json.dumps({'issuer': provider.issuer}), flush=True)
    while True:
        line = sys.stdin.buffer.readline(1048577)
        if not line:
            break
        try:
            if len(line) > 1048576:
                raise ValueError('bounded private request')
            value = json.loads(line)
            url = urllib.parse.urlsplit(value['url'])
            if url.scheme != 'https' or url.username or url.password or url.fragment or url.scheme + '://' + url.netloc not in allowed:
                raise ValueError('unowned endpoint')
            data = value.get('body')
            request = urllib.request.Request(value['url'], data=None if data is None else json.dumps(data).encode(),
                headers=value.get('headers', {}), method=value['method'])
            try:
                response = opener.open(request, timeout=10)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                body = response.read(65537)
                if len(body) > 65536:
                    raise ValueError('bounded private response')
                result = {'status': response.status, 'headers': list(response.headers.raw_items()), 'body': body.decode('utf-8')}
        except Exception as error:
            result = {'fixture_error': type(error).__name__}
        print(json.dumps(result), flush=True)
"#;

pub struct OwnedOidc {
    child: Child,
    input: Option<ChildStdin>,
    output: BufReader<ChildStdout>,
    root: tempfile::TempDir,
    pub issuer: String,
    pub origin: String,
}

pub struct BrowserLogin {
    pub cookie: String,
    pub csrf: String,
    pub principal: String,
}

impl OwnedOidc {
    pub fn start(origin: String) -> Self {
        let root = tempfile::Builder::new()
            .prefix("kronik-oidc-consumer-")
            .tempdir()
            .unwrap();
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let python = std::env::var_os("KRONIK_TEST_PYTHON")
            .expect("set KRONIK_TEST_PYTHON to the private pinned runtime from CONTRIBUTING.md");
        let mut child = Command::new(python)
            .args(["-I", "-u", "-c", PROVIDER])
            .arg(repository.join("scripts/e2e-ui-oidc.py"))
            .arg(root.path())
            .arg(&origin)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("start the prepared KRONIK_TEST_PYTHON from CONTRIBUTING.md");
        let input = child.stdin.take();
        let output = BufReader::new(child.stdout.take().unwrap());
        let mut owned = Self {
            child,
            input,
            output,
            root,
            issuer: String::new(),
            origin,
        };
        let ready = owned.receive();
        owned.issuer = ready["issuer"]
            .as_str()
            .expect("real owned OIDC provider readiness")
            .to_owned();
        owned
    }

    pub fn ca(&self) -> PathBuf {
        self.root.path().join("ca.pem")
    }
    pub fn certificate(&self) -> PathBuf {
        self.root.path().join("server.pem")
    }
    pub fn key(&self) -> PathBuf {
        self.root.path().join("server.key")
    }

    pub fn profile(&self, token: &str) -> Value {
        json!({"issuer": self.issuer, "client_id": "kronik-ui",
            "redirect_uri": format!("{}/v1/auth/callback", self.origin), "ca_file": self.ca(),
            "bindings": [{"subject": "fixture-reviewer", "token": token}]})
    }

    pub fn request(
        &mut self,
        method: &str,
        url: &str,
        headers: Value,
        body: Option<Value>,
    ) -> Value {
        serde_json::to_writer(
            self.input.as_mut().unwrap(),
            &json!({"method": method, "url": url,
            "headers": headers, "body": body}),
        )
        .unwrap();
        let input = self.input.as_mut().unwrap();
        input.write_all(b"\n").unwrap();
        input.flush().unwrap();
        self.receive()
    }

    pub fn login(&mut self) -> BrowserLogin {
        let origin = self.origin.clone();
        let start = self.request("GET", &format!("{origin}/v1/auth/login"), json!({}), None);
        assert_eq!(start["status"], 303);
        let bound = cookie(&start, "__Host-kronik-login");
        let authorize = self.request("GET", &header(&start, "location"), json!({}), None);
        assert_eq!(authorize["status"], 302);
        let callback = self.request(
            "GET",
            &header(&authorize, "location"),
            json!({"Cookie": bound}),
            None,
        );
        assert_eq!(callback["status"], 303);
        let cookie = cookie(&callback, "__Host-kronik-session");
        let info = self.request(
            "GET",
            &format!("{origin}/v1/auth/session"),
            json!({"Cookie": cookie}),
            None,
        );
        assert_eq!(info["status"], 200);
        let info: Value = serde_json::from_str(info["body"].as_str().unwrap()).unwrap();
        BrowserLogin {
            cookie,
            csrf: info["csrf_token"].as_str().unwrap().to_owned(),
            principal: info["principal"].as_str().unwrap().to_owned(),
        }
    }

    fn receive(&mut self) -> Value {
        let mut line = String::new();
        let bytes = self
            .output
            .by_ref()
            .take(1_048_577)
            .read_line(&mut line)
            .unwrap();
        assert!(
            bytes > 0 && bytes <= 1_048_576,
            "bounded owned OIDC response; prepare pinned cryptography/PyJWT from CONTRIBUTING.md"
        );
        let value: Value = serde_json::from_str(&line).expect("owned OIDC fixture response JSON");
        assert!(
            value.get("fixture_error").is_none(),
            "owned OIDC fixture transport failed"
        );
        value
    }
}

impl Drop for OwnedOidc {
    fn drop(&mut self) {
        drop(self.input.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn header(response: &Value, name: &str) -> String {
    response["headers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row[0].as_str().unwrap().eq_ignore_ascii_case(name))
        .unwrap()[1]
        .as_str()
        .unwrap()
        .to_owned()
}

fn cookie(response: &Value, name: &str) -> String {
    response["headers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row[0].as_str().unwrap().eq_ignore_ascii_case("set-cookie"))
        .map(|row| row[1].as_str().unwrap().split(';').next().unwrap())
        .find(|value| value.split_once('=').is_some_and(|(key, _)| key == name))
        .unwrap()
        .to_owned()
}
