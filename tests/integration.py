"""Runs the real compiled server and real agent runner against disposable local data.
No system service installation, firewall mutation, or production credentials.
"""
import hashlib
import http.cookiejar as cookiejar
import importlib.util
import json
import os
import pathlib
import re
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.request

root = pathlib.Path(__file__).parents[1].resolve()
spec = importlib.util.spec_from_file_location('agent', root / 'agent/agent.py')
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


def run():
    with tempfile.TemporaryDirectory() as directory:
        work = pathlib.Path(directory)
        password = secrets.token_hex(24)
        (work / 'password').write_text(password)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        origin = 'http://127.0.0.1:' + str(port)
        env = {**os.environ, 'LC_PUBLIC_URL': origin, 'LC_LISTEN': '127.0.0.1:' + str(port),
               'LC_ADMIN_PASSWORD_FILE': str(work / 'password'), 'LC_LOCAL_TEST': '1'}
        with open(work / 'server.log', 'w') as log:
            proc = subprocess.Popen([str(root / '.build/lightsail-control')], env=env, cwd=work, stdout=log, stderr=log)
            try:
                http = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookiejar.CookieJar()))
                csrf = ''

                def request(path, data=None):
                    headers = {'Origin': origin, 'Content-Type': 'application/json', 'X-CSRF-Token': csrf}
                    req = urllib.request.Request(origin + path, headers=headers,
                        data=None if data is None else json.dumps(data).encode())
                    with http.open(req, timeout=10) as r:
                        return json.loads(r.read())

                for _ in range(100):
                    if proc.poll() is not None:
                        raise RuntimeError((work / 'server.log').read_text())
                    try:
                        request('/healthz')
                        break
                    except OSError:
                        time.sleep(0.1)
                csrf = request('/api/login', {'username': 'admin', 'password': password})['csrf']
                node = request('/api/nodes', {'name': 'integration-node', 'quota': 10**12})['id']
                script = request('/api/nodes/' + node + '/enrollment', {})['script']
                assert len(script.encode()) < 16384
                enroll = re.search(r'Authorization: Bearer ([a-f0-9]+)', script)[1]
                req = urllib.request.Request(origin + '/enroll', method='POST', headers={'Authorization': 'Bearer ' + enroll})
                with http.open(req, timeout=10) as r:
                    installer = r.read().decode()
                cfg = json.loads(re.search(r"<<'LC_CONFIG'\n(.*?)\nLC_CONFIG", installer, re.S)[1])
                os.environ['LC_LOCAL_TEST'] = '1'
                client = agent.Client(cfg)
                metrics = agent.Metrics(work)
                client.post('/agent/heartbeat', metrics.sample())
                nodes = request('/api/nodes')
                assert nodes[0]['last_seen'] > 0
                assert 'token_hash' not in nodes[0] and 'enroll_hash' not in nodes[0]
                runner = agent.Runner(client, work)
                for script, expected in [("echo 'LC_PROGRESS=40|准备完成'\necho 'LC_LINK=https://example.com/panel'\necho ok\n", 'succeeded'), ('echo failed\nexit 9\n', 'failed')]:
                    j = request('/api/jobs', {'node_id': node, 'title': 'check', 'script': script, 'timeout': 60})
                    job = client.post('/agent/poll', {})['job']
                    assert job['id'] == j['id']
                    assert client.post('/agent/poll', {})['job'] is None
                    runner.run(job)
                    result = request('/api/jobs/' + j['id'])
                    assert result['state'] == expected, result
                    if expected == 'succeeded':
                        assert result['progress'] == 100 and 'https://example.com/panel' in result['links']
                    else:
                        assert result['exit_code'] == 9
                request('/api/nodes/' + node + '/revoke', {})
                try:
                    client.post('/agent/poll', {})
                    raise AssertionError('revoked agent authenticated')
                except urllib.error.HTTPError as e:
                    assert e.code == 401
                assert (work / 'data/metrics.db').exists()
                print('PASS: login, one-use enrollment, real Komari metrics, job claim, real shell execution, progress, links, failure, revocation')
            finally:
                proc.terminate()
                proc.wait(timeout=15)


if __name__ == '__main__': run()
