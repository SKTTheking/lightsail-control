#!/usr/bin/env python3
"""Visible, opt-in Linux agent for Lightsail Control. Python standard library only.

No inbound listener, SSH changes, self update, third-party telemetry or detached jobs.
Monthly counters and the execution journal MUST survive service/server restarts.
"""
import codecs
import datetime as dt
import fcntl
import hashlib
import json
import os
import pathlib
import platform
import re
import selectors
import signal
import socket
import subprocess
import tempfile
import threading
import time
import urllib.request
import urllib.parse


def atomic_json(path, data):
    path = pathlib.Path(path)
    fd, tmp = tempfile.mkstemp(prefix='.lc-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(data, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def read_json(path, default):
    try:
        return json.loads(pathlib.Path(path).read_text())
    except FileNotFoundError:
        return default
    # Corrupt state must fail closed, never silently reset counters/journal.


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError('Control center redirects are not allowed')


class Client:
    def __init__(self, config):
        self.endpoint = config['endpoint'].rstrip('/')
        u = urllib.parse.urlparse(self.endpoint)
        local = os.getenv('LC_LOCAL_TEST') == '1' and u.hostname in ('127.0.0.1', 'localhost')
        if (u.scheme != 'https' and not local) or u.path or u.query or u.fragment or u.username:
            raise ValueError('An HTTPS origin is required')
        self.token = config['token']
        # Do not inherit third-party HTTP proxies carrying privileged credentials.
        self.http = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def post(self, path, data):
        req = urllib.request.Request(self.endpoint + path,
            data=json.dumps(data).encode(), method='POST',
            headers={'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json'})
        with self.http.open(req, timeout=10) as response:
            return json.loads(response.read(262144))


def network_counters():
    # Default-route interfaces only: excludes lo, Docker bridges, veth and tunnels.
    names = set()
    for line in pathlib.Path('/proc/net/route').read_text().splitlines()[1:]:
        parts = line.split()
        if len(parts) > 3 and parts[1] == '00000000' and int(parts[3], 16) & 1:
            names.add(parts[0])
    try:
        for line in pathlib.Path('/proc/net/ipv6_route').read_text().splitlines():
            p = line.split()
            if p[0] == '0' * 32 and p[1] == '00' and p[-1] != 'lo':
                names.add(p[-1])
    except FileNotFoundError:
        pass
    counters = {}
    for name in names:
        base = pathlib.Path('/sys/class/net') / name / 'statistics'
        try:
            counters[name] = [int((base / 'tx_bytes').read_text()), int((base / 'rx_bytes').read_text())]
        except FileNotFoundError:
            continue
    return counters


def update_traffic(state, counters, boot, month):
    """Count deltas, rebases on reboot/reset; first contact excludes prior traffic.

    A boundary-crossing sample is assigned to the new UTC month. This is an estimate.
    """
    previous = state.get('counters', {})
    first = not state
    same_boot = state.get('boot') == boot
    up = state.get('up', 0) if state.get('month') == month else 0
    down = state.get('down', 0) if state.get('month') == month else 0
    delta = [0, 0]
    for name, pair in counters.items():
        for i in (0, 1):
            if first or (same_boot and name not in previous):
                d = 0
            elif same_boot and pair[i] >= previous.get(name, [0, 0])[i]:
                d = pair[i] - previous[name][i]
            else:
                d = pair[i]
            delta[i] += d
    return dict(month=month, up=up + delta[0], down=down + delta[1],
                counters=counters, boot=boot, seq=state.get('seq', 0) + 1), delta


class Metrics:
    def __init__(self, directory):
        self.path = pathlib.Path(directory) / 'traffic.json'
        self.state = read_json(self.path, {})
        self.boot = pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        self.previous_cpu = None
        self.previous_time = time.monotonic()
        self.ip = self.public_ip()

    @staticmethod
    def public_ip():
        # AWS IMDSv2 only; no external IP lookup service. Failure falls back to local IP.
        http = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        base = 'http://169.254.169.254/latest/'
        try:
            req = urllib.request.Request(base + 'api/token', method='PUT',
                headers={'X-aws-ec2-metadata-token-ttl-seconds': '60'})
            with http.open(req, timeout=1) as r:
                tok = r.read(4096).decode()
            req = urllib.request.Request(base + 'meta-data/public-ipv4',
                headers={'X-aws-ec2-metadata-token': tok})
            with http.open(req, timeout=1) as r:
                return r.read(100).decode().strip()
        except Exception:
            try:
                return socket.gethostbyname(socket.gethostname())
            except OSError:
                return ''

    def sample(self):
        month = dt.datetime.now(dt.timezone.utc).strftime('%Y-%m')
        self.state, delta = update_traffic(self.state, network_counters(), self.boot, month)
        atomic_json(self.path, self.state)
        cpu = [int(x) for x in pathlib.Path('/proc/stat').read_text().splitlines()[0].split()[1:9]]
        total, idle = sum(cpu), cpu[3] + cpu[4]
        usage = 0
        if self.previous_cpu and total > self.previous_cpu[0]:
            usage = 100 * (1 - (idle - self.previous_cpu[1]) / (total - self.previous_cpu[0]))
        self.previous_cpu = total, idle
        mem = {}
        for line in pathlib.Path('/proc/meminfo').read_text().splitlines():
            k, v = line.split(':', 1)
            mem[k] = int(v.strip().split()[0]) * 1024
        disk = os.statvfs('/')
        elapsed = max(1, time.monotonic() - self.previous_time)
        self.previous_time = time.monotonic()
        load = os.getloadavg()
        report = dict(cpu=dict(usage=max(0, min(100, usage)), cores=os.cpu_count() or 1,
                               arch=platform.machine()),
            ram=dict(total=mem['MemTotal'], used=mem['MemTotal'] - mem.get('MemAvailable', mem['MemFree'])),
            swap=dict(total=mem['SwapTotal'], used=mem['SwapTotal'] - mem['SwapFree']),
            load=dict(load1=load[0], load5=load[1], load15=load[2]),
            disk=dict(total=disk.f_blocks * disk.f_frsize, used=(disk.f_blocks - disk.f_bfree) * disk.f_frsize),
            network=dict(up=int(delta[0] / elapsed), down=int(delta[1] / elapsed),
                         totalUp=self.state['up'], totalDown=self.state['down']),
            uptime=int(float(pathlib.Path('/proc/uptime').read_text().split()[0])),
            process=sum(1 for p in pathlib.Path('/proc').iterdir() if p.name.isdigit()),
            connections=dict(tcp=0, udp=0))
        report['message'] = self.ip
        return dict(report=report, os=platform.system() + ' ' + platform.release(),
                    arch=platform.machine(), ip=self.ip, boot=self.boot,
                    **{k: self.state[k] for k in ('month', 'up', 'down', 'seq')})


def allowed_link(value):
    if len(value) > 8192 or any(c in value for c in '\r\n\0'):
        return False
    try:
        u = urllib.parse.urlparse(value)
        return u.scheme in ('http', 'https', 'vless', 'vmess', 'ss', 'trojan') and bool(u.netloc)
    except ValueError:
        return False


class Runner:
    def __init__(self, client, directory):
        self.client = client
        self.directory = pathlib.Path(directory)
        self.journal = self.directory / 'job.json'

    def send(self, job_id, event, seconds=45):
        # Retry the exact sequence number. The server deduplicates accepted events.
        deadline = time.monotonic() + seconds
        while True:
            try:
                return self.client.post('/agent/jobs/' + job_id + '/events', event)
            except Exception:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(1)

    def recover(self):
        saved = read_json(self.journal, None)
        if saved:
            # Never rerun a script after a crash, ambiguous delivery or agent restart.
            event = saved.get('pending')
            if event:
                result = self.send(saved['id'], event)
                if result.get('stop'):
                    self.journal.unlink(missing_ok=True)
                    return
            seq = saved['seq'] + 1
            self.send(saved['id'], dict(seq=seq, state='interrupted', log='\nAgent restarted; execution was not replayed.\n'))
            self.journal.unlink(missing_ok=True)

    @staticmethod
    def kill(proc):
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=10)

    def run(self, job):
        jid = job['id']
        if not re.fullmatch(r'[0-9a-f-]{36}', jid):
            raise ValueError('invalid job id')
        if hashlib.sha256(job['script'].encode()).hexdigest() != job['sha256']:
            raise ValueError('script digest mismatch')
        timeout = int(job['timeout'])
        if not 60 <= timeout <= 7200:
            raise ValueError('invalid timeout')
        seq = 1
        start = dict(seq=seq, state='running', step='开始执行', log='')
        atomic_json(self.journal, dict(id=jid, seq=seq, pending=start))
        response = self.send(jid, start)
        if response.get('stop'):
            self.journal.unlink(missing_ok=True)
            return
        atomic_json(self.journal, dict(id=jid, seq=seq))
        with tempfile.TemporaryDirectory(prefix='job-', dir=self.directory) as work:
            script = pathlib.Path(work) / 'install.sh'
            script.write_text(job['script'])
            os.chmod(script, 0o600)
            # No control-center bearer tokens are passed in the child environment.
            env = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                   'HOME': '/root', 'LANG': 'C.UTF-8', 'DEBIAN_FRONTEND': 'noninteractive',
                   'PYTHONUNBUFFERED': '1'}
            proc = subprocess.Popen(['/bin/bash', str(script)], cwd=work, env=env,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                start_new_session=True)
            selector = selectors.DefaultSelector()
            selector.register(proc.stdout, selectors.EVENT_READ)
            decoder = codecs.getincrementaldecoder('utf-8')('replace')
            started = last_send = time.monotonic()
            log_buffer, line_buffer, links = '', '', []
            progress, step, final = 0, '正在执行', None
            try:
                while True:
                    for key, _ in selector.select(timeout=0.2):
                        chunk = os.read(key.fileobj.fileno(), 8192)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        text = decoder.decode(chunk)
                        log_buffer = (log_buffer + text).encode('utf-8')[-24000:].decode('utf-8', 'ignore')
                        line_buffer += text
                        while '\n' in line_buffer:
                            line, line_buffer = line_buffer.split('\n', 1)
                            m = re.fullmatch(r'LC_PROGRESS=(\d{1,3})\|(.*)', line.strip())
                            if m:
                                progress = max(progress, min(99, int(m[1])))
                                step = m[2][:100]
                            if line.startswith('LC_LINK='):
                                link = line[8:].strip()
                                if allowed_link(link) and link not in links and len(links) < 20:
                                    links.append(link)
                        line_buffer = line_buffer[-16384:]
                    now = time.monotonic()
                    if now - started > timeout:
                        final = 'timed_out'
                        self.kill(proc)
                    exited = proc.poll() is not None
                    if now - last_send >= 2 or exited:
                        seq += 1
                        event = dict(seq=seq, state='running', progress=progress, step=step,
                                     log=log_buffer, links=links)
                        atomic_json(self.journal, dict(id=jid, seq=seq, pending=event))
                        # Stop the process within ~60s when control connectivity is lost.
                        reply = self.send(jid, event)
                        atomic_json(self.journal, dict(id=jid, seq=seq))
                        log_buffer = ''
                        last_send = time.monotonic()
                        if reply.get('stop'):
                            final = 'cancelled'
                            self.kill(proc)
                    if final or (exited and not selector.get_map()):
                        break
                if final is None:
                    final = 'succeeded' if proc.returncode == 0 else 'failed'
                seq += 1
                event = dict(seq=seq, state=final, exit_code=proc.returncode,
                             log=log_buffer, links=links, step='执行结束')
                atomic_json(self.journal, dict(id=jid, seq=seq, pending=event))
                self.send(jid, event)
                self.journal.unlink(missing_ok=True)
            finally:
                self.kill(proc)  # Includes background children in the same process group.
                selector.close()
                proc.stdout.close()


def main():
    os.umask(0o077)
    config_path = os.environ.get('LC_AGENT_CONFIG', '/etc/lightsail-control/agent.json')
    directory = pathlib.Path(os.environ.get('LC_AGENT_STATE', '/var/lib/lightsail-control'))
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock = open(directory / 'agent.lock', 'w')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    client = Client(read_json(config_path, {}))
    metrics = Metrics(directory)
    stop = threading.Event()

    def heartbeat():
        while not stop.is_set():
            try:
                client.post('/agent/heartbeat', metrics.sample())
            except Exception as e:
                print('Heartbeat failed:', type(e).__name__, flush=True)
            stop.wait(5)

    threading.Thread(target=heartbeat, daemon=True).start()
    runner = Runner(client, directory)
    while True:
        try:
            runner.recover()
            job = client.post('/agent/poll', {}).get('job')
            if job:
                runner.run(job)
        except Exception as e:
            # Never print credential-bearing request objects or response bodies.
            print('Task channel failed:', type(e).__name__, flush=True)
        time.sleep(3)


if __name__ == '__main__':
    main()
