import importlib.util
import pathlib
import tempfile
import unittest
import hashlib

spec = importlib.util.spec_from_file_location('agent', pathlib.Path(__file__).parents[1] / 'agent/agent.py')
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


class TrafficTests(unittest.TestCase):
    def test_reboot_reset_and_month(self):
        state, _ = agent.update_traffic({}, {'eth0': [100, 200]}, 'a', '2026-09')
        self.assertEqual((state['up'], state['down']), (0, 0))
        state, _ = agent.update_traffic(state, {'eth0': [140, 280]}, 'a', '2026-09')
        self.assertEqual((state['up'], state['down']), (40, 80))
        state, _ = agent.update_traffic(state, {'eth0': [10, 20]}, 'b', '2026-09')
        self.assertEqual((state['up'], state['down']), (50, 100))
        state, _ = agent.update_traffic(state, {'eth0': [15, 25]}, 'b', '2026-10')
        self.assertEqual((state['up'], state['down']), (5, 5))

    def test_interface_change_does_not_add_lifetime(self):
        state, _ = agent.update_traffic({}, {'eth0': [100, 200]}, 'a', '2026-09')
        state, _ = agent.update_traffic(state, {'eth1': [10000, 20000]}, 'a', '2026-09')
        self.assertEqual(state['up'], 0)

    def test_links(self):
        for link in ['javascript:alert(1)', 'data:text/html,hi', 'https://x\nhi']:
            self.assertFalse(agent.allowed_link(link))
        self.assertTrue(agent.allowed_link('vless://abc@example.com:443?security=reality'))


class FakeClient:
    def __init__(self): self.events = []
    def post(self, path, event):
        self.events.append(event.copy())
        return {'ack': event['seq'], 'stop': False}


class ExecutionTests(unittest.TestCase):
    def run_script(self, script):
        client = FakeClient()
        with tempfile.TemporaryDirectory() as directory:
            runner = agent.Runner(client, directory)
            runner.run(dict(id='a' * 36, script=script, sha256=hashlib.sha256(script.encode()).hexdigest(), timeout=60))
            self.assertFalse(runner.journal.exists())
        return client.events

    def test_success_progress_result(self):
        events = self.run_script("echo 'LC_PROGRESS=45|完成依赖'\necho 'LC_LINK=https://example.com/panel'\n")
        self.assertEqual(events[-1]['state'], 'succeeded')
        self.assertEqual(events[-1]['links'], ['https://example.com/panel'])
        self.assertTrue(any(e.get('progress') == 45 for e in events))
        self.assertEqual([e['seq'] for e in events], list(range(1, len(events) + 1)))

    def test_nonzero_is_failure(self):
        events = self.run_script('echo failure\nexit 7\n')
        self.assertEqual(events[-1]['state'], 'failed')
        self.assertEqual(events[-1]['exit_code'], 7)

    def test_digest_rejects_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                agent.Runner(FakeClient(), directory).run(dict(id='a'*36, script='exit 0', sha256='wrong', timeout=60))

    def test_recovery_does_not_reexecute(self):
        with tempfile.TemporaryDirectory() as directory:
            client = FakeClient()
            runner = agent.Runner(client, directory)
            agent.atomic_json(runner.journal, dict(id='a'*36, seq=4))
            runner.recover()
            self.assertEqual(client.events[0]['state'], 'interrupted')
            self.assertEqual(client.events[0]['seq'], 5)


if __name__ == '__main__': unittest.main()
