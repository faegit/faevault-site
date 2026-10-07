import json
from pathlib import Path
import unittest
from core.remote_update import UpdateState, reduce

class RemoteUpdateFixtureTest(unittest.TestCase):
    def test_shared_fixtures(self):
        fixture = json.loads((Path(__file__).resolve().parents[1] / 'spec/remote_update_v1_fixtures.json').read_text(encoding='utf-8'))
        for case in fixture['cases']:
            raw = case['initial']
            state = UpdateState(**{**raw, 'notified': tuple(raw.get('notified', []))})
            for event in case['events']:
                with self.subTest(case=case['name'], event=event):
                    state, notify = reduce(state, event)
                    self.assertEqual(notify, event['notify'])
                    for field in ('baseline', 'pending', 'detected_at'):
                        if 'expected_' + field in event:
                            self.assertEqual(getattr(state, field), event['expected_' + field])
                    if 'expected_notified_count' in event:
                        self.assertEqual(len(state.notified), event['expected_notified_count'])

    def test_uploaded_version_acknowledges_consumed_input_only(self):
        state = UpdateState('A', 'B', ('B',), 1000)
        state, notify = reduce(state, {'type': 'acknowledge', 'version': 'C', 'consumed_version': 'B'})
        self.assertEqual(state.baseline, 'C')
        self.assertEqual(state.pending, '')
        self.assertFalse(notify)
        state = UpdateState('A', 'D', ('D',), 2000)
        state, _ = reduce(state, {'type': 'acknowledge', 'version': 'C', 'consumed_version': 'B'})
        self.assertEqual(state.pending, 'D')
        self.assertEqual(state.detected_at, 2000)


def test_reenabling_keeps_confirmed_baseline_and_detects_changes_while_disabled(monkeypatch):
    from core import remote_update
    values={}
    monkeypatch.setattr(remote_update.config,'get',lambda key,default=None:values.get(key,default))
    monkeypatch.setattr(remote_update.config,'set',lambda key,value:values.__setitem__(key,value))
    remote_update.save('vault','webdav','association',UpdateState('A','B',('B',),1000))
    remote_update.set_enabled('vault','webdav',False)
    assert not remote_update.load('vault','webdav','association').pending
    remote_update.set_enabled('vault','webdav',True)
    state,notify=reduce(remote_update.load('vault','webdav','association'),{'type':'observe','version':'C','now':2000})
    assert notify
    assert not reduce(state,{'type':'observe','version':'C','now':3000})[1]
