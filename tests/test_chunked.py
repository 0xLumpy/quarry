"""C07 increment 4 — chunked lanes (nuclei/dalfox) under the contract vocabulary.

Two correctness gains reconciled with their existing custom per-chunk events (no duplicates):
1. resume validity is a WORK_UNIT that folds coverage-affecting CONFIG (severity/etags/mode/chunk), not
   just the input list — so a template-scope / mode change no longer wrongly resumes done chunks.
2. per-chunk events carry a stable work_unit (not the loop index), and the source terminal always fires.
"""
import inspect

import pytest

from quarry_recon.events import work_unit
from quarry_recon.phases import params

pytestmark = pytest.mark.offline


class TestResumeKeyFoldsConfig:
    def test_config_change_yields_new_scan_key(self):
        # same hosts, DIFFERENT coverage config → different work_unit → resume starts fresh (no wrong skip)
        base = work_unit("params.nuclei_scan", inputs={"hosts": ["a", "b"]},
                         config={"severity": "critical,high,medium", "etags": "intrusive", "chunk": 50})
        wider = work_unit("params.nuclei_scan", inputs={"hosts": ["a", "b"]},
                          config={"severity": "critical,high,medium,low", "etags": "intrusive", "chunk": 50})
        assert base != wider

    def test_same_config_same_key(self):
        cfg = {"severity": "critical,high,medium", "etags": "intrusive,fuzz,dos,brute-force", "chunk": 50}
        assert (work_unit("params.nuclei_scan", inputs={"hosts": ["a"]}, config=cfg)
                == work_unit("params.nuclei_scan", inputs={"hosts": ["a"]}, config=cfg))

    def test_chunk_unit_distinct_from_scan_unit(self):
        cfg = {"severity": "s", "chunk": 2}
        scan = work_unit("params.nuclei_scan", inputs={"hosts": ["a", "b", "c"]}, config=cfg)
        chunk = work_unit("params.nuclei_scan", inputs={"hosts": ["a", "b"]}, config=cfg)
        assert scan != chunk                                # scan folds ALL hosts; a chunk folds its subset


class TestSourceStructure:
    @pytest.mark.parametrize("fn", [params._nuclei_scan, params._dalfox_xss_fast])
    def test_resume_key_is_config_inclusive_work_unit(self, fn):
        src = inspect.getsource(fn)
        assert "scan_wu = events.work_unit(" in src         # config-inclusive resume key
        assert '"work_unit": scan_wu' in src                # persisted in chunks.state.json
        assert 'prev.get("work_unit") == scan_wu' in src    # validity check keys on it
        assert "hashlib.sha256((" not in src                # the old hosts-only input_hash CODE is gone

    @pytest.mark.parametrize("fn", [params._nuclei_scan, params._dalfox_xss_fast])
    def test_per_chunk_work_unit_on_events(self, fn):
        src = inspect.getsource(fn)
        assert "chunk_wu = events.work_unit(" in src         # a stable per-chunk unit (not the loop index)
        assert "work_unit=chunk_wu" in src                   # tagged on the per-chunk progress event

    @pytest.mark.parametrize("fn", [params._nuclei_scan, params._dalfox_xss_fast])
    def test_source_terminal_guaranteed(self, fn):
        src = inspect.getsource(fn)
        assert "try:" in src and "finally:" in src           # source tool_finish fires even if the loop raises
        assert "events.tool_finish(sid" in src and "work_unit=scan_wu" in src
