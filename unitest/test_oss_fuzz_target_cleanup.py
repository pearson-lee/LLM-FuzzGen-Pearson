import tempfile
import unittest
from pathlib import Path

from external.oss_fuzz import OSSFuzz


class OSSFuzzTargetCleanupTest(unittest.TestCase):
    def test_remove_target_cleans_sources_binaries_and_corpus(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            oss_fuzz = OSSFuzz()
            oss_fuzz.oss_fuzz_dir = root / "oss-fuzz"
            oss_fuzz.build_out_dir = oss_fuzz.oss_fuzz_dir / "build" / "out"
            oss_fuzz.build_corpus_dir = oss_fuzz.oss_fuzz_dir / "build" / "corpus"
            oss_fuzz.build_cache_dir = oss_fuzz.oss_fuzz_dir / "build" / "artifact_cache"

            project_dir = oss_fuzz.oss_fuzz_dir / "projects" / "demo"
            out_dir = oss_fuzz.build_out_dir / "demo"
            corpus_dir = oss_fuzz.build_corpus_dir / "demo" / "llm_fuzzgen_symcc_demo"
            replay_dir = out_dir / "symcc_replay"
            coverage_dir = out_dir / "coverage"
            src_dir = out_dir / "src"
            inspector_dir = out_dir / "inspector"
            textcov_dir = out_dir / "textcov_reports"
            report_dir = out_dir / "report"
            report_target_dir = out_dir / "report_target"
            stale_cache_snapshot = (
                oss_fuzz.build_cache_dir / "demo" / "address" / "default" / "fingerprint-with-target"
            )
            unrelated_cache_snapshot = (
                oss_fuzz.build_cache_dir / "demo" / "address" / "default" / "fingerprint-without-target"
            )
            stale_cache_src_dir = stale_cache_snapshot / "src"
            unrelated_cache_src_dir = unrelated_cache_snapshot / "src"
            for directory in (
                project_dir,
                out_dir,
                corpus_dir,
                replay_dir,
                coverage_dir,
                src_dir,
                inspector_dir,
                textcov_dir,
                report_dir,
                report_target_dir,
                stale_cache_src_dir,
                unrelated_cache_src_dir,
            ):
                directory.mkdir(parents=True, exist_ok=True)

            target_source = project_dir / "llm_fuzzgen_symcc_demo.c"
            target_options = project_dir / "llm_fuzzgen_symcc_demo.options"
            unrelated_source = project_dir / "llm_fuzzgen_other.c"
            direct_binary = out_dir / "llm_fuzzgen_symcc_demo"
            out_options = out_dir / "llm_fuzzgen_symcc_demo.options"
            replay_binary = replay_dir / "llm_fuzzgen_symcc_demo"
            replay_wrapper = replay_dir / "llm_fuzzgen_symcc_demo_replay"
            coverage_binary = coverage_dir / "llm_fuzzgen_symcc_demo"
            src_copy = src_dir / "llm_fuzzgen_symcc_demo.c"
            src_options = src_dir / "llm_fuzzgen_symcc_demo.options"
            inspector_report = inspector_dir / "llm_fuzzgen_symcc_demo.covreport"
            inspector_aggregate = inspector_dir / "all_functions.js"
            textcov_project_report = textcov_dir / "project.linecovreport"
            branch_blockers = report_dir / "linux" / "branch-blockers.json"
            target_summary = report_target_dir / "llm_fuzzgen_symcc_demo" / "linux" / "summary.json"
            stale_cache_binary = stale_cache_snapshot / "llm_fuzzgen_symcc_demo"
            stale_cache_src = stale_cache_src_dir / "llm_fuzzgen_symcc_demo.c"
            unrelated_cache_binary = unrelated_cache_snapshot / "llm_fuzzgen_other"
            unrelated_binary = out_dir / "llm_fuzzgen_other"
            seed = corpus_dir / "seed"

            for path in (
                target_source,
                target_options,
                unrelated_source,
                direct_binary,
                out_options,
                replay_binary,
                replay_wrapper,
                coverage_binary,
                src_copy,
                src_options,
                inspector_report,
                inspector_aggregate,
                textcov_project_report,
                branch_blockers,
                target_summary,
                stale_cache_binary,
                stale_cache_src,
                unrelated_cache_binary,
                unrelated_binary,
                seed,
            ):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("x", encoding="utf-8")

            oss_fuzz.remove_target("demo", "llm_fuzzgen_symcc_demo")

            self.assertFalse(target_source.exists())
            self.assertFalse(target_options.exists())
            self.assertFalse(direct_binary.exists())
            self.assertFalse(out_options.exists())
            self.assertFalse(replay_binary.exists())
            self.assertFalse(replay_wrapper.exists())
            self.assertFalse(coverage_binary.exists())
            self.assertFalse(src_copy.exists())
            self.assertFalse(src_options.exists())
            self.assertFalse(inspector_report.exists())
            self.assertFalse(inspector_dir.exists())
            self.assertFalse(textcov_dir.exists())
            self.assertFalse(report_dir.exists())
            self.assertFalse(report_target_dir.exists())
            self.assertFalse(stale_cache_snapshot.exists())
            self.assertTrue(unrelated_cache_snapshot.exists())
            self.assertTrue(unrelated_cache_binary.exists())
            self.assertFalse(corpus_dir.exists())
            self.assertTrue(unrelated_source.exists())
            self.assertTrue(unrelated_binary.exists())


if __name__ == "__main__":
    unittest.main()
