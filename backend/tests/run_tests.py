import os
import sys

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tests.test_url_engine import run_all_tests as run_all_url_engine_tests
from tests.test_phase3 import run_all_phase3_tests
from tests.test_phase4 import run_all_phase4_tests
from tests.test_phase5 import run_all_phase5_tests
from tests.test_phase6 import run_all_phase6_tests
from tests.test_phase7 import run_all_phase7_tests
from tests.test_phase8 import run_all_phase8_tests
from tests.test_phase9 import run_all_phase9_tests
from tests.test_phase10 import run_all_phase10_tests
from tests.test_phase11 import run_all_phase11_tests

def run_master_verification():
    print("================================================================")
    print("PHISHGUARD AI - MASTER AUTOMATED SYSTEM VERIFICATION SUITE")
    print("================================================================")

    print("\n>>> [RUNNING PHASE 1 & 2: URL & LEXICAL ENGINE TESTS] <<<")
    run_all_url_engine_tests()

    print("\n>>> [RUNNING PHASE 3: EMAIL INSPECTION & ML TRAINING PIPELINE] <<<")
    run_all_phase3_tests()

    print("\n>>> [RUNNING PHASE 4: RATE LIMITING, SECURITY HEADERS & WEBSOCKETS] <<<")
    run_all_phase4_tests()

    print("\n>>> [RUNNING PHASE 5: WHITELIST ENGINE, API KEYS & CI/CD PIPELINE] <<<")
    run_all_phase5_tests()

    print("\n>>> [RUNNING PHASE 6: SIEM EXPORTERS (CEF, STIX 2.1) & DIAGNOSTICS] <<<")
    run_all_phase6_tests()

    print("\n>>> [RUNNING PHASE 7: BATCH SCANS, WEBHOOK ALERTS & IOC FEEDS] <<<")
    run_all_phase7_tests()

    print("\n>>> [RUNNING PHASE 8: PRODUCTION SECURITY AUDIT & BENCHMARKING] <<<")
    run_all_phase8_tests()

    print("\n>>> [RUNNING PHASE 9: GUARDAI CHAT ASSISTANT & THREAT MAP INTELLIGENCE] <<<")
    run_all_phase9_tests()

    print("\n>>> [RUNNING PHASE 10: ENTERPRISE PRODUCTION RELEASE CERTIFICATION] <<<")
    run_all_phase10_tests()

    print("\n>>> [RUNNING PHASE 11: SOAR PLAYBOOK ENGINE & THREAT RELATIONSHIP GRAPH] <<<")
    run_all_phase11_tests()

    print("================================================================")
    print("[SUCCESS] ALL PHASES (PHASE 1 - 11) AUTOMATED SYSTEM VERIFICATION PASSED!")
    print("================================================================")

if __name__ == "__main__":
    run_master_verification()
