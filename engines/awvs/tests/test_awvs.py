"""
AWVS Tests
"""

# Own library imports
from PatrowlEngineTest import PatrowlEngineTest

BASE_URL = "http://192.168.204.129:7003/engines/awvs"
# BASE_URL = "http://192.168.204.1:5445/engines/awvs"

# Define the engine instance
PET = PatrowlEngineTest(engine_name="awvs", base_url=BASE_URL)


def test_generic_features():
    """Generic tests."""
    PET.do_generic_tests()

def test_awvs_scan_url():
    """Custom test."""
    PET.custom_test(
        test_name="awvs_scan_url",
        assets=[{
            "id":2,
            "value":"http://192.168.204.1:8080",
            "criticity":"low",
            "datatype":"url"
        }],
        is_valid=True
    )

if __name__ == "__main__":
    test_generic_features()
    test_awvs_scan_url()