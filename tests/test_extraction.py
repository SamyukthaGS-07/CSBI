from csbi.common.schema import ScanRecord


def test_scan_record_defaults():
    record = ScanRecord(url='https://example.com')
    assert record.url == 'https://example.com'
    assert record.status == 'unknown'
