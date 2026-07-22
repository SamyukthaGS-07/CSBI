from csbi.clustering.dbscan_cluster import cluster_records


def test_cluster_records_returns_payload():
    result = cluster_records([{'id': 1}])
    assert 'clusters' in result
