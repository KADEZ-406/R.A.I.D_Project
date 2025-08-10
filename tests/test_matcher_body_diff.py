from app.utils.compare import ResponseComparator


def test_body_diff_threshold():
    cmp = ResponseComparator()
    baseline = "Hello world, this is a baseline response with TIMESTAMP 2020-01-01 10:10:10"
    mutated = "Hello mars, this is a changed response with TIMESTAMP 2020-02-02 12:12:12"
    sim = cmp.calculate_text_similarity(baseline, mutated)
    assert 0.0 <= sim <= 1.0
    assert sim < 0.9  # Should reflect noticeable difference


