from app.utils.compare import ResponseComparator


def test_validator_decision_like_logic():
    cmp = ResponseComparator()
    control = {
        "text": "OK page",
        "headers": {"Content-Type": "text/html"},
        "status_code": 200,
        "elapsed": 0.1,
    }
    test = {
        "text": "Database error: MySQLSyntaxErrorException",
        "headers": {"Content-Type": "text/html"},
        "status_code": 500,
        "elapsed": 0.2,
    }
    from app.data.signatures import signatures as _sig

    comp = cmp.compare_responses(control, test, _sig)
    assert comp["status_code_change"] is True
    assert "error_signature" in comp["indicators"]
    assert comp["text_similarity"] < 0.9


