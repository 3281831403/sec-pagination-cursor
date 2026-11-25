from cursorpg import page, total_pages


def test_first_page_respects_size_limit():
    records = [
        {"id": "r1", "score": 7},
        {"id": "r2", "score": 7},
        {"id": "r3", "score": 7},
    ]

    result = page(records, ["score"], 2)

    assert len(result["records"]) <= 2


def test_second_page_does_not_overlap_first_page():
    records = [
        {"id": "r1", "score": 10},
        {"id": "r2", "score": 20},
        {"id": "r3", "score": 30},
        {"id": "r4", "score": 40},
    ]

    first = page(records, ["score"], 2)
    second = page(records, ["score"], 2, first["next"])

    first_ids = {record["id"] for record in first["records"]}
    second_ids = {record["id"] for record in second["records"]}
    assert first_ids.isdisjoint(second_ids)


def test_last_page_has_no_following_cursor():
    records = [
        {"id": "r1", "score": 10},
        {"id": "r2", "score": 20},
        {"id": "r3", "score": 30},
    ]

    result = page(records, ["score"], 3)

    assert result["next"] is None


def test_total_pages_rounds_up():
    assert total_pages(5, 2) == 3
    assert total_pages(6, 2) == 3
    assert total_pages(0, 2) == 0


def test_single_record_is_the_last_page():
    records = [{"id": "only", "score": 1}]

    result = page(records, ["score"], 1)

    assert [record["id"] for record in result["records"]] == ["only"]
    assert result["next"] is None