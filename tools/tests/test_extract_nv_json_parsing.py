import json

from analysis import extract_nv_references as enr


def test_traverse_json_and_associate(tmp_path):
    sample = {
        "functions": [
            {
                "function": "modem2_modem_carrier_unlock",
                "operands": "0xEA64",
                "address": "0x1000",
                "instructions": [
                    {"operands": "0xEA64", "address": "0x1000"},
                    {"operands": "some other"},
                ],
            }
        ]
    }
    p = tmp_path / "sample.json"
    p.write_text(json.dumps(sample))
    nvset = set(["0xea64", str(int("0xEA64", 16))])
    matches = enr.search_repo(tmp_path, nvset)
    assert matches, "No matches found in JSON sample"
    # ensure associate_function extracts function and address
    for m in matches:
        m2 = enr.associate_function(m)
        assert m2.get("function") is not None
        func = m2.get("function") or ""
        assert (
            "modem2_modem_carrier_unlock" in func
            or m2.get("address") == "0x1000"
        )
