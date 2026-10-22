#!/usr/bin/env python3
"""Local synthetic fixtures; raw multipart files never pass through a model."""
import json
import time
import urllib.request
import uuid

BASE = "http://127.0.0.1:18082"


def call(operation, options, **files):
    boundary = "csv-demo-" + uuid.uuid4().hex
    chunks = []
    parts = {"options": json.dumps(options).encode(), **files}
    for name, data in parts.items():
        chunks.extend([
            ("--" + boundary + "\r\nContent-Disposition: form-data; name=\"" + name + "\"\r\n\r\n").encode(),
            data, b"\r\n",
        ])
    chunks.append(("--" + boundary + "--\r\n").encode())
    request = urllib.request.Request(BASE + "/csv/" + operation, data=b"".join(chunks),
        headers={"Content-Type": "multipart/form-data; boundary=" + boundary}, method="POST")
    started = time.perf_counter()
    with urllib.request.urlopen(request, timeout=45) as response:
        raw = response.read()
    result = json.loads(raw)
    print(operation, json.dumps(result, separators=(",", ":")))
    print(json.dumps({"input_file_bytes": sum(map(len, files.values())), "response_bytes": len(raw),
        "elapsed_seconds": round(time.perf_counter() - started, 3)}))
    return result, len(raw)


dedupe, _ = call("dedupe", {"key_columns": ["id"], "keep": "last"},
    file=b"id,status\na,old\nb,pending\na,active\n")
assert dedupe["rows"] == [["b", "pending"], ["a", "active"]]
joined, _ = call("join", {"left_key_columns": ["id"], "right_key_columns": ["customer_id"], "type": "left"},
    left=b"id,region\na,west\nb,east\n", right=b"customer_id,plan\na,pro\na,team\n")
assert joined["rows"] == [["a", "west", "pro"], ["a", "west", "team"], ["b", "east", ""]]
totals, _ = call("aggregate", {"metrics": [{"name": "total", "op": "sum", "column": "amount"}]},
    file=b"amount\n0.1\n0.2\n")
assert totals["rows"] == [["0.3"]]
transformed, _ = call("transform", {"column": "email", "op": "lower"},
    file=b"id,email\n01,AGENT@EXAMPLE.INVALID\n")
assert transformed["rows"] == [["01", "agent@example.invalid"]]
source = b"region,amount,description\n" + b"".join(
    ("%s,0.10,synthetic repeated event payload\n" % ["west", "east", "north"][i % 3]).encode()
    for i in range(50_000))
result, size = call("aggregate", {"group_columns": ["region"], "metrics": [
    {"name": "events", "op": "count_rows"}, {"name": "total", "op": "sum", "column": "amount"}]}, file=source)
assert result["rows"] == [["west", "16667", "1666.7"], ["east", "16667", "1666.7"], ["north", "16666", "1666.6"]]
print(json.dumps({"synthetic_50000_rows_to": result["output_rows"],
    "response_to_csv_percent": round(100 * size / len(source), 4),
    "model_token_savings_measured": False, "paid_demand_validated": False}))
