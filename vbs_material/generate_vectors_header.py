"""Convert actual Linux oracle results to a C++ public-fixture table."""
import json
from pathlib import Path

root = Path(__file__).resolve().parent
source = root / "testdata" / "upstream-vectors.json"
data = json.loads(source.read_text(encoding="utf-8-sig"))
assert data["schema"] == 1 and len(data["vectors"]) == 8
lines = ["// Generated from testdata/upstream-vectors.json; public test inputs only.",
         "#ifndef HINTLESS_VBS_TEST_VECTORS_H_", "#define HINTLESS_VBS_TEST_VECTORS_H_",
         "struct UpstreamVector { unsigned dimension; const char* lwe_seed; const char* rlwe_seed;",
         "  const char* stream_hash; const char* boundary_word; const char* lwe_hash; const char* rlwe_hash; };",
         "constexpr UpstreamVector kUpstreamVectors[] = {"]
for i, item in enumerate(data["vectors"]):
    assert item["case"] == i
    values = []
    for field, size in [("lwe_seed", 64), ("rlwe_seed", 64), ("stream_sha256", 32),
                        ("boundary_rand64_le", 8), ("lwe_sha256", 32), ("rlwe_coeff_sha256", 32)]:
        value = item[field]
        assert len(bytes.fromhex(value)) == size
        values.append('"' + value + '"')
    lines.append("  {" + str(item["lwe_dimension"]) + ", " + ", ".join(values) + "},")
lines.extend(["};", "#endif", ""])
(root / "test_vectors.h").write_text("\n".join(lines), encoding="utf-8")
