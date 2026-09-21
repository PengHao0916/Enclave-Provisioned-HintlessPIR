#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
BAZEL_BIN="${BAZEL_BIN:-bazel}"
if ! command -v "$BAZEL_BIN" >/dev/null 2>&1; then
  BAZEL_BIN=/home/ph/bin/bazel
fi
mkdir -p local_material/results
"$BAZEL_BIN" test -c opt --jobs=4 --test_output=errors \
  //local_material:protocol_test \
  //hintless_simplepir:hintless_simplepir_test \
  //hintless_simplepir:client_test //hintless_simplepir:server_test \
  //linpir:client_test //linpir:server_test
"$BAZEL_BIN" build -c opt --jobs=4 //local_material:local_worker
./bazel-bin/local_material/local_worker demo 5 functional > local_material/results/functional.json
./bazel-bin/local_material/local_worker demo "${1:-3}" 8mb > local_material/results/8mb.json
python3 local_material/summarize_results.py
