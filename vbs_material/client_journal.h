#ifndef HINTLESS_VBS_CLIENT_JOURNAL_H_
#define HINTLESS_VBS_CLIENT_JOURNAL_H_
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include "absl/status/statusor.h"

namespace hintless_pir::vbs {
enum class DurableState : uint32_t { kPending = 1, kReady, kReserved, kInFlight, kDone, kInvalid };
// Trusted CLIENT filesystem only. No secrets, keys or plaintext indices stored.
// Crash recovery invalidates unfinished IDs; it never restores key material.
// Hash chaining detects corruption, NOT malicious snapshot rollback/deletion.
class ClientJournal final {
 public:
  static absl::StatusOr<std::unique_ptr<ClientJournal>> Open(const std::string& path);
  ~ClientJournal();
  absl::Status Begin(const std::string& config, const std::string& material);
  // Call only after authenticated generation AND installation were accepted.
  absl::Status Ready(const std::string& material);
  // Reserve durably before constructing a query; Commit before sending it.
  absl::Status Reserve(const std::string& material);
  absl::Status Commit(const std::string& material, const std::string& serialized_query);
  absl::StatusOr<std::string> Retry(const std::string& material) const;
  absl::Status Finish(const std::string& material);
  absl::Status Abandon(const std::string& material);
  absl::StatusOr<DurableState> State(const std::string& material) const;
 private:
  struct Entry { std::string config; DurableState state; std::string query; };
  explicit ClientJournal(int fd) : fd_(fd) {}
  absl::Status LoadAndInvalidate();
  absl::Status Transition(const std::string& id, DurableState next, const std::string& query = "");
  absl::Status Append(const std::string& config, const std::string& id, DurableState state, const std::string& query);
  absl::Status Validate(const std::string& config, const std::string& id, DurableState state, const std::string& query) const;
  void Apply(const std::string& config, const std::string& id, DurableState state, const std::string& query);
  int fd_;
  bool poisoned_ = false;
  uint64_t sequence_ = 0;
  uint64_t file_bytes_ = 8;
  std::string previous_ = std::string(32, '\0');
  std::map<std::string, Entry> entries_;
  mutable std::mutex mutex_;
};
}  // namespace hintless_pir::vbs
#endif
