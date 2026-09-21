#include "client_journal.h"
#include <errno.h>
#include <fcntl.h>
#include <filesystem>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include "local_material/protocol.h"
#include "shell_encryption/status_macros.h"

namespace hintless_pir::vbs {
namespace {
constexpr char kMagic[] = "HPJNL001";
constexpr uint32_t kMaxRecord = 2 * 1024 * 1024;
constexpr uint64_t kMaxFile = 256ULL * 1024 * 1024;
std::string Hash(const std::string& value) { return local_material::Digest("hintless/client-journal/v1" + value); }
void Put(std::string& out, uint64_t number, int width) {
  for (int i = width - 1; i >= 0; --i) out.push_back(static_cast<char>(number >> (i * 8)));
}
uint64_t Get(const char* bytes, int width) {
  uint64_t value = 0;
  for (int i = 0; i < width; ++i) value = (value << 8) | static_cast<unsigned char>(bytes[i]);
  return value;
}
bool Write(int fd, const char* bytes, size_t size) {
  while (size) {
    ssize_t n = write(fd, bytes, size);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return false;
    bytes += n; size -= n;
  }
  return true;
}
bool Read(int fd, char* bytes, size_t size) {
  while (size) {
    ssize_t n = read(fd, bytes, size);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return false;
    bytes += n; size -= n;
  }
  return true;
}
absl::Status Broken(const char* message) { return absl::DataLossError(message); }
}  // namespace

ClientJournal::~ClientJournal() { if (fd_ >= 0) close(fd_); }
absl::StatusOr<std::unique_ptr<ClientJournal>> ClientJournal::Open(const std::string& path) {
  int fd = open(path.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
  const bool created = fd >= 0;
  if (fd < 0 && errno == EEXIST) fd = open(path.c_str(), O_RDWR | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return absl::PermissionDeniedError("Cannot open client journal.");
  auto journal = std::unique_ptr<ClientJournal>(new ClientJournal(fd));
  struct stat st{};
  if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
      (st.st_mode & 077) || st.st_nlink != 1) return absl::PermissionDeniedError("Journal must be a private regular file owned by the client.");
  if (flock(fd, LOCK_EX | LOCK_NB)) return absl::UnavailableError("Client journal already locked.");
  if (created) {
    if (!Write(fd, kMagic, 8) || fsync(fd)) return Broken("Journal header commit failed.");
    const auto parent = std::filesystem::path(path).parent_path();
    const int dir = open(parent.empty() ? "." : parent.c_str(), O_DIRECTORY | O_RDONLY | O_CLOEXEC);
    if (dir < 0) return Broken("Cannot sync journal directory.");
    const int synced = fsync(dir); close(dir);
    if (synced) return Broken("Journal directory sync failed.");
  }
  RLWE_RETURN_IF_ERROR(journal->LoadAndInvalidate());
  return journal;
}

absl::Status ClientJournal::Validate(const std::string& config, const std::string& id,
                                    DurableState next, const std::string& query) const {
  if (config.size() != 32 || id.size() != 32) return absl::InvalidArgumentError("Journal IDs must have 32 bytes.");
  auto found = entries_.find(id);
  if (next == DurableState::kPending) {
    if (found != entries_.end()) return absl::AlreadyExistsError("Material ID is already recorded.");
  } else {
    if (found == entries_.end() || found->second.config != config) return absl::FailedPreconditionError("Unknown or mismatched material.");
    const auto old = found->second.state;
    bool allowed = (next == DurableState::kReady && old == DurableState::kPending) ||
        (next == DurableState::kReserved && old == DurableState::kReady) ||
        (next == DurableState::kInFlight && old == DurableState::kReserved) ||
        (next == DurableState::kDone && old == DurableState::kInFlight) ||
        (next == DurableState::kInvalid && old != DurableState::kDone && old != DurableState::kInvalid);
    if (!allowed) return absl::FailedPreconditionError("Unsafe journal state transition.");
  }
  if (next == DurableState::kInFlight) {
    local_material::Query parsed;
    if (query.empty() || query.size() > kMaxRecord - 144 || !parsed.ParseFromString(query) ||
        parsed.config_id() != config || parsed.material_id() != id || parsed.request_id().size() != 32 ||
        !parsed.has_lwe_query() || parsed.lwe_query().b_coeffs_size() == 0)
      return absl::InvalidArgumentError("Journal request binding is invalid.");
  } else if (!query.empty()) return absl::InvalidArgumentError("Only in-flight state can store a query.");
  return absl::OkStatus();
}
void ClientJournal::Apply(const std::string& config, const std::string& id,
                           DurableState state, const std::string& query) {
  entries_[id] = Entry{config, state, query};
}
absl::Status ClientJournal::Append(const std::string& config, const std::string& id,
                                   DurableState state, const std::string& query) {
  if (poisoned_) return Broken("Journal was invalidated by an I/O failure.");
  RLWE_RETURN_IF_ERROR(Validate(config, id, state, query));
  std::string record;
  Put(record, sequence_ + 1, 8); record += previous_; record += config; record += id;
  Put(record, static_cast<uint32_t>(state), 4); Put(record, query.size(), 4); record += query;
  const auto hash = Hash(record); record += hash;
  if (file_bytes_ + 4 + record.size() > kMaxFile) return absl::ResourceExhaustedError("Client journal size limit reached.");
  std::string prefix; Put(prefix, record.size(), 4);
  if (!Write(fd_, prefix.data(), prefix.size()) || !Write(fd_, record.data(), record.size()) || fsync(fd_)) {
    poisoned_ = true;
    return Broken("Journal commit failed; no query may be emitted.");
  }
  Apply(config, id, state, query);
  sequence_++; previous_ = hash; file_bytes_ += 4 + record.size();
  return absl::OkStatus();
}
absl::Status ClientJournal::LoadAndInvalidate() {
  struct stat st{};
  if (fstat(fd_, &st) || st.st_size < 8 || static_cast<uint64_t>(st.st_size) > kMaxFile || lseek(fd_, 0, SEEK_SET) < 0)
    return Broken("Invalid journal size or seek.");
  char magic[8];
  if (!Read(fd_, magic, 8) || std::string(magic, 8) != std::string(kMagic, 8)) return Broken("Journal header mismatch.");
  while (file_bytes_ < static_cast<uint64_t>(st.st_size)) {
    char prefix[4];
    if (!Read(fd_, prefix, 4)) return Broken("Truncated journal frame.");
    const uint64_t length = Get(prefix, 4);
    if (length < 144 || length > kMaxRecord || file_bytes_ + 4 + length > static_cast<uint64_t>(st.st_size))
      return Broken("Invalid or truncated journal record.");
    std::string record(length, '\0');
    if (!Read(fd_, record.data(), record.size())) return Broken("Journal read failed.");
    const uint64_t seq = Get(record.data(), 8), query_size = Get(record.data() + 108, 4);
    const auto state = static_cast<DurableState>(Get(record.data() + 104, 4));
    if (seq != sequence_ + 1 || record.substr(8, 32) != previous_ || query_size != length - 144 ||
        Hash(record.substr(0, length - 32)) != record.substr(length - 32)) return Broken("Journal integrity check failed.");
    const auto config = record.substr(40, 32), id = record.substr(72, 32), query = record.substr(112, query_size);
    if (!Validate(config, id, state, query).ok()) return Broken("Journal contains an invalid transition.");
    Apply(config, id, state, query); sequence_ = seq;
    previous_ = record.substr(length - 32); file_bytes_ += 4 + length;
  }
  // No client secret state is restored. Burn every unfinished ID before any
  // caller can use this journal, even if a previous recovery was interrupted.
  for (const auto& item : entries_) {
    if (item.second.state != DurableState::kDone && item.second.state != DurableState::kInvalid) {
      RLWE_RETURN_IF_ERROR(Append(item.second.config, item.first, DurableState::kInvalid, ""));
    }
  }
  return absl::OkStatus();
}
absl::Status ClientJournal::Begin(const std::string& config, const std::string& id) {
  std::lock_guard<std::mutex> lock(mutex_); return Append(config, id, DurableState::kPending, "");
}
absl::Status ClientJournal::Transition(const std::string& id, DurableState next, const std::string& query) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto found = entries_.find(id);
  if (found == entries_.end()) return absl::NotFoundError("Unknown journal material.");
  return Append(found->second.config, id, next, query);
}
absl::Status ClientJournal::Ready(const std::string& id) { return Transition(id, DurableState::kReady); }
absl::Status ClientJournal::Reserve(const std::string& id) { return Transition(id, DurableState::kReserved); }
absl::Status ClientJournal::Commit(const std::string& id, const std::string& query) { return Transition(id, DurableState::kInFlight, query); }
absl::Status ClientJournal::Finish(const std::string& id) { return Transition(id, DurableState::kDone); }
absl::Status ClientJournal::Abandon(const std::string& id) { return Transition(id, DurableState::kInvalid); }
absl::StatusOr<std::string> ClientJournal::Retry(const std::string& id) const {
  std::lock_guard<std::mutex> lock(mutex_);
  auto found = entries_.find(id);
  if (poisoned_ || found == entries_.end() || found->second.state != DurableState::kInFlight)
    return absl::FailedPreconditionError("No durable in-flight request.");
  return found->second.query;
}
absl::StatusOr<DurableState> ClientJournal::State(const std::string& id) const {
  std::lock_guard<std::mutex> lock(mutex_);
  auto found = entries_.find(id);
  if (poisoned_) return Broken("Journal is invalidated.");
  if (found == entries_.end()) return absl::NotFoundError("Unknown journal material.");
  return found->second.state;
}
}  // namespace hintless_pir::vbs
