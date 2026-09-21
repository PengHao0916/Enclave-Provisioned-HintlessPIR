#include "client_journal.h"
#include <atomic>
#include <fstream>
#include <filesystem>
#include <thread>
#include <signal.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "local_material/protocol.h"
#include "shell_encryption/testing/status_testing.h"

// The upstream ASSERT_OK macro declares an unscoped line-numbered local.
// Keep this shorthand safe inside conditional statements and on shared lines.
#undef ASSERT_OK
#define ASSERT_OK(expr) do { const auto checked_status = (expr); \
  ASSERT_TRUE(checked_status.ok()) << checked_status.ToString(); } while (false)

namespace hintless_pir::vbs {
namespace {
class JournalTest : public ::testing::Test {
 protected:
  void SetUp() override {
    char temp[] = "/tmp/hintless-journal-XXXXXX";
    auto* made = mkdtemp(temp); ASSERT_NE(made, nullptr);
    directory = made; path = directory + "/client.log";
  }
  void TearDown() override { std::filesystem::remove_all(directory); }
  std::string Query(const std::string& material) {
    local_material::Query q;
    q.set_config_id(config); q.set_material_id(material); q.set_request_id(std::string(32, 'r'));
    q.mutable_lwe_query()->add_b_coeffs(123); q.mutable_lwe_query()->add_b_coeffs(456);
    return q.SerializeAsString();
  }
  const std::string config = std::string(32, 'c'), id = std::string(32, 'i');
  std::string directory, path;
};
TEST_F(JournalTest, DurableExactRetryAndTerminalState) {
  ASSERT_OK_AND_ASSIGN(auto journal, ClientJournal::Open(path));
  ASSERT_OK(journal->Begin(config, id)); ASSERT_OK(journal->Ready(id));
  ASSERT_OK(journal->Reserve(id)); ASSERT_OK(journal->Commit(id, Query(id)));
  EXPECT_EQ(*journal->Retry(id), Query(id));
  EXPECT_FALSE(journal->Commit(id, Query(id)).ok());
  ASSERT_OK(journal->Finish(id)); EXPECT_FALSE(journal->Retry(id).ok());
  journal.reset();
  ASSERT_OK_AND_ASSIGN(auto reopened, ClientJournal::Open(path));
  EXPECT_EQ(*reopened->State(id), DurableState::kDone);
  EXPECT_FALSE(reopened->Begin(config, id).ok()); EXPECT_FALSE(reopened->Reserve(id).ok());
}
TEST_F(JournalTest, QueryCannotPrecedeReadyAndReservation) {
  ASSERT_OK_AND_ASSIGN(auto j, ClientJournal::Open(path));
  EXPECT_FALSE(j->Ready(id).ok()); ASSERT_OK(j->Begin(config, id));
  EXPECT_FALSE(j->Reserve(id).ok()); EXPECT_FALSE(j->Commit(id, Query(id)).ok());
  ASSERT_OK(j->Ready(id)); EXPECT_FALSE(j->Commit(id, Query(id)).ok());
  ASSERT_OK(j->Reserve(id)); ASSERT_OK(j->Commit(id, Query(id)));
}
TEST_F(JournalTest, ConcurrentReservationHasOneWinner) {
  ASSERT_OK_AND_ASSIGN(auto j, ClientJournal::Open(path));
  ASSERT_OK(j->Begin(config, id)); ASSERT_OK(j->Ready(id));
  std::atomic<int> winners{0};
  std::thread a([&]{ if (j->Reserve(id).ok()) ++winners; });
  std::thread b([&]{ if (j->Reserve(id).ok()) ++winners; });
  a.join(); b.join(); EXPECT_EQ(winners, 1);
}
TEST_F(JournalTest, RestartInvalidatesEveryUnfinishedState) {
  ASSERT_OK_AND_ASSIGN(auto j, ClientJournal::Open(path));
  for (int state = 1; state <= 4; ++state) {
    const std::string material(32, '0' + state);
    ASSERT_OK(j->Begin(config, material));
    if (state >= 2) ASSERT_OK(j->Ready(material));
    if (state >= 3) ASSERT_OK(j->Reserve(material));
    if (state >= 4) ASSERT_OK(j->Commit(material, Query(material)));
  }
  j.reset(); ASSERT_OK_AND_ASSIGN(auto reopened, ClientJournal::Open(path));
  for (int state = 1; state <= 4; ++state) {
    const std::string material(32, '0' + state);
    EXPECT_EQ(*reopened->State(material), DurableState::kInvalid);
    EXPECT_FALSE(reopened->Ready(material).ok()); EXPECT_FALSE(reopened->Retry(material).ok());
  }
}
TEST_F(JournalTest, AbruptProcessExitPreservesReservation) {
  pid_t child = fork(); ASSERT_GE(child, 0);
  if (!child) {
    auto j = ClientJournal::Open(path);
    bool ok = j.ok() && (*j)->Begin(config, id).ok() && (*j)->Ready(id).ok() && (*j)->Reserve(id).ok();
    _exit(ok ? 0 : 2);  // No C++ destructors or buffered stream flushing.
  }
  int status = 0; ASSERT_EQ(waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status)); ASSERT_EQ(WEXITSTATUS(status), 0);
  ASSERT_OK_AND_ASSIGN(auto j, ClientJournal::Open(path));
  EXPECT_EQ(*j->State(id), DurableState::kInvalid); EXPECT_FALSE(j->Reserve(id).ok());
}
TEST_F(JournalTest, TruncatedTailIsRejectedWithoutRepair) {
  ASSERT_OK_AND_ASSIGN(auto j, ClientJournal::Open(path)); ASSERT_OK(j->Begin(config, id)); j.reset();
  const auto old = std::filesystem::file_size(path);
  ASSERT_EQ(truncate(path.c_str(), old - 1), 0);
  EXPECT_FALSE(ClientJournal::Open(path).ok()); EXPECT_EQ(std::filesystem::file_size(path), old - 1);
}
TEST_F(JournalTest, CorruptionIsRejectedWithoutReset) {
  ASSERT_OK_AND_ASSIGN(auto j, ClientJournal::Open(path)); ASSERT_OK(j->Begin(config, id)); j.reset();
  std::fstream file(path, std::ios::in | std::ios::out | std::ios::binary);
  file.seekp(60); file.put('x'); file.close();
  EXPECT_FALSE(ClientJournal::Open(path).ok());
}
TEST_F(JournalTest, EmptyExistingJournalIsNotReinitialized) {
  ASSERT_OK_AND_ASSIGN(auto j, ClientJournal::Open(path));
  ASSERT_OK(j->Begin(config, id));
  j.reset();
  ASSERT_EQ(truncate(path.c_str(), 0), 0);
  EXPECT_EQ(ClientJournal::Open(path).status().code(), absl::StatusCode::kDataLoss);
  EXPECT_EQ(std::filesystem::file_size(path), 0);
}
TEST_F(JournalTest, ExclusiveLockAndPrivateFileRequirements) {
  ASSERT_OK_AND_ASSIGN(auto j, ClientJournal::Open(path));
  EXPECT_FALSE(ClientJournal::Open(path).ok()); j.reset();
  ASSERT_EQ(chmod(path.c_str(), 0644), 0); EXPECT_FALSE(ClientJournal::Open(path).ok());
  ASSERT_EQ(chmod(path.c_str(), 0600), 0);
  const auto symlink_path = directory + "/alias";
  ASSERT_EQ(symlink(path.c_str(), symlink_path.c_str()), 0); EXPECT_FALSE(ClientJournal::Open(symlink_path).ok());
}
TEST_F(JournalTest, QueryBindingAndSizeAreChecked) {
  ASSERT_OK_AND_ASSIGN(auto j, ClientJournal::Open(path));
  ASSERT_OK(j->Begin(config, id)); ASSERT_OK(j->Ready(id)); ASSERT_OK(j->Reserve(id));
  EXPECT_FALSE(j->Commit(id, Query(std::string(32, 'w'))).ok());
  EXPECT_FALSE(j->Commit(id, "not a query").ok());
  EXPECT_FALSE(j->Commit(id, std::string(2 * 1024 * 1024, 'x')).ok());
  ASSERT_OK(j->Commit(id, Query(id)));
}
TEST_F(JournalTest, FailedWritePoisonsLiveJournal) {
  pid_t child = fork(); ASSERT_GE(child, 0);
  if (!child) {
    auto j = ClientJournal::Open(path);
    if (!j.ok() || !(*j)->Begin(config, id).ok()) _exit(2);
    signal(SIGXFSZ, SIG_IGN);
    rlimit limit{}; if (getrlimit(RLIMIT_FSIZE, &limit)) _exit(3);
    limit.rlim_cur = std::filesystem::file_size(path);
    if (setrlimit(RLIMIT_FSIZE, &limit)) _exit(4);
    bool blocked = !(*j)->Ready(id).ok() && !(*j)->State(id).ok() &&
        !(*j)->Begin(config, std::string(32, 'n')).ok();
    _exit(blocked ? 0 : 5);
  }
  int status = 0; ASSERT_EQ(waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status)); EXPECT_EQ(WEXITSTATUS(status), 0);
  ASSERT_OK_AND_ASSIGN(auto j, ClientJournal::Open(path));
  EXPECT_EQ(*j->State(id), DurableState::kInvalid);
}
}  // namespace
}  // namespace hintless_pir::vbs
