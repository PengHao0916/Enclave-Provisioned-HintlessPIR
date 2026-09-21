#include "lifecycle_test_driver.h"
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include "shell_encryption/status_macros.h"

namespace hintless_pir::vbs {
namespace {
namespace wire = hintless_vbs;
absl::Status Bad(const char* s) { return absl::InternalError(s); }
struct Child {
  pid_t pid = -1;
  int input = -1, output = -1;
  ~Child() {
    if (input >= 0) close(input);
    if (output >= 0) close(output);
    if (pid > 0) { kill(pid, SIGKILL); while (waitpid(pid, nullptr, 0) < 0 && errno == EINTR) {} }
  }
  absl::Status Start(const std::string& program, const std::string& dll, const std::string& log) {
    int to[2], from[2];
    if (pipe2(to, O_CLOEXEC)) return Bad("Cannot create client input pipe.");
    if (pipe2(from, O_CLOEXEC)) { close(to[0]); close(to[1]); return Bad("Cannot create client output pipe."); }
    pid = fork();
    if (!pid) {
      if (dup2(to[0], STDIN_FILENO) < 0 || dup2(from[1], STDOUT_FILENO) < 0 ||
          !freopen(log.c_str(), "w", stderr)) _exit(127);
      close(to[0]); close(to[1]); close(from[0]); close(from[1]);
      if (dll.empty()) execl(program.c_str(), program.c_str(), "--native-lifecycle", nullptr);
      else execl(program.c_str(), program.c_str(), "--enclave-lifecycle", dll.c_str(), nullptr);
      _exit(127);
    }
    close(to[0]); close(from[1]); input = to[1]; output = from[0];
    if (pid < 0) return Bad("Cannot start public lifecycle client.");
    // Nonblocking descriptors make the deadline apply to both partial reads
    // and writes. The caller ignores SIGPIPE before launching this test helper.
    if (fcntl(input, F_SETFL, O_NONBLOCK) || fcntl(output, F_SETFL, O_NONBLOCK)) return Bad("Cannot configure test pipes.");
    return absl::OkStatus();
  }
  absl::Status Transfer(bool sending, void* bytes, size_t size) {
    auto* p = static_cast<char*>(bytes);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(120);
    while (size) {
      if (std::chrono::steady_clock::now() >= deadline) return Bad("Lifecycle pipe timed out.");
      pollfd descriptor{sending ? input : output, static_cast<short>(sending ? POLLOUT : POLLIN), 0};
      const int ready = poll(&descriptor, 1, 1000);
      if (ready < 0 && errno == EINTR) continue;
      if (ready < 0) return Bad("Lifecycle poll failed.");
      if (!ready) continue;
      const ssize_t n = sending ? write(input, p, size) : read(output, p, size);
      if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
      if (n <= 0) return Bad("Lifecycle pipe closed unexpectedly; inspect backend log.");
      p += n; size -= n;
    }
    return absl::OkStatus();
  }
  absl::Status Finish() {
    close(input); input = -1;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (std::chrono::steady_clock::now() < deadline) {
      int status = 0;
      const auto result = waitpid(pid, &status, WNOHANG);
      if (result == pid) {
        pid = -1;
        return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? absl::OkStatus() : Bad("Lifecycle client exited unsuccessfully.");
      }
      if (result < 0 && errno != EINTR) return Bad("Cannot reap lifecycle client.");
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return Bad("Lifecycle client did not exit.");
  }
};
}  // namespace

absl::Status RunPublicLifecycle(const std::string& program, const std::string& dll,
    const std::string& log, const wire::PublicMaterialTestRequest& request,
    AuthenticatedInstaller& installer, wire::RawMaterial& raw, int corruption) {
  Child child;
  RLWE_RETURN_IF_ERROR(child.Start(program, dll, log));
  wire::PublicLifecycleInput input{}; input.request = request;
  memcpy(input.pinned_server_key, installer.PublicKey().data(), 65);
  memcpy(input.server_epoch, installer.Epoch().data(), 32);
  if (corruption == 3) input.pinned_server_key[0] = 0;
  RLWE_RETURN_IF_ERROR(child.Transfer(true, &input, sizeof(input)));
  int32_t status = 0;
  RLWE_RETURN_IF_ERROR(child.Transfer(false, &status, sizeof(status)));
  if (status != 0) return Bad("Lifecycle preparation rejected; inspect backend log for enclave stage and HRESULT.");
  RLWE_RETURN_IF_ERROR(child.Transfer(false, &raw, sizeof(raw)));
  wire::InstallationBinding binding{};
  RLWE_RETURN_IF_ERROR(child.Transfer(false, &binding, sizeof(binding)));
  auto wrong = binding; wrong.server_epoch[0] ^= 1;
  if (installer.Install(raw, wrong).ok()) return Bad("Installer accepted wrong server epoch.");
  wrong = binding; wrong.material_digest[0] ^= 1;
  if (installer.Install(raw, wrong).ok()) return Bad("Installer accepted wrong material hash.");
  RLWE_ASSIGN_OR_RETURN(auto ack, installer.Install(raw, binding));
  RLWE_ASSIGN_OR_RETURN(auto retried, installer.Install(raw, binding));
  if (memcmp(&ack, &retried, sizeof(ack))) return Bad("Installation retry was not byte-identical.");
  wrong = binding; wrong.client_nonce[0] ^= 1;
  if (installer.Install(raw, wrong).ok()) return Bad("Installer accepted changed binding for same material.");
  if (corruption == 1) ack.signature[0] ^= 1;
  if (corruption == 2) ack.binding.client_nonce[0] ^= 1;
  if (corruption == 4) ack.version++;
  RLWE_RETURN_IF_ERROR(child.Transfer(true, &ack, sizeof(ack)));
  RLWE_RETURN_IF_ERROR(child.Transfer(false, &status, sizeof(status)));
  if ((corruption == 0 && status != 0) || (corruption != 0 && status >= 0)) return Bad("Unexpected installation authentication result.");
  return child.Finish();
}
}  // namespace hintless_pir::vbs
