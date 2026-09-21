// Linux/WSL local validation harness. Three ordinary processes, no TEE.
#include "local_material/protocol.h"

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <iostream>
#include <poll.h>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "shell_encryption/status_macros.h"

namespace hintless_pir::local_material {
namespace {

constexpr uint32_t kMaxFrame = 64 * 1024 * 1024;
bool ReadAll(int fd, char* buffer, size_t size) {
  while (size) {
    pollfd descriptor{fd, POLLIN, 0};
    // Large database preprocessing can take minutes in an unoptimized build.
    // The driver keeps EOF/error handling and owns worker cleanup.
    const int ready = poll(&descriptor, 1, 600000);
    if (ready < 0 && errno == EINTR) continue;
    if (ready <= 0) return false;
    const auto n = read(fd, buffer, size);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return false;
    buffer += n; size -= n;
  }
  return true;
}
bool WriteAll(int fd, const char* buffer, size_t size) {
  while (size) {
    const auto n = write(fd, buffer, size);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return false;
    buffer += n; size -= n;
  }
  return true;
}
bool ReadFrame(int fd, WorkerMessage& message) {
  uint32_t length;
  if (!ReadAll(fd, reinterpret_cast<char*>(&length), sizeof(length))) return false;
  length = ntohl(length);
  if (length > kMaxFrame) return false;
  std::string bytes(length, '\0');
  return ReadAll(fd, bytes.data(), bytes.size()) && message.ParseFromString(bytes);
}
bool WriteFrame(int fd, const WorkerMessage& message) {
  const std::string bytes = message.SerializeAsString();
  if (bytes.size() > kMaxFrame) return false;
  uint32_t length = htonl(bytes.size());
  return WriteAll(fd, reinterpret_cast<const char*>(&length), sizeof(length)) &&
         WriteAll(fd, bytes.data(), bytes.size());
}

class Role {
 public:
  Role(std::string name, Parameters params)
      : name_(std::move(name)), params_(std::move(params)) {}
  absl::StatusOr<WorkerMessage> Dispatch(const WorkerMessage& in) {
    WorkerMessage out;
    const auto& params = params_;
    const auto& command = in.command();
    if (command == "init") {
      if (server_ || client_ || generator_) return absl::FailedPreconditionError("Already initialized.");
      if (name_ == "server") {
        RLWE_ASSIGN_OR_RETURN(server_, PreparedServer::Create(params));
        *out.mutable_public_params() = server_->PublicParams();
        *out.mutable_generator_config() = MakeGeneratorConfig(params, out.public_params());
      } else if (name_ == "client") {
        RLWE_ASSIGN_OR_RETURN(client_, PreparedClient::Create(params, in.public_params()));
      } else if (name_ == "generator") {
        generator_ = std::make_unique<LocalMaterialGenerator>(params, in.generator_config());
      } else return absl::InvalidArgumentError("Unknown role.");
    } else if (name_ == "server" && server_) {
      if (command == "install") {
        RLWE_ASSIGN_OR_RETURN(*out.mutable_receipt(), server_->Install(in.material()));
      } else if (command == "query") {
        const auto start = std::chrono::steady_clock::now();
        RLWE_ASSIGN_OR_RETURN(*out.mutable_response(), server_->Handle(in.query()));
        out.set_elapsed_ms(std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - start).count());
      } else if (command == "expected") {
        // Explicit test oracle. Never expose this in a deployment.
        RLWE_ASSIGN_OR_RETURN(*out.mutable_record(), server_->ExpectedRecord(in.index()));
      } else if (command == "release") {
        RLWE_RETURN_IF_ERROR(server_->Release(in.material_id()));
      } else return absl::InvalidArgumentError("Server command rejected.");
    } else if (name_ == "generator" && generator_) {
      if (command != "generate") return absl::InvalidArgumentError("Generator accepts no query/index commands.");
      RLWE_ASSIGN_OR_RETURN(*out.mutable_material(), generator_->Generate(in.preparation()));
      *out.mutable_receipt() = MakeReceipt(out.material());
    } else if (name_ == "client" && client_) {
      if (command == "prepare") {
        RLWE_ASSIGN_OR_RETURN(*out.mutable_preparation(), client_->BeginPreparation());
      } else if (command == "ready") {
        // The generated receipt is carried separately from the server receipt.
        Receipt generated;
        if (!generated.ParseFromString(in.record())) return absl::InvalidArgumentError("Missing generator receipt.");
        RLWE_RETURN_IF_ERROR(client_->AcceptReady(generated, in.receipt()));
      } else if (command == "query") {
        RLWE_ASSIGN_OR_RETURN(*out.mutable_query(), client_->GenerateQuery(in.material_id(), in.index()));
      } else if (command == "recover") {
        RLWE_ASSIGN_OR_RETURN(*out.mutable_record(), client_->Recover(in.response()));
      } else if (command == "retry") {
        RLWE_ASSIGN_OR_RETURN(*out.mutable_query(), client_->Retry(in.material_id()));
      } else return absl::InvalidArgumentError("Client command rejected.");
    } else return absl::FailedPreconditionError("Initialize this worker first.");
    return out;
  }
 private:
  std::string name_;
  Parameters params_;
  std::unique_ptr<PreparedServer> server_;
  std::unique_ptr<PreparedClient> client_;
  std::unique_ptr<LocalMaterialGenerator> generator_;
};

int WorkerLoop(const std::string& name, const std::string& profile) {
  auto params = ParametersForProfile(profile);
  if (!params.ok()) return 2;
  Role role(name, *params);
  WorkerMessage input;
  while (ReadFrame(STDIN_FILENO, input)) {
    auto result = role.Dispatch(input);
    WorkerMessage output;
    if (result.ok()) output = std::move(*result);
    else output.set_error(std::string(result.status().message()));
    if (!WriteFrame(STDOUT_FILENO, output)) return 2;
    // Protobuf buffers and upstream library copies are not reliably erased.
    input.Clear();
  }
  return 0;
}

class Process {
 public:
  Process(const char* executable, const char* role, const char* profile) {
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) != 0) throw std::runtime_error("socketpair failed");
    pid_ = fork();
    if (pid_ < 0) { close(sockets[0]); close(sockets[1]); throw std::runtime_error("fork failed"); }
    if (pid_ == 0) {
      if (dup2(sockets[1], STDIN_FILENO) < 0 || dup2(sockets[1], STDOUT_FILENO) < 0) _exit(126);
      close(sockets[0]); close(sockets[1]);
      execl(executable, executable, role, profile, static_cast<char*>(nullptr));
      _exit(127);
    }
    close(sockets[1]); fd_ = sockets[0];
  }
  ~Process() {
    close(fd_);
    int status;
    // The local driver owns only this child. A bounded wait prevents a
    // failed experiment from leaving hidden workers behind.
    for (int i = 0; i < 20; ++i) {
      const auto result = waitpid(pid_, &status, WNOHANG);
      if (result == pid_ || (result < 0 && errno == ECHILD)) return;
      usleep(10000);
    }
    kill(pid_, SIGTERM);
    while (waitpid(pid_, &status, 0) < 0 && errno == EINTR) {}
  }
  Process(const Process&) = delete;
  Process& operator=(const Process&) = delete;
  WorkerMessage Call(const WorkerMessage& request) {
    WorkerMessage response;
    if (!WriteFrame(fd_, request) || !ReadFrame(fd_, response)) throw std::runtime_error("Worker IPC failed or timed out.");
    bytes += 8 + request.ByteSizeLong() + response.ByteSizeLong();
    if (response.has_error()) throw std::runtime_error(response.error());
    return response;
  }
  uint64_t bytes = 0;
 private:
  int fd_;
  pid_t pid_;
};

WorkerMessage Command(const char* name) { WorkerMessage m; m.set_command(name); return m; }

int RunDemo(const char* executable, int queries, const char* profile) {
  auto parameters = ParametersForProfile(profile);
  if (!parameters.ok()) throw std::runtime_error(std::string(parameters.status().message()));
  const auto params = *parameters;
  // The coordinator is trusted test instrumentation; it sees every message.
  Process server(executable, "server", profile), client(executable, "client", profile), generator(executable, "generator", profile);
  auto setup = server.Call(Command("init"));
  auto init = Command("init");
  *init.mutable_public_params() = setup.public_params();
  client.Call(init);
  init = Command("init");
  *init.mutable_generator_config() = setup.generator_config();
  generator.Call(init);
  uint64_t seeds = 0, ready = 0, online_up = 0, online_down = 0, internal = 0, release = 0;
  uint64_t static_rlwe = 0, online_rlwe = 0;
  for (const auto& hint : setup.public_params().linpir_response_hints()) static_rlwe += hint.ByteSizeLong();
  int index = 1;
  std::vector<double> prepare_ms, query_ms, server_ms, server_compute_ms;
  for (int i = 0; i < queries; ++i) {
    auto start = std::chrono::steady_clock::now();
    auto prep = client.Call(Command("prepare"));
    seeds += prep.preparation().ByteSizeLong();
    auto request = Command("generate");
    *request.mutable_preparation() = prep.preparation();
    auto generated = generator.Call(request);
    internal += generated.material().ByteSizeLong();
    auto install = Command("install");
    *install.mutable_material() = generated.material();
    auto installed = server.Call(install);
    ready += generated.receipt().ByteSizeLong() + installed.receipt().ByteSizeLong();
    auto confirm = Command("ready");
    *confirm.mutable_receipt() = installed.receipt();
    confirm.set_record(generated.receipt().SerializeAsString());
    client.Call(confirm);
    prepare_ms.push_back(std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count());

    // Decide the next index only after preparation; later queries depend on
    // previous results. The generator never receives the index or the query.
    start = std::chrono::steady_clock::now();
    request = Command("query");
    request.set_material_id(prep.preparation().material_id());
    request.set_index(index);
    auto query = client.Call(request);
    online_up += query.query().ByteSizeLong();
    request = Command("query");
    *request.mutable_query() = query.query();
    const auto server_start = std::chrono::steady_clock::now();
    auto response = server.Call(request);
    server_ms.push_back(std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - server_start).count());
    server_compute_ms.push_back(response.elapsed_ms());
    online_down += response.response().ByteSizeLong();
    for (const auto& limb : response.response().pir_response().linpir_responses()) online_rlwe += limb.ByteSizeLong();
    request = Command("recover");
    *request.mutable_response() = response.response();
    auto recovered = client.Call(request);
    query_ms.push_back(std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count());
    request = Command("expected"); request.set_index(index);
    if (recovered.record() != server.Call(request).record()) throw std::runtime_error("Incorrect retrieval.");
    uint64_t selector = 0;
    for (unsigned char byte : recovered.record()) selector = (selector << 8) | byte;
    index = selector % (params.db_rows * params.db_cols);
    request = Command("release"); request.set_material_id(prep.preparation().material_id());
    release += request.ByteSizeLong();
    server.Call(request);
  }
  std::cout << "{\n  \"backend\": \"" << kBackend << "\",\n"
            << "  \"hardware_attested\": false,\n  \"secure_erasure_validated\": false,\n"
            << "  \"security_parameters_validated\": false,\n"
            << "  \"profile\": \"" << profile << "\",\n"
            << "  \"database_bytes\": " << params.db_rows * params.db_cols * params.db_record_bit_size / 8 << ",\n"
            << "  \"lwe_secret_dimension\": " << params.lwe_secret_dim << ",\n"
            << "  \"queries_correct\": " << queries << ",\n"
            << "  \"public_setup_payload_bytes\": " << setup.public_params().ByteSizeLong() << ",\n"
            << "  \"seed_provisioning_payload_bytes\": " << seeds << ",\n"
            << "  \"readiness_receipts_payload_bytes\": " << ready << ",\n"
            << "  \"online_query_payload_bytes\": " << online_up << ",\n"
            << "  \"online_response_payload_bytes\": " << online_down << ",\n"
            << "  \"static_rlwe_component_payload_bytes\": " << static_rlwe << ",\n"
            << "  \"online_rlwe_component_payload_bytes\": " << online_rlwe << ",\n"
            << "  \"release_control_payload_bytes\": " << release << ",\n"
            << "  \"server_internal_material_payload_bytes\": " << internal << ",\n"
            << "  \"generator_public_config_payload_bytes\": " << setup.generator_config().ByteSizeLong() << ",\n"
            << "  \"logical_client_payload_total_bytes\": " << setup.public_params().ByteSizeLong() + seeds + ready + online_up + online_down + release << ",\n"
            << "  \"all_worker_ipc_framed_bytes_including_test_oracle\": " << server.bytes + client.bytes + generator.bytes << ",\n"
            << "  \"attestation_and_private_channel_bytes\": null,\n"
            << "  \"prepare_with_local_ipc_ms\": [";
  for (int i = 0; i < queries; ++i) std::cout << (i ? ", " : "") << prepare_ms[i];
  std::cout << "],\n  \"server_with_local_ipc_ms\": [";
  for (int i = 0; i < queries; ++i) std::cout << (i ? ", " : "") << server_ms[i];
  std::cout << "],\n  \"server_compute_ms\": [";
  for (int i = 0; i < queries; ++i) std::cout << (i ? ", " : "") << server_compute_ms[i];
  std::cout << "],\n  \"online_with_local_ipc_ms\": [";
  for (int i = 0; i < queries; ++i) std::cout << (i ? ", " : "") << query_ms[i];
  std::cout << "]\n}\n";
  return 0;
}
}  // namespace
}  // namespace hintless_pir::local_material

int main(int argc, char** argv) {
  signal(SIGPIPE, SIG_IGN);
  try {
    if (argc >= 2 && std::string(argv[1]) != "demo") {
      return hintless_pir::local_material::WorkerLoop(argv[1], argc >= 3 ? argv[2] : "functional");
    }
    const int queries = argc >= 3 ? std::stoi(argv[2]) : 5;
    if (queries < 1 || queries > 10000) throw std::runtime_error("Query count must be 1..10000.");
    // /proc/self/exe works for both bazel run and direct invocation.
    return hintless_pir::local_material::RunDemo("/proc/self/exe", queries, argc >= 4 ? argv[3] : "functional");
  } catch (const std::exception& error) {
    std::cerr << "Local validation failed: " << error.what() << '\n';
    return 1;
  }
}
