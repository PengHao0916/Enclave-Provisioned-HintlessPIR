load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library", "cc_test")
load("@rules_proto//proto:defs.bzl", "proto_library")

package(default_visibility = ["//visibility:public"])
licenses(["notice"])

proto_library(
    name = "serialization_proto",
    srcs = ["serialization.proto"],
    deps = [
        "//hintless_simplepir:serialization_proto",
        "@com_github_google_shell-encryption//shell_encryption/rns:serialization_proto",
    ],
)
cc_proto_library(name = "serialization_cc_proto", deps = [":serialization_proto"])

cc_library(
    name = "protocol",
    srcs = ["protocol.cc"],
    hdrs = ["protocol.h"],
    deps = [
        ":serialization_cc_proto",
        "//hintless_simplepir:client",
        "//hintless_simplepir:server",
        "//hintless_simplepir:parameters",
        "//hintless_simplepir:utils",
        "//linpir:client",
        "//lwe:lwe_symmetric_encryption",
        "@boringssl//:crypto",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_github_google_shell-encryption//shell_encryption:int256",
        "@com_github_google_shell-encryption//shell_encryption:statusor_fork",
        "@com_github_google_shell-encryption//shell_encryption/prng:single_thread_hkdf_prng",
        "@com_github_google_shell-encryption//shell_encryption/prng:single_thread_chacha_prng",
    ],
)

cc_test(
    name = "protocol_test",
    srcs = ["protocol_test.cc"],
    deps = [
        ":protocol",
        "@com_github_google_googletest//:gtest_main",
        "@com_github_google_shell-encryption//shell_encryption/testing:status_testing",
    ],
)

cc_binary(
    name = "local_worker",
    srcs = ["local_worker.cc"],
    deps = [
        ":protocol",
        "@com_github_google_shell-encryption//shell_encryption:statusor_fork",
    ],
)
