load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library", "cc_test")

cc_library(
    name = "client_journal",
    srcs = ["client_journal.cc"],
    hdrs = ["client_journal.h"],
    deps = [
        "//local_material:protocol",
        "@com_google_absl//absl/status:statusor",
        "@com_github_google_shell-encryption//shell_encryption:statusor_fork",
    ],
)

cc_test(
    name = "client_journal_test",
    srcs = ["client_journal_test.cc"],
    deps = [
        ":client_journal",
        "//local_material:protocol",
        "@com_github_google_googletest//:gtest_main",
        "@com_github_google_shell-encryption//shell_encryption/testing:status_testing",
    ],
)

cc_library(
    name = "installation_server",
    srcs = ["installation_server.cc"],
    hdrs = ["installation_server.h", "installation.h", "rlwe_material.h"],
    deps = [
        "//local_material:protocol",
        "@boringssl//:crypto",
        "@com_google_absl//absl/status:statusor",
        "@com_github_google_shell-encryption//shell_encryption:montgomery",
        "@com_github_google_shell-encryption//shell_encryption:statusor_fork",
        "@com_github_google_shell-encryption//shell_encryption/rns:rns_context",
        "@com_github_google_shell-encryption//shell_encryption/rns:rns_polynomial",
    ],
)

# Public, deterministic test fixtures only. This runs in Linux, NOT in a TEE.
cc_binary(
    name = "compatibility_oracle",
    srcs = ["compatibility_oracle.cc"],
    deps = [
        "//local_material:protocol",
        "//lwe:sample_error",
        "@boringssl//:crypto",
        "@com_google_absl//absl/status:statusor",
        "@com_github_google_shell-encryption//shell_encryption:montgomery",
        "@com_github_google_shell-encryption//shell_encryption:sample_error",
        "@com_github_google_shell-encryption//shell_encryption/prng:single_thread_hkdf_prng",
    ],
)

cc_binary(
    name = "material_interop_test",
    srcs = ["material_interop_test.cc", "material_test_abi.h", "rlwe_material.h",
            "lifecycle_test_driver.cc", "lifecycle_test_driver.h", "lifecycle_test_abi.h"],
    deps = [
        ":client_journal",
        ":installation_server",
        "//local_material:protocol",
        "//hintless_simplepir:client",
        "//hintless_simplepir:utils",
        "//lwe:lwe_symmetric_encryption",
        "@com_google_absl//absl/status:statusor",
        "@com_github_google_shell-encryption//shell_encryption:montgomery",
        "@com_github_google_shell-encryption//shell_encryption/prng:single_thread_hkdf_prng",
        "@com_github_google_shell-encryption//shell_encryption/rns:finite_field_encoder",
        "@com_github_google_shell-encryption//shell_encryption/rns:rns_context",
        "@com_github_google_shell-encryption//shell_encryption/rns:rns_gadget",
        "@com_github_google_shell-encryption//shell_encryption/rns:rns_polynomial",
        "@com_github_google_shell-encryption//shell_encryption/rns:rns_secret_key",
    ],
)
