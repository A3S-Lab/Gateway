#!/usr/bin/env python3
"""Regenerate Formula/a3s-gateway.rb with new version and sha256 values."""
import os
import sys

ver             = os.environ["VER"]
sha_macos_arm64 = os.environ["SHA_MACOS_ARM64"]
sha_macos_x64   = os.environ["SHA_MACOS_X64"]
sha_linux_arm64 = os.environ["SHA_LINUX_ARM64"]
sha_linux_x64   = os.environ["SHA_LINUX_X64"]

base = f"https://github.com/A3S-Lab/Gateway/releases/download/v{ver}"

formula = (
    'class A3sGateway < Formula\n'
    '  desc "AI-native API gateway — SSE streaming, scale-to-zero, safe model rollouts"\n'
    '  homepage "https://github.com/A3S-Lab/Gateway"\n'
    f'  version "{ver}"\n'
    '  license "MIT"\n'
    '\n'
    '  on_macos do\n'
    '    on_arm do\n'
    f'      url "{base}/a3s-gateway-v{ver}-aarch64-apple-darwin.tar.gz"\n'
    f'      sha256 "{sha_macos_arm64}"\n'
    '    end\n'
    '    on_intel do\n'
    f'      url "{base}/a3s-gateway-v{ver}-x86_64-apple-darwin.tar.gz"\n'
    f'      sha256 "{sha_macos_x64}"\n'
    '    end\n'
    '  end\n'
    '\n'
    '  on_linux do\n'
    '    on_arm do\n'
    f'      url "{base}/a3s-gateway-v{ver}-aarch64-unknown-linux-musl.tar.gz"\n'
    f'      sha256 "{sha_linux_arm64}"\n'
    '    end\n'
    '    on_intel do\n'
    f'      url "{base}/a3s-gateway-v{ver}-x86_64-unknown-linux-musl.tar.gz"\n'
    f'      sha256 "{sha_linux_x64}"\n'
    '    end\n'
    '  end\n'
    '\n'
    '  def install\n'
    '    bin.install "a3s-gateway"\n'
    '  end\n'
    '\n'
    '  test do\n'
    '    assert_match "a3s-gateway", shell_output("#{bin}/a3s-gateway --version")\n'
    '  end\n'
    'end\n'
)

out = "Formula/a3s-gateway.rb"
with open(out, "w") as f:
    f.write(formula)
print(f"Written {out} for v{ver}")
