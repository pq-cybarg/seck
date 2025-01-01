class Seck < Formula
  desc "Sandboxed-LLM file/project analyzer"
  homepage "https://github.com/seck-project/seck"
  version "0.1.0"
  license "AGPL-3.0-or-later"
  on_macos do
    on_arm do
      url "https://github.com/seck-project/seck/releases/download/v#{version}/seck-aarch64-apple-darwin"
      sha256 "REPLACE_AT_RELEASE"
    end
    on_intel do
      url "https://github.com/seck-project/seck/releases/download/v#{version}/seck-x86_64-apple-darwin"
      sha256 "REPLACE_AT_RELEASE"
    end
  end
  on_linux do
    on_arm do
      url "https://github.com/seck-project/seck/releases/download/v#{version}/seck-aarch64-unknown-linux-gnu"
      sha256 "REPLACE_AT_RELEASE"
    end
    on_intel do
      url "https://github.com/seck-project/seck/releases/download/v#{version}/seck-x86_64-unknown-linux-gnu"
      sha256 "REPLACE_AT_RELEASE"
    end
  end
  def install
    bin.install Dir["seck*"][0] => "seck"
  end
  test do
    assert_match "seck", shell_output("#{bin}/seck --version")
  end
end
