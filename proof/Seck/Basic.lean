-- Basic types shared across the model.
namespace Seck

abbrev Bytes := ByteArray

abbrev Fd := Nat

-- Distinguished FDs (matched at runtime by the orchestrator).
def hostStdinSinkFd  : Fd := 3
def sandboxReportFd  : Fd := 5

end Seck
