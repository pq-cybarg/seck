// Plan-16 Windows Shellext: declarations for the "Analyze with seck"
// `IExplorerCommand` handler. Built by `Seck.sln` (msbuild) and packaged
// into the MSIX sparse package alongside `AppxManifest.xml`.
#pragma once

#include <windows.h>
#include <shobjidl_core.h>
#include <wrl.h>

// {A8B0F0C0-8A41-4F8B-B2C2-6F2C5E2C0F01} — pinned identity for the
// AppxManifest.xml registration. Do NOT regenerate; existing installs
// reference this GUID.
extern "C" const GUID __declspec(selectany) CLSID_SeckCommand =
    { 0xa8b0f0c0, 0x8a41, 0x4f8b, { 0xb2, 0xc2, 0x6f, 0x2c, 0x5e, 0x2c, 0x0f, 0x01 } };

class __declspec(uuid("A8B0F0C0-8A41-4F8B-B2C2-6F2C5E2C0F01")) SeckCommand;
