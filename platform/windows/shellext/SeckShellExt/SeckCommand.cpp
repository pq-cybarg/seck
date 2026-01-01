// Plan-16 Windows Shellext: implementation of the "Analyze with seck"
// IExplorerCommand. For each selected item, opens an inheritable HANDLE
// and launches seck.exe with --handle=<N> via
// CreateProcessW(EXTENDED_STARTUPINFO_PRESENT) +
// PROC_THREAD_ATTRIBUTE_HANDLE_LIST. The path NEVER appears in argv.

#include "SeckCommand.h"
#include <shellapi.h>
#include <memory>
#include <string>

using namespace Microsoft::WRL;

class SeckCommand : public RuntimeClass<RuntimeClassFlags<ClassicCom>, IExplorerCommand> {
public:
    IFACEMETHODIMP GetTitle(IShellItemArray*, LPWSTR* name) override {
        *name = (LPWSTR)CoTaskMemAlloc((wcslen(L"Analyze with seck") + 1) * sizeof(wchar_t));
        if (!*name) return E_OUTOFMEMORY;
        wcscpy_s(*name, wcslen(L"Analyze with seck") + 1, L"Analyze with seck");
        return S_OK;
    }
    IFACEMETHODIMP GetIcon(IShellItemArray*, LPWSTR* icon) override { *icon = nullptr; return E_NOTIMPL; }
    IFACEMETHODIMP GetToolTip(IShellItemArray*, LPWSTR* tt) override { *tt = nullptr; return E_NOTIMPL; }
    IFACEMETHODIMP GetCanonicalName(GUID* g) override { *g = CLSID_SeckCommand; return S_OK; }
    IFACEMETHODIMP GetState(IShellItemArray*, BOOL, EXPCMDSTATE* state) override {
        *state = ECS_ENABLED;
        return S_OK;
    }
    IFACEMETHODIMP GetFlags(EXPCMDFLAGS* f) override { *f = ECF_DEFAULT; return S_OK; }
    IFACEMETHODIMP EnumSubCommands(IEnumExplorerCommand** e) override {
        *e = nullptr;
        return E_NOTIMPL;
    }

    IFACEMETHODIMP Invoke(IShellItemArray* items, IBindCtx*) override {
        DWORD count = 0;
        if (!items) return E_INVALIDARG;
        items->GetCount(&count);

        for (DWORD i = 0; i < count; ++i) {
            // WRL ComPtr — no extra dep (wil is not on the stock VS 2022
            // install path; we previously imported wil/com.h which broke
            // the msbuild step in CI).
            ComPtr<IShellItem> item;
            if (FAILED(items->GetItemAt(i, &item))) continue;

            LPWSTR path = nullptr;
            if (FAILED(item->GetDisplayName(SIGDN_FILESYSPATH, &path))) continue;

            SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
            HANDLE h = CreateFileW(
                path, GENERIC_READ, FILE_SHARE_READ, &sa,
                OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
            CoTaskMemFree(path);
            if (h == INVALID_HANDLE_VALUE) continue;

            // Build STARTUPINFOEXW with PROC_THREAD_ATTRIBUTE_HANDLE_LIST = { h }
            SIZE_T attrSize = 0;
            InitializeProcThreadAttributeList(nullptr, 1, 0, &attrSize);
            auto attrBuf = std::make_unique<unsigned char[]>(attrSize);
            auto attrList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attrBuf.get());
            if (!InitializeProcThreadAttributeList(attrList, 1, 0, &attrSize)) {
                CloseHandle(h); continue;
            }
            HANDLE handleList[1] = { h };
            if (!UpdateProcThreadAttribute(
                    attrList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                    handleList, sizeof(handleList), nullptr, nullptr)) {
                DeleteProcThreadAttributeList(attrList);
                CloseHandle(h); continue;
            }

            STARTUPINFOEXW si{};
            si.StartupInfo.cb = sizeof(si);
            si.lpAttributeList = attrList;
            PROCESS_INFORMATION pi{};

            // Compose: seck.exe analyze --handle=<N>
            wchar_t cmd[256];
            swprintf_s(cmd, L"seck.exe analyze --handle=%llu",
                       static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(h)));

            BOOL ok = CreateProcessW(
                nullptr, cmd, nullptr, nullptr, TRUE,
                EXTENDED_STARTUPINFO_PRESENT,
                nullptr, nullptr,
                reinterpret_cast<LPSTARTUPINFOW>(&si), &pi);
            DeleteProcThreadAttributeList(attrList);
            CloseHandle(h);
            if (ok) {
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
            }
        }
        return S_OK;
    }
};

CoCreatableClass(SeckCommand);
