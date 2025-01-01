// Standard COM DLL entry points for the Seck shellext.
#include <windows.h>
#include <wrl.h>

using namespace Microsoft::WRL;

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        Module<InProc>::GetModule().Create();
    } else if (reason == DLL_PROCESS_DETACH) {
        Module<InProc>::GetModule().Terminate();
    }
    return TRUE;
}

STDAPI DllCanUnloadNow() {
    return Module<InProc>::GetModule().Terminate() ? S_OK : S_FALSE;
}

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv) {
    return Module<InProc>::GetModule().GetClassObject(rclsid, riid, ppv);
}
