"""Nautilus extension: adds 'Analyze with seck' to the Files context menu.

CRITICAL: this script does NOT pass file paths via shell expansion. It
invokes gdbus, which serializes the path as a single D-Bus method
argument — bytes, not shell-interpreted.
"""

import gi

gi.require_version("Nautilus", "4.0")
from gi.repository import Nautilus, GObject  # type: ignore
import subprocess  # noqa: E402


class SeckExtension(GObject.GObject, Nautilus.MenuProvider):
    def get_file_items(self, files):
        if not files:
            return []
        item = Nautilus.MenuItem(
            name="SeckExtension::Analyze",
            label="Analyze with seck",
            tip="Run sandboxed LLM analysis",
        )
        item.connect("activate", self.on_activate, files)
        return [item]

    def get_background_items(self, current_folder):
        return self.get_file_items([current_folder])

    def on_activate(self, _menu, files):
        for f in files:
            uri = f.get_uri()
            if uri.startswith("file://"):
                path = uri[7:]
                subprocess.Popen([
                    "gdbus", "call", "--session",
                    "--dest", "net.seck.Analyze",
                    "--object-path", "/net/seck/Analyze",
                    "--method", "net.seck.Analyze.AnalyzePath",
                    path,
                ])
