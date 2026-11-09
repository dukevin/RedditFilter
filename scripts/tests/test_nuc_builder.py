from pathlib import Path
import plistlib
import stat
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from nuc_builder import normalize_base
from nuc_tool import load_commands, needs_insert


class PackagingTests(unittest.TestCase):
    def test_patched_base_preserves_native_extensions_and_removes_only_owned_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / "source.ipa", Path(directory) / "output.ipa"
            app = "Payload/Reddit.app/"
            info = {"CFBundleExecutable": "Reddit", "ALTBundleIdentifier": "old",
                    "CFBundleURLTypes": [{"CFBundleURLSchemes": ["reddit", "redditfilter"]},
                                         {"CFBundleURLSchemes": ["redditfilter"]}]}
            native = app + "PlugIns/Share.appex/Info.plist"
            safari = app + "PlugIns/RedditFilterSafari.appex/old.js"
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr(app + "Info.plist", plistlib.dumps(info))
                archive.writestr(app + "Reddit", b"native binary")
                archive.writestr(native, b"native extension")
                archive.writestr(safari, b"obsolete extension file")
                archive.writestr(app + "Frameworks/RedditFilter.dylib", b"old filter")
                archive.writestr(app + "Frameworks/RedditSideloadFix.dylib", b"old fix")
            normalize_base(source, output)
            with zipfile.ZipFile(output) as archive:
                rebuilt = plistlib.loads(archive.read(app + "Info.plist"))
                self.assertNotIn("ALTBundleIdentifier", rebuilt)
                self.assertEqual(rebuilt["CFBundleURLTypes"], [{"CFBundleURLSchemes": ["reddit"]}])
                self.assertEqual(archive.read(native), b"native extension")
                self.assertEqual(archive.read(app + "Reddit"), b"native binary")
                self.assertNotIn(safari, archive.namelist())
                self.assertNotIn(app + "Frameworks/RedditFilter.dylib", archive.namelist())

    def test_duplicate_zip_entry_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / "source.ipa", Path(directory) / "output.ipa"
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr("duplicate", b"one")
                with self.assertWarns(UserWarning):
                    archive.writestr("duplicate", b"two")
            with self.assertRaisesRegex(ValueError, "duplicate ZIP"):
                normalize_base(source, output)

    def test_existing_loads_are_skipped_and_duplicates_or_mixed_slices_rejected(self):
        text = """binary:
Load command 0
          cmd LC_RPATH
      cmdsize 48
         path @executable_path/Frameworks (offset 12)
Load command 1
          cmd LC_LOAD_WEAK_DYLIB
      cmdsize 56
         name @rpath/RedditFilter.dylib (offset 24)
Load command 2
          cmd LC_LOAD_DYLIB
         name /usr/lib/libSystem.B.dylib (offset 24)
"""
        self.assertEqual(load_commands(text, "LC_RPATH", "path"), ["@executable_path/Frameworks"])
        self.assertEqual(load_commands(text, "LC_LOAD_WEAK_DYLIB", "name"), ["@rpath/RedditFilter.dylib"])
        self.assertFalse(needs_insert([1, 1]))
        self.assertTrue(needs_insert([0, 0]))
        for counts in [[], [2], [0, 1], [1, 2]]:
            with self.assertRaises(ValueError):
                needs_insert(counts)

    def test_symlink_entry_is_rejected_before_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / "source.ipa", Path(directory) / "output.ipa"
            with zipfile.ZipFile(source, "w") as archive:
                link = zipfile.ZipInfo("Payload/link")
                link.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(link, "../../outside")
            with self.assertRaisesRegex(ValueError, "symlinks"):
                normalize_base(source, output)


if __name__ == "__main__":
    unittest.main()
