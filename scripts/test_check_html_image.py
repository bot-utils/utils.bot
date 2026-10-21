import unittest

from check_html_image import verify_native_inventory, verify_removed_components


class NativeInventoryTests(unittest.TestCase):
    def setUp(self):
        self.files = {
            '/lib/ld-linux-aarch64.so.1': 'loader-digest',
            '/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1': 'loader-digest',
            '/usr/lib/aarch64-linux-gnu/libc.so.6': 'libc-digest',
        }

    def test_exact_inventory(self):
        verify_native_inventory(self.files, dict(self.files))

    def test_untracked_library_is_rejected(self):
        actual = dict(self.files, **{'/usr/lib/unreviewed.so': 'other'})
        with self.assertRaises(RuntimeError):
            verify_native_inventory(actual, self.files)

    def test_modified_library_is_rejected(self):
        actual = dict(self.files)
        actual['/usr/lib/aarch64-linux-gnu/libc.so.6'] = 'different'
        with self.assertRaises(RuntimeError):
            verify_native_inventory(actual, self.files)

    def test_removing_both_loader_entries_cannot_pass(self):
        missing = {'/usr/lib/aarch64-linux-gnu/libc.so.6': 'libc-digest'}
        with self.assertRaises(RuntimeError):
            verify_native_inventory(missing, missing)

    def test_mixed_loader_bytes_are_rejected(self):
        mixed = dict(self.files)
        mixed['/lib/ld-linux-aarch64.so.1'] = 'other-loader'
        with self.assertRaises(RuntimeError):
            verify_native_inventory(mixed, mixed)

    def test_unused_desktop_libraries_cannot_be_reintroduced(self):
        verify_removed_components({'usr/lib/libglib-2.0.so.0', 'usr/lib/libexpat.so.1'})
        for library in ['libmount.so.1', 'libblkid.so.1', 'libgtk-3.so.0', 'libpango-1.0.so.0', 'libcairo.so.2', 'libcups.so.2', 'libcurl.so.4', 'libvulkan.so.1', 'libatk-bridge-2.0.so.0']:
            with self.assertRaises(RuntimeError):
                verify_removed_components({'usr/lib/aarch64-linux-gnu/' + library})


if __name__ == '__main__':
    unittest.main()
