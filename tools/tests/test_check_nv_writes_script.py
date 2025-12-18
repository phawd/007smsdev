from tools import check_nv_writes


def test_scan_diff_no_writes():
    safe_diff = """
diff --git a/tools/safe.py b/tools/safe.py
--- a/tools/safe.py
+++ b/tools/safe.py
@@ -1,3 +1,4 @@
-print('No danger here')
"""
    assert check_nv_writes.scan_diff(safe_diff) == 0


def test_scan_diff_with_dangerous_write():
    dangerous_diff = """
diff --git a/tools/maybe.py b/tools/maybe.py
--- a/tools/maybe.py
+++ b/tools/maybe.py
@@ -10,6 +10,7 @@
+nwqmi_nvtl_nv_item_write_cmd(60076, buf, len(buf))
"""
    assert check_nv_writes.scan_diff(dangerous_diff) == 1
