#!/usr/bin/env python3
# coding=utf-8
# date 2024-01-30 03:47:12
# author calllivecn <calllivecn@outlook.com>


import unittest
import subprocess
import tempfile
import shutil
import os
from pathlib import Path

import version


TAR_SCRIPT = os.path.abspath(os.path.join(os.path.dirname(__file__), "tar.py"))


class MainTestCase(unittest.TestCase):
    def test_version(self):
        self.assertTrue(hasattr(version, "VERSION"), True)

    def test_tar(self):
        """test tar -vcf t.tar <dir>"""
        pass

    def test_pass(self):
        pass


class TarPyFunctionalTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.srcdir = Path(self.tmpdir) / "src"
        self.srcdir.mkdir()
        # 创建测试文件
        (self.srcdir / "file1.txt").write_text("hello world\n")
        (self.srcdir / "file2.txt").write_text("tar.py test\n")
        (self.srcdir / "subdir").mkdir()
        (self.srcdir / "subdir" / "file3.txt").write_text("subdir file\n")
        self.archive = Path(self.tmpdir) / "test.tar"
        self.archive_zst = Path(self.tmpdir) / "test.tar.zst"
        self.archive_enc = Path(self.tmpdir) / "test.ta"
        self.archive_zst_enc = Path(self.tmpdir) / "test.tza"

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def run_tar(self, args, input=None, env=None):
        cmd = ["python3", TAR_SCRIPT] + args
        result = subprocess.run(
            cmd,
            input=input,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.tmpdir,
            env=env,
            text=True,
        )
        return result

    def test_create_and_extract_tar(self):
        # 创建 tar 包
        result = self.run_tar(["-cf", str(self.archive), str(self.srcdir)])
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertTrue(self.archive.exists())

        # 解包
        extract_dir = Path(self.tmpdir) / "extract"
        extract_dir.mkdir()
        result = self.run_tar(["-xf", str(self.archive), "-C", str(extract_dir)])
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        # 校验文件内容
        self.assertTrue((extract_dir / "src" / "file1.txt").exists())
        self.assertEqual(
            (extract_dir / "src" / "file1.txt").read_text(), "hello world\n"
        )

    def test_create_and_extract_zst(self):
        # 创建 zstd 压缩包
        result = self.run_tar(["-zcf", str(self.archive_zst), str(self.srcdir)])
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertTrue(self.archive_zst.exists())

        # 解包
        extract_dir = Path(self.tmpdir) / "extract_zst"
        extract_dir.mkdir()
        result = self.run_tar(["-zxf", str(self.archive_zst), "-C", str(extract_dir)])
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertTrue((extract_dir / "src" / "file2.txt").exists())
        self.assertEqual(
            (extract_dir / "src" / "file2.txt").read_text(), "tar.py test\n"
        )

    def test_create_and_extract_encrypted(self):
        # 创建加密包
        password = "123456"
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        # 交互式输入密码
        result = self.run_tar(
            ["-ecf", str(self.archive_enc), str(self.srcdir)],
            input=f"{password}\n{password}\n",
            env=env,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertTrue(self.archive_enc.exists())

        # 解包
        extract_dir = Path(self.tmpdir) / "extract_enc"
        extract_dir.mkdir()
        result = self.run_tar(
            ["-exf", str(self.archive_enc), "-C", str(extract_dir)],
            input=f"{password}\n",
            env=env,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertTrue((extract_dir / "src" / "subdir" / "file3.txt").exists())
        self.assertEqual(
            (extract_dir / "src" / "subdir" / "file3.txt").read_text(), "subdir file\n"
        )

    def test_create_and_extract_zst_encrypted(self):
        # 创建压缩加密包
        password = "654321"
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        result = self.run_tar(
            ["-ezcf", str(self.archive_zst_enc), str(self.srcdir)],
            input=f"{password}\n{password}\n",
            env=env,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertTrue(self.archive_zst_enc.exists())

        # 解包
        extract_dir = Path(self.tmpdir) / "extract_zst_enc"
        extract_dir.mkdir()
        result = self.run_tar(
            ["-ezxf", str(self.archive_zst_enc), "-C", str(extract_dir)],
            input=f"{password}\n",
            env=env,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertTrue((extract_dir / "src" / "file1.txt").exists())
        self.assertEqual(
            (extract_dir / "src" / "file1.txt").read_text(), "hello world\n"
        )

    def test_list_tar(self):
        # 创建 tar 包
        result = self.run_tar(["-cf", str(self.archive), str(self.srcdir)])
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        # 列表
        result = self.run_tar(["-tf", str(self.archive)])
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("file1.txt", result.stdout)
        self.assertIn("file2.txt", result.stdout)


if __name__ == "__main__":
    unittest.main()
