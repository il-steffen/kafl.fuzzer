"""
SYX workdir/Qemu interface
"""

import os
import shutil


class SyxWorkdir:
    def __init__(self, qemu_id, config):
        self.base_path = config.work_dir + "/syx_workdir_" + str(qemu_id)

    def init_dir(self):
        if os.path.exists(self.base_path):
            shutil.rmtree(self.base_path)
        os.makedirs(self.base_path)

    def result(self):
        return self.base_path + "/sym_results"