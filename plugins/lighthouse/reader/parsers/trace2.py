import collections
from ..coverage_file import CoverageFile


class TraceData2(CoverageFile):
    """
    An instruction (or basic block) address trace log parser.
    Format: `<address> <count>`
    """

    def __init__(self, filepath):
        self._hitmap = {}
        super(TraceData2, self).__init__(filepath)

    def get_addresses(self, module_name=None):
        return self._hitmap.keys()

    def _parse(self):
        """
        Parse absolute address coverage from the given log file.
        """
        hitmap = collections.defaultdict(int)
        with open(self.filepath) as f:
            for line in f:
                parts = line.split()
                addr = int(parts[0], 16)
                count = int(parts[1])
                hitmap[addr] += count

        self._hitmap = hitmap
