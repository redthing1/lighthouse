from dataclasses import dataclass


@dataclass
class LighthouseUserConfig:
    block_trace_confidence_threshold: float = 0.80
    suspicious_nodes_confidence_threshold: float = 0.02
