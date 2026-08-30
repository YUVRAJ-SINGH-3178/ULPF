"""
Drain3 Online Template Miner Subsystem
Streaming online prefix-tree miner for clustering unknown log formats and extracting variable parameters.
"""

import os
from typing import Any

from drain3 import TemplateMiner
from drain3.masking import MaskingInstruction
from drain3.template_miner_config import TemplateMinerConfig


class Drain3Engine:
    """
    Online streaming template miner for discovering structural templates in unseen log formats.
    """

    def __init__(self, persistence_dir: str = "data/drain3_state"):
        os.makedirs(persistence_dir, exist_ok=True)
        self.persistence_dir = persistence_dir
        
        # Configure Drain3 with cybersecurity domain maskers
        config = TemplateMinerConfig()
        config.drain_depth = 4
        config.drain_sim_th = 0.5
        config.drain_max_children = 100
        config.mask_prefix = "<"
        config.mask_suffix = ">"
        config.masking_instructions = [
            MaskingInstruction(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", "IP"),
            MaskingInstruction(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", "UUID"),
            MaskingInstruction(r"\b[0-9a-fA-F]{32,64}\b", "HEX"),
            MaskingInstruction(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b", "TIMESTAMP"),
            MaskingInstruction(r'"[^"]*"', "STR"),
            MaskingInstruction(r"\b\d+\b", "NUM")
        ]

        self.miner = TemplateMiner(config=config)

    def mine_log(self, raw_message: str) -> dict[str, Any]:
        """
        Processes a raw log line, updates the prefix tree, and returns the cluster result.
        """
        cleaned = raw_message.strip()
        result = self.miner.add_log_message(cleaned)
        
        template = result.get("template_mined") if isinstance(result, dict) else str(result)
        cluster_id = result.get("cluster_id") if isinstance(result, dict) else 1
        change_type = result.get("change_type", "none") if isinstance(result, dict) else "cluster_created"
        
        cluster = self.miner.drain.id_to_cluster.get(cluster_id)
        cluster_size = cluster.size if cluster else 1
        sample_messages = [cleaned]

        return {
            "cluster_id": cluster_id,
            "template": template,
            "cluster_size": cluster_size,
            "change_type": change_type,
            "sample_message": cleaned
        }

    def match_template(self, raw_message: str) -> dict[str, Any] | None:
        """Matches a message against existing mined templates."""
        cleaned = raw_message.strip()
        cluster = self.miner.match(cleaned)
        if cluster:
            params = self.miner.extract_parameters(cluster.get_template(), cleaned)
            return {
                "cluster_id": cluster.cluster_id,
                "template": cluster.get_template(),
                "cluster_size": cluster.size,
                "parameters": params or []
            }
        return None
