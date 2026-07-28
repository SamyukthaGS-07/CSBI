# Vendored Module C — patch notes

Varshan's code is used as-is except one fix needed to run:

* `clustering/label_cluster.py` — added `Tuple` to the typing import
  (`from typing import List, Dict, Any, Tuple`). His original raises
  `NameError: name 'Tuple' is not defined` on import. Tell him to add it upstream.
