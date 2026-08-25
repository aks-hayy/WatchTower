# Third-Party Notices

WatchTower source code is licensed under MIT. Dependencies, synchronized content, and optional external software retain their own licenses and are not relicensed by this repository.

Important boundaries:

- Npcap is downloaded from the official Npcap site when requested and is not redistributed in this repository. Its free Windows installer requires interactive license acceptance.
- Sigma rules synchronized from SigmaHQ remain subject to the licenses and notices in the upstream repository. Synchronized rule checkouts are runtime data and are not committed here.
- Neo4j is an optional external service started from an operator-supplied container image and configuration.
- Ollama and hosted AI providers are optional external products governed by their own terms.
- Python, Rust, and JavaScript packages retain the licenses declared by their respective distributions.

Before distributing a binary bundle, generate a dependency software-bill-of-materials and review every included license for the intended distribution model. This source repository does not bundle Npcap, Sysmon, Neo4j, model weights, or synchronized SigmaHQ content.
