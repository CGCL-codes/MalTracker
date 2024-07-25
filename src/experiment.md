#### experiment
1. get all package and install all the dependencies
2. split the pkgs with the call graph and locate the malicious snippet manually
3. get feature from the snippet with PDG and group detection

#### config

base_dirname: core-odgenfast

* pkgs: ../../data/(malware/test/popular)
* snippets: ../snippets/*
* feature: ../PDGFeature/*
* tools:
    * jelly: ../res/jelly/src/main.ts
        ts-node ../res/jelly/src/main.ts --callgraph-json {self.cg_json} {self.base_path}
    * fast: ../../tools/fast/generate_graph.py
        python ../../tools/fast/generate_graph.py -a -no {self.node_path} -eo {self.edge_path} {self.target_file_path}



1. call graph (jelly)
    * cg_json: ./tmp/cg/json/{file_name}.json
    * coped_file: ./tmp/cg/CopedPackage.txt
    
2. pdg (fast)
    * node_path: ./tmp/fast/{file_name}_node.tsv
    * edge_path: ./tmp/fast/{file_name}_rel.tsv
    * target_file: ./tmp/fast/{file_name}
3. ./log/*