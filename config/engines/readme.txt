You can add multiple engine definitions under this path (./engines/*.yaml)

If you need to tune them for different runmodes, you can for example duplicate the engine definition and change the name accordingly.
Somehting like

engines:
  - engine: "suricata102"
    ...
  - engine: "suricata102-sanitize"
    ... set different paths
  - engine: "suricata102-xtract"
    ... set different paths
