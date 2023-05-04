## CSE534 Final project

### Usage in Mininet

* Setup VM environment as described in [p4lang/tutorials](https://github.com/p4lang/tutorials).
* Under the `tutorials` folder, apply `patch.diff` to enable CPU port for the framework.
* Create a folder under `exercises` folder, copy all files to that folder.
* Modify the flag `MININET` in `controller.py` to `True`.
* `make clean && make run`

### FABRIC testbed Jupyter notebook

* The notebook can be found at `fabric/arp_defense.ipynb`.
* Under `fabric/`, there are also other scripts that helps settings up the environment.

