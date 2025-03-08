# LLM-FuzzGen

A Large Language Model-based Fuzzing Target Generator.

## System Requirements
- ubuntu 22.04
- python 3.11.11 
- docker

## Installation

1. Clone the repository:
```bash
git clone https://github.com/ch097711/LLM-FuzzGen.git
cd LLM-FuzzGen
```

2. Set up Python environment:
```bash
python3.11 -m venv .venv
source .venv/bin/activate
```

3. Run the installation script:
```bash
chmod +x setup.sh
./setup.sh
```

4. Modify config.yaml

5. Run main.py
```bash
python ./main.py tinyxml2
# or
python ./main.py tinyxml2 pugixml json-c
```