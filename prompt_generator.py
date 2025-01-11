from langchain.prompts import PromptTemplate
from typing import Dict, Literal

TEMPLATE_PATHS = {
    "generator": "prompt_templates/fuzz_target_generator",
    "compile_fail": "prompt_templates/fuzz_target_compile_fail"
}


class PromptGenerator:
    def __init__(self):
        # Load generator template
        with open(TEMPLATE_PATHS["generator"], "r") as f:
            generator_template = f.read()
        self.generator_template = PromptTemplate(
            input_variables=["language", "function_signature","source_code", "headers", "build_script"],
            template=generator_template
        )

        # Load compile fail template
        with open(TEMPLATE_PATHS["compile_fail"], "r") as f:
            compile_fail_template = f.read()
        self.compile_fail_template = PromptTemplate(
            input_variables=["source_code", "error"],
            template=compile_fail_template
        )

    def get_fuzz_target_prompt(self) -> PromptTemplate:
        return self.generator_template

    def get_compile_fail_prompt(self) -> PromptTemplate:
        return self.compile_fail_template
