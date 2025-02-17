import logging
import re

from langchain_google_genai import ChatGoogleGenerativeAI

import config.config as config

logger = logging.getLogger(__name__)


class LLMClient:
    def __init__(self):
        try:
            self._llm = ChatGoogleGenerativeAI(
                temperature=config.TEMPERATURE,
                model=config.MODEL_NAME,
                max_tokens=config.MAX_TOKENS,
                api_key=config.API_KEY,
            )
        except Exception as e:
            logger.error(f"LLM initialization failed: {e}")
            raise

    def _parse_code_block(text: str) -> str:
        """Extract code block from text or return stripped text."""
        match = re.search(r"```(?:c|cpp|c\+\+)\n(.*?)```", text, re.DOTALL)
        return match.group(1).strip() if match else text.strip()

    def generate(self, prompt: str) -> str | None:
        """Generate response using the configured LLM."""
        logger.info(f"Generating response for prompt (first 100 chars): {prompt[:100]}...")
        try:
            response = self._llm.invoke(prompt).content
            logger.info(f"Generated response: \n{response}\n")
            return self._parse_code_block(response)
        except Exception as e:
            logger.error(f"Generation failed: {e}")
            return None
