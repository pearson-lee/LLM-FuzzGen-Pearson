from langgraph.checkpoint.memory import MemorySaver
import config.config as config
import logging
import re
import time
from typing import Literal, TypedDict, List
from langchain.schema import HumanMessage
from .tools import tools
from typing import Annotated
from langgraph.prebuilt import ToolNode, tools_condition
from langgraph.graph import StateGraph, add_messages, START, END
from langgraph.graph.state import CompiledStateGraph
import langchain_google_vertexai as langchain_vertexai
import langchain_google_genai as langchain_genai

logger = logging.getLogger(__name__)


class State(TypedDict):
    messages: Annotated[list, add_messages]
    parsed: str


class LLMClient:
    def __init__(self):
        try:
            llm_base = langchain_genai.ChatGoogleGenerativeAI(
                temperature=config.TEMPERATURE,
                model=config.MODEL_NAME,
                max_output_tokens=config.MAX_TOKENS,
                thinking_budget=config.THINK_BUDGET_TOKEN,
                safety_settings={
                    langchain_genai.HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: langchain_genai.HarmBlockThreshold.OFF,
                    langchain_genai.HarmCategory.HARM_CATEGORY_UNSPECIFIED: langchain_genai.HarmBlockThreshold.OFF,
                    langchain_genai.HarmCategory.HARM_CATEGORY_TOXICITY: langchain_genai.HarmBlockThreshold.OFF,
                    langchain_genai.HarmCategory.HARM_CATEGORY_HATE_SPEECH: langchain_genai.HarmBlockThreshold.OFF,
                    langchain_genai.HarmCategory.HARM_CATEGORY_VIOLENCE: langchain_genai.HarmBlockThreshold.OFF,
                    langchain_genai.HarmCategory.HARM_CATEGORY_CIVIC_INTEGRITY: langchain_genai.HarmBlockThreshold.OFF,
                    langchain_genai.HarmCategory.HARM_CATEGORY_DANGEROUS: langchain_genai.HarmBlockThreshold.OFF,
                    langchain_genai.HarmCategory.HARM_CATEGORY_HARASSMENT: langchain_genai.HarmBlockThreshold.OFF,
                    langchain_genai.HarmCategory.HARM_CATEGORY_DEROGATORY: langchain_genai.HarmBlockThreshold.OFF,
                    langchain_genai.HarmCategory.HARM_CATEGORY_MEDICAL: langchain_genai.HarmBlockThreshold.OFF,
                    langchain_genai.HarmCategory.HARM_CATEGORY_SEXUAL: langchain_genai.HarmBlockThreshold.OFF,
                    langchain_genai.HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: langchain_genai.HarmBlockThreshold.OFF,
                },
                max_retries=10,
            )

            # llm_base = langchain_vertexai.ChatVertexAI(
            #     model=config.MODEL_NAME,
            #     temperature=config.TEMPERATURE,
            #     max_tokens=config.MAX_TOKENS,
            #     max_retries=10,
            #     thinking_budget=config.THINK_BUDGET_TOKEN,
            #     safety_settings={
            #         langchain_vertexai.HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: langchain_vertexai.HarmBlockThreshold.OFF,
            #         langchain_vertexai.HarmCategory.HARM_CATEGORY_UNSPECIFIED: langchain_vertexai.HarmBlockThreshold.OFF,
            #         langchain_vertexai.HarmCategory.HARM_CATEGORY_HATE_SPEECH: langchain_vertexai.HarmBlockThreshold.OFF,
            #         langchain_vertexai.HarmCategory.HARM_CATEGORY_CIVIC_INTEGRITY: langchain_vertexai.HarmBlockThreshold.OFF,
            #         langchain_vertexai.HarmCategory.HARM_CATEGORY_HARASSMENT: langchain_vertexai.HarmBlockThreshold.OFF,
            #         langchain_vertexai.HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: langchain_vertexai.HarmBlockThreshold.OFF,
            #     },
            #     project="ordinal-oxygen-lz9rc",
            #     location="global",
            # )

            self._llm_without_tools = llm_base
            self._llm = llm_base.bind_tools(tools=tools, tool_choice="auto")

            self._graph = self._build_graph()

        except Exception as e:
            logger.error(f"LLM initialization failed: {e}")
            raise

    def _generate_node(self, state: State) -> dict:
        logger.info(f"Generating prompt from messages...")
        try:
            # retry if the LLM response is empty
            for attempt in range(10):
                res = self._llm.invoke(state["messages"])
                if res.content or res.tool_calls:
                    return {"messages": [res]}
                else:
                    sleep_time = 30 * attempt
                    logger.warning(
                        f"LLM response empty on attempt {attempt + 1}. Retrying... {sleep_time} seconds, raw response: {res}",
                        exc_info=True,
                    )
                    time.sleep(sleep_time)

            # If all attempts fail, raise an exception
            raise Exception("LLM generation failed after multiple retries.")

        except Exception as e:
            logger.error(f"LLM generation failed: {e}")
            raise

    def _parse_node(self, state: State) -> dict:
        content = state["messages"][-1].content
        if not content:
            parsed = ""
        else:
            if isinstance(content, list):
                content = " ".join(str(item) for item in content)
            match = re.search(r"```(?:c|cpp|c\+\+)\n(.*?)```", content, re.DOTALL)
            parsed = match.group(1).strip() if match else content.strip()
        return {"parsed": parsed}

    def _should_continue(self, state: State) -> Literal["tools", "parse"]:
        messages = state["messages"]
        last_message = messages[-1]
        if last_message.tool_calls:
            return "tools"
        return "parse"

    def _build_graph(self) -> CompiledStateGraph:
        """Builds and compiles the LangGraph workflow."""
        workflow = StateGraph(State)
        workflow.add_node("generate", self._generate_node)
        workflow.add_node("tools", ToolNode(tools))
        workflow.add_node("parse", self._parse_node)

        workflow.set_entry_point("generate")
        workflow.add_conditional_edges(source="generate", path=self._should_continue)
        workflow.add_edge("tools", "generate")
        workflow.set_finish_point("parse")

        return workflow.compile(checkpointer=MemorySaver())

    def generate(self, prompt: str, thread_id: int) -> str | None:
        """Generate response using the LangGraph workflow."""
        if not prompt:
            logger.warning("Generate called with empty prompt.")
            return None
        logger.info(f"Generating response for prompt: {prompt[:300]}...")
        try:
            message = HumanMessage(content=prompt)
            config_thread_id = thread_id if thread_id else int(time.time())
            final_state = self._graph.invoke({"messages": [message]}, config={"configurable": {"thread_id": config_thread_id}})
            result = final_state.pop("parsed", "")
            logger.info(f"\nfuzz target: \n{result}")

            return result
        except Exception as e:
            logger.error(f"LangGraph invocation failed: {e}")
            return None

    def generate_seeds(self, prompt: str) -> List[str] | None:
        """Generates a list of seed strings using the LLM, expecting Markdown format."""
        if not prompt:
            logger.warning("Generate_seeds called with empty prompt.")
            return None

        logger.info(f"Generating seeds for prompt: {prompt[:300]}...")
        for i in range(3):
            try:
                response = self._llm_without_tools.invoke([HumanMessage(content=prompt)])
                response_content = getattr(response, "content", "").strip()
                if response_content:
                    # First, try to extract content within <seeds> tags
                    seeds_block_match = re.search(r"<seeds>(.*?)</seeds>", response_content, re.DOTALL)
                    if seeds_block_match:
                        response_content = seeds_block_match.group(1).strip()

                    if seeds := [s.strip() for s in re.findall(r"```(.*?)```", response_content, re.DOTALL) if s.strip()]:
                        logger.info(f"Successfully generated {len(seeds)} seeds. Seeds: {seeds}")
                        return seeds

                logger.warning(f"No seeds extracted from LLM response, retrying..., raw response: {response}")
            except Exception as e:
                logger.error(f"Attempt {i+1}/3 failed: {e}", exc_info=True)

        return None

    def generate_dict(self, prompt: str) -> str | None:
        if not prompt:
            logger.warning("Generate_dict called with empty prompt.")
            return None
        logger.info(f"Generating dict for prompt: {prompt[:300]}...")

        for i in range(3):
            try:
                response = self._llm_without_tools.invoke([HumanMessage(content=prompt)])
                if response and response.content:
                    # Use regex to extract content within ```text ... ```
                    if match := re.search(r"```(?:text)?\n(.*?)\n```", response.content, re.DOTALL):
                        dict_content = match.group(1).strip()
                        logger.info("Successfully extracted dictionary content.")
                        return dict_content

                    logger.warning(
                        f"Could not find ```text ... ``` block in LLM response, retrying..., raw response: {response.content}"
                    )

                else:
                    logger.warning(f"Empty LLM response, retrying..., raw response: {response.content}")

            except Exception as e:
                logger.error(f"Dictionary generation failed: {e}", exc_info=True)

        return None
