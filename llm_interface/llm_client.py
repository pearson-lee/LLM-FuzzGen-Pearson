from langchain_core.runnables import RunnableLambda
from langgraph.checkpoint.memory import MemorySaver
import config.config as config
import logging
import re
import time
from typing import Literal, TypedDict, List
from langchain.schema import HumanMessage, BaseMessage
from .tools import tools
from typing import Annotated
from langgraph.prebuilt import ToolNode
from langgraph.graph import StateGraph, add_messages
from langgraph.graph.state import CompiledStateGraph
import langchain_google_genai as langchain_genai
import langchain_google_vertexai as langchain_vertexai
from langchain_openai import ChatOpenAI

logger = logging.getLogger(__name__)


class State(TypedDict):
    messages: Annotated[list, add_messages]
    parsed: str


# Ensure the response from the LLM is not empty and not just tool calls.
def ensure_response_not_empty(message: BaseMessage) -> BaseMessage:
    """Checks if the AIMessage from the LLM is empty (no content and no tool calls)."""
    has_content = bool(message.content)
    has_tool_calls = bool(getattr(message, "tool_calls", []))
    if has_content or has_tool_calls:
        return message

    logger.error("LLM returned an empty response, raw response: %s", message)
    raise ValueError("LLM returned an empty response.")


class LLMClient:
    def __init__(self, backend: Literal["gemini", "vertexai", "openrouter"] = "gemini"):
        try:
            logger.info(f"Initializing LLM with backend: {backend}")
            if backend == "vertexai":
                llm_base = langchain_vertexai.ChatVertexAI(
                    model=config.MODEL_NAME,
                    temperature=config.TEMPERATURE,
                    max_tokens=config.MAX_TOKENS,
                    thinking_budget=config.THINK_BUDGET_TOKEN,
                    safety_settings={
                        langchain_vertexai.HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: langchain_vertexai.HarmBlockThreshold.OFF,
                        langchain_vertexai.HarmCategory.HARM_CATEGORY_UNSPECIFIED: langchain_vertexai.HarmBlockThreshold.OFF,
                        langchain_vertexai.HarmCategory.HARM_CATEGORY_HATE_SPEECH: langchain_vertexai.HarmBlockThreshold.OFF,
                        langchain_vertexai.HarmCategory.HARM_CATEGORY_CIVIC_INTEGRITY: langchain_vertexai.HarmBlockThreshold.OFF,
                        langchain_vertexai.HarmCategory.HARM_CATEGORY_HARASSMENT: langchain_vertexai.HarmBlockThreshold.OFF,
                        langchain_vertexai.HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: langchain_vertexai.HarmBlockThreshold.OFF,
                    },
                    project="ordinal-oxygen-lz9rc",
                    location="global",
                    # location="us-central1",
                    # location="europe-west1",
                )
            elif backend == "gemini":
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
                )
            elif backend == "openrouter":
                llm_base = ChatOpenAI(
                    model_name="deepseek/deepseek-chat-v3-0324:free",
                    temperature=config.TEMPERATURE,
                    max_tokens=config.MAX_TOKENS,
                    openai_api_key="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",
                    openai_api_base="https://openrouter.ai/api/v1",
                    # extra_body={
                    #     "provider": {"only": ["moonshotai"]},
                    # },
                )
            else:
                raise ValueError(f"Unsupported LLM backend: {backend}")

            validator = RunnableLambda(ensure_response_not_empty)
            retry_attempt = 10

            pipeline_without_tools = llm_base | validator
            self._llm_without_tools = pipeline_without_tools.with_retry(stop_after_attempt=retry_attempt)

            pipeline_with_tools = llm_base.bind_tools(tools=tools) | validator
            self._llm = pipeline_with_tools.with_retry(stop_after_attempt=retry_attempt)

            self._graph = self._build_graph()
            logger.info("LLMClient initialized successfully.")

        except Exception as e:
            logger.error(f"LLM initialization failed: {e}")
            raise

    def _generate_node(self, state: State) -> dict:
        logger.info(f"Generating prompt from messages...")
        res = self._llm.invoke(state["messages"])
        return {"messages": [res]}

    def _parse_node(self, state: State) -> dict:
        content = state["messages"][-1].content
        if not content:
            return {"parsed": ""}

        if isinstance(content, list):
            content = " ".join(str(item) for item in content)

        match = re.search(r"<fuzz_target>(.*?)</fuzz_target>", content, re.DOTALL)
        if match:
            parsed = match.group(1).strip()
        else:
            logger.warning(f"Could not find <fuzz_target> tag in response. Returning full content. Response: {content[:500]}")
            parsed = content.strip()

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
        try:
            response = self._llm_without_tools.invoke([HumanMessage(content=prompt)])
            if response_content := getattr(response, "content", "").strip():
                if seeds_block_match := re.search(r"<seeds>(.*?)</seeds>", response_content, re.DOTALL):
                    response_content = seeds_block_match.group(1).strip()

                if seeds := [s.strip() for s in re.findall(r"```(.*?)```", response_content, re.DOTALL) if s.strip()]:
                    logger.info(f"Successfully generated {len(seeds)} seeds. Seeds: {seeds}")
                    return seeds

            logger.warning(f"No seeds extracted from LLM response. Raw response: {response}")
            return None
        except Exception as e:
            logger.error(f"Seed generation failed after all retries: {e}", exc_info=True)
            return None

    def generate_dict(self, prompt: str) -> str | None:
        if not prompt:
            logger.warning("Generate_dict called with empty prompt.")
            return None
        logger.info(f"Generating dict for prompt: {prompt[:300]}...")

        try:
            response = self._llm_without_tools.invoke([HumanMessage(content=prompt)])
            if response and response.content:
                if match := re.search(r"```(?:text)?\n(.*?)\n```", response.content, re.DOTALL):
                    dict_content = match.group(1).strip()
                    logger.info("Successfully extracted dictionary content.")
                    return dict_content

                logger.warning(f"Could not find ```text ... ``` block in LLM response. Raw response: {response.content}")
                return None
            else:
                logger.warning(f"Empty LLM response. Raw response: {response.content}")
                return None
        except Exception as e:
            logger.error(f"Dictionary generation failed after all retries: {e}", exc_info=True)
            return None
