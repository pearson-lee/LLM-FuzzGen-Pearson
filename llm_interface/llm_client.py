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
from langchain_google_genai import ChatGoogleGenerativeAI, HarmBlockThreshold, HarmCategory
from langgraph.graph import StateGraph, add_messages, START, END
from langgraph.graph.state import CompiledStateGraph
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# --- Output Schema for Seeds ---
class SeedList(BaseModel):
    """A list of seed inputs for fuzzing."""

    seeds: list[str] = Field(description="List of generated seed strings.")


class State(TypedDict):
    messages: Annotated[list, add_messages]
    parsed: str


class LLMClient:
    def __init__(self):
        try:
            llm_base = ChatGoogleGenerativeAI(
                temperature=config.TEMPERATURE,
                model=config.MODEL_NAME,
                max_output_tokens=config.MAX_TOKENS,
                thinking_budget=24575,
                safety_settings={
                    HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
                    HarmCategory.HARM_CATEGORY_UNSPECIFIED: HarmBlockThreshold.BLOCK_NONE,
                    HarmCategory.HARM_CATEGORY_TOXICITY: HarmBlockThreshold.BLOCK_NONE,
                    HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
                    HarmCategory.HARM_CATEGORY_VIOLENCE: HarmBlockThreshold.BLOCK_NONE,
                    HarmCategory.HARM_CATEGORY_CIVIC_INTEGRITY: HarmBlockThreshold.BLOCK_NONE,
                    HarmCategory.HARM_CATEGORY_DANGEROUS: HarmBlockThreshold.BLOCK_NONE,
                    HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
                    HarmCategory.HARM_CATEGORY_DEROGATORY: HarmBlockThreshold.BLOCK_NONE,
                    HarmCategory.HARM_CATEGORY_MEDICAL: HarmBlockThreshold.BLOCK_NONE,
                    HarmCategory.HARM_CATEGORY_SEXUAL: HarmBlockThreshold.BLOCK_NONE,
                    HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
                },
                max_retries=10,
                timeout=300.0,
            )

            self._llm_without_tools = llm_base
            self._llm = llm_base.bind_tools(tools=tools, tool_choice="auto")
            self._seed_generator_llm = llm_base.with_structured_output(schema=SeedList)

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
                    logger.warning(f"LLM response empty on attempt {attempt + 1}. Retrying...")
                    time.sleep(3)

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
            if thread_id:
                final_state = self._graph.invoke(
                    {"messages": [message]}, config={"configurable": {"thread_id": thread_id}}
                )
            else:
                final_state = self._graph.invoke({"messages": [message]})
            result = final_state.pop("parsed", "")
            logger.info(f"\nfuzz target: \n{result}")

            return result
        except Exception as e:
            logger.error(f"LangGraph invocation failed: {e}")
            return None

    def generate_seeds(self, prompt: str) -> List[str] | None:
        """Generates a list of seed strings using the structured output LLM."""
        if not prompt:
            logger.warning("Generate_seeds called with empty prompt.")
            return None
        logger.info(f"Generating seeds for prompt: {prompt[:300]}...")
        try:
            structured_response = self._seed_generator_llm.invoke([HumanMessage(content=prompt)])

            if isinstance(structured_response, SeedList) and structured_response.seeds:
                logger.info(f"Successfully generated {len(structured_response.seeds)} seeds.")
                return structured_response.seeds
            else:
                logger.warning(
                    f"LLM did not return the expected SeedList structure or the list was empty. Response: {structured_response}"
                )
                return None
        except Exception as e:
            logger.error(f"Seed generation failed: {e}")
            return None

    def generate_dict(self, prompt: str) -> str:
        if not prompt:
            logger.warning("Generate_dict called with empty prompt.")
            return None
        logger.info(f"Generating dict for prompt: {prompt[:300]}...")
        try:
            response = self._llm_without_tools.invoke([HumanMessage(content=prompt)])
            if response and response.content:
                # Use regex to extract content within ```text ... ```
                match = re.search(r"```(?:text)?\n(.*?)\n```", response.content, re.DOTALL)
                if match:
                    dict_content = match.group(1).strip()
                    logger.info("Successfully extracted dictionary content.")
                    return dict_content
                else:
                    logger.warning(
                        "Could not find ```text ... ``` block in LLM response. Returning raw content."
                    )
                    return response.content.strip()
            else:
                logger.warning("LLM response was empty.")
                return None

        except Exception as e:
            logger.error(f"Dictionary generation failed: {e}")
            return None
