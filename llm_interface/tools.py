import logging
from langchain_core.tools import tool
from external.introspector import Introspector

logger = logging.getLogger(__name__)

introspector = Introspector()


@tool(parse_docstring=True)
def function_cross_references(project_name: str, function_signature: str) -> str:
    """Retrieves the calling functions (with their signatures and headers) for a given function signature.

    Args:
        project_name (str): The target project or library name where the function is defined. Examples: "tinyxml2", "libxml2", "json-c", "libplist"
        function_signature (str): The signature of the function to analyze. You can obtain function signatures using the `get_all_functions` method.

    Returns:
        str: A formatted string containing:
            - Function signature
            - List of caller functions with their signatures and headers
            Returns empty string if no information is found.

    Examples:
        >>> function_cross_references("tinyxml2", "XMLAttribute * tinyxml2::XMLElement::FindOrCreateAttribute(const char *)")
        Function signature: XMLAttribute * tinyxml2::XMLElement::FindOrCreateAttribute(const char *)
        Called by:
        1. void tinyxml2::XMLElement::SetAttribute(const char *, const char *)
            Headers: /src/tinyxml2/tinyxml2.h
    """
    if not function_signature:
        logger.info(f"Tool(function_cross_references): No function signature provided")
        return ""

    # Get cross references (functions that call this function)
    callers = introspector.get_function_cross_references(
        project_name=project_name, function_signature=function_signature
    )

    # Format the output
    result = [f"Function signature: {function_signature}"]

    if callers:
        result.append("Called by:")
        for i, caller in enumerate(callers, 1):
            caller_signature = caller.get("src_func_signature", caller.get("src_func", ""))
            caller_headers = caller.get("possible_header_files", [])
            result.append(f"{i}. {caller_signature}")
            if caller_headers:
                result.append(f"   Headers: {', '.join(caller_headers)}")
    else:
        result.append("No functions call this function")

    final_result = "\n".join(result)
    logger.info(f"Tool(function_cross_references): Information for {function_signature}: {final_result}")
    return final_result


@tool(parse_docstring=True)
def get_all_functions(project_name: str) -> str:
    """Retrieves all functions with their signatures, headers, and coverage from a project.

    Args:
        project_name (str): The target project or library name where the functions are defined. Examples: "tinyxml2", "libxml2", "json-c", "libplist"

    Returns:
        str: A formatted string containing all functions in the project, with each function represented by:
            - Function signature: The human-readable function signature
            - Possible header files: A list of possible header files for the function
            - Runtime coverage percent: The runtime coverage percentage. Useful for prioritizing low-coverage functions for testing.
            Returns empty string if no functions are found.

    Examples:
        >>> get_all_functions("tinyxml2")
        Function signature: XMLNode * tinyxml2::XMLElement::ShallowClone(XMLDocument *)
        Possible header files: ['/src/tinyxml2/tinyxml2.h']
        Runtime coverage percent: 0.0%

        Function signature: void tinyxml2::XMLElement::SetAttribute(const char *, const char *)
        Possible header files: ['/src/tinyxml2/tinyxml2.h']
        Runtime coverage percent: 10.5%
    """
    functions = introspector.get_all_functions(project_name=project_name)

    if not functions:
        logger.info(f"Tool(get_all_functions): No functions found for {project_name}")
        return ""

    # Format the output
    result = []
    for func in functions:
        result.extend(
            [
                f"Function signature: {func['function_signature']}",
                f"Possible header files: {func.get('possible_header_files', [])}",
                f"Runtime coverage percent: {func.get('runtime_coverage_percent', 0.0)}%",
                "",  # Empty line for better readability
            ]
        )

    final_result = "\n".join(result).strip()
    logger.info(f"Tool(get_all_functions): Found {len(functions)} functions for {project_name}")
    return final_result


tools = [function_cross_references, get_all_functions]