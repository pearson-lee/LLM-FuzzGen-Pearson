import logging
from langchain_core.tools import tool
from external.introspector import Introspector

logger = logging.getLogger(__name__)

introspector = Introspector()


@tool(parse_docstring=True)
def function_cross_references(project_name: str, function_signature: str) -> str:
    """Retrieves the calling functions (with their signatures and headers) for a given function signature.
    Examples:
        >>> function_cross_references("tinyxml2", "XMLAttribute * tinyxml2::XMLElement::FindOrCreateAttribute(const char *)")
        Function signature: XMLAttribute * tinyxml2::XMLElement::FindOrCreateAttribute(const char *)
        Called by:
        1. void tinyxml2::XMLElement::SetAttribute(const char *, const char *)
            Headers: /src/tinyxml2/tinyxml2.h

    Args:
        project_name (str): The target project or library name where the function is defined. Examples: "tinyxml2", "libxml2", "json-c", "libplist"
        function_signature (str): The signature of the function to analyze.

    Returns:
        str: A formatted string containing:
            - Function signature
            - List of caller functions with their signatures and headers
            Returns empty string if no information is found.
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


# @tool(parse_docstring=True)
# def get_all_functions(project_name: str) -> str:
#     """Retrieves all functions with their signatures, headers, and coverage from a project.

#     Args:
#         project_name (str): The target project or library name where the functions are defined. Examples: "tinyxml2", "libxml2", "json-c", "libplist"

#     Returns:
#         str: A formatted string containing all functions in the project, with each function represented by:
#             - Function signature: The human-readable function signature
#             - Possible header files: A list of possible header files for the function
#             - Runtime coverage percent: The runtime coverage percentage. Useful for prioritizing low-coverage functions for testing.
#             Returns empty string if no functions are found.

#     Examples:
#         >>> get_all_functions("tinyxml2")
#         Function signature: XMLNode * tinyxml2::XMLElement::ShallowClone(XMLDocument *)
#         Possible header files: ['/src/tinyxml2/tinyxml2.h']
#         Runtime coverage percent: 0.0%

#         Function signature: void tinyxml2::XMLElement::SetAttribute(const char *, const char *)
#         Possible header files: ['/src/tinyxml2/tinyxml2.h']
#         Runtime coverage percent: 10.5%
#     """
#     functions = introspector.get_all_functions(project_name=project_name)

#     if not functions:
#         logger.info(f"Tool(get_all_functions): No functions found for {project_name}")
#         return ""

#     # Format the output
#     result = []
#     for func in functions:
#         result.extend(
#             [
#                 f"Function signature: {func['function_signature']}",
#                 f"Possible header files: {func.get('possible_header_files', [])}",
#                 f"Runtime coverage percent: {func.get('runtime_coverage_percent', 0.0)}%",
#                 "",  # Empty line for better readability
#             ]
#         )

#     final_result = "\n".join(result).strip()
#     logger.info(f"Tool(get_all_functions): Found {len(functions)} functions for {project_name}")
#     return final_result


@tool(parse_docstring=True)
def function_source_code(project_name: str, function_signature: str) -> str:
    """Retrieves the source code for a given function signature.
    Examples:
        >>> function_source_code("tinyxml2", "XMLAttribute * tinyxml2::XMLElement::FindOrCreateAttribute(const char *)")
        (returns the source code for the function XMLAttribute * tinyxml2::XMLElement::FindOrCreateAttribute(const char *))
        >>> function_source_code("astc-encoder", "void write_bits(unsigned int, unsigned int, unsigned int, uint8_t *)")
        (returns the source code for the function void write_bits(unsigned int, unsigned int, unsigned int, uint8_t *))

    Args:
        project_name (str): The target project or library name where the function is defined. Examples: "tinyxml2", "libxml2", "json-c", "libplist"
        function_signature (str): The signature of the function to retrieve source code for.

    Returns:
        str: The source code of the function, or an empty string if not found.
    """
    if not function_signature:
        logger.info(f"Tool(function_source_code): No function signature provided")
        return ""

    source_code = introspector.function_source_code(
        project_name=project_name, function_signature=function_signature
    )
    logger.info(f"Tool(function_source_code): Retrieved source code for {function_signature}")
    return source_code


@tool(parse_docstring=True)
def project_source_code(
    project_name: str, filepath: str, begin_line: int = None, end_line: int = None
) -> str:
    """
    Retrieve the source code of a specific file in a project, with optional line range selection.

    - If only project_name and filepath are provided, returns the entire file content.
    - If both begin_line and end_line are provided, returns the content for the specified line range (1-based, inclusive).

    Examples:
        >>> project_source_code("tinyxml2", "/src/tinyxml2/tinyxml2.cpp")
        (returns the full source code of /src/tinyxml2/tinyxml2.cpp)
        >>> project_source_code("tinyxml2", "/src/tinyxml2/tinyxml2.cpp", 10, 20)
        (returns the source code from line 10 to 20)

    Args:
        project_name (str): Target project or library name, e.g., "tinyxml2", "libxml2", "json-c", "libplist".
        filepath (str): Path to the file within the project, e.g., "/src/tinyxml2/tinyxml2.cpp".
        begin_line (int, optional): Starting line number (inclusive, 1-based).
        end_line (int, optional): Ending line number (inclusive, 1-based).

    Returns:
        str: The source code of the specified file (or line range), or an empty string if not found.
    """
    if not filepath:
        logger.info(f"Tool(project_source_code): No filepath provided")
        return ""

    # If no line range is specified, retrieve the entire file
    if begin_line is None or end_line is None:
        source_code = introspector.get_project_source_code(
            project_name=project_name, filepath=filepath, begin_line=1, end_line=9999
        )
        logger.info(f"Tool(project_source_code): Retrieved full source code for {project_name}:{filepath}")
        return source_code

    # Retrieve the specified line range
    source_code = introspector.get_project_source_code(
        project_name=project_name, filepath=filepath, begin_line=begin_line, end_line=end_line
    )
    logger.info(
        f"Tool(project_source_code): Retrieved source code for {project_name}:{filepath} lines {begin_line}-{end_line}"
    )
    return source_code


tools = [function_cross_references, function_source_code, project_source_code]
