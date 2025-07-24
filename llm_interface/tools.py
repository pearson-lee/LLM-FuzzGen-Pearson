import logging
import threading
from langchain_core.tools import tool
from external.introspector import Introspector
from external.oss_fuzz import OSSFuzz

logger = logging.getLogger(__name__)

introspector = Introspector()
oss_fuzz = OSSFuzz()
coverage_lock = threading.Lock()


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
        project_name (str): The target project or library name. Examples: "tinyxml2", "cjson"
        function_signature (str): The signature of the function to analyze.

    Returns:
        str: A formatted string containing:
            - Function signature
            - List of caller functions with their signatures and headers
            Returns a message if no callers are found.
    """
    project_name = project_name.lower()
    logger.info(f"Tool(function_cross_references): project_name='{project_name}', function_signature='{function_signature}'")
    if not function_signature:
        msg = "Tool(function_cross_references): No function signature provided"
        logger.warning(msg)
        return msg

    # Get cross references (functions that call this function)
    callers = introspector.get_function_cross_references(project_name=project_name, function_signature=function_signature)

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
    logger.info(
        f"Retrieved, Tool(function_cross_references): function_signature='{function_signature}', callers_found={len(callers)}"
    )
    return final_result


@tool(parse_docstring=True)
def search_function(project_name: str, function_name_pattern: str) -> str:
    """Searches for functions in a project that match a given name pattern and retrieves their source code.
    Examples:
        >>> search_function("tinyxml2", "SetAttribute")
        Function signature: void tinyxml2::XMLElement::SetAttribute(const char *, const char *)
        Possible header files: ['/src/tinyxml2/tinyxml2.h']
        Source location: /src/tinyxml2/tinyxml2.h:1467:1470
        Source code:
        void XMLElement::SetAttribute( const char* name, const char* value )
        {
            XMLAttribute* a = FindOrCreateAttribute( name );
            a->SetAttribute( value );
        }

    Args:
        project_name (str): The target project or library name. Examples: "tinyxml2", "cjson"
        function_name_pattern (str): The pattern to search for in function names. Can be a substring.

    Returns:
        str: A formatted string of all matching functions, including their signature, header files, source location, and source code. Returns a message if no functions are found.

    """
    project_name = project_name.lower()
    logger.info(f"Tool(search_function): project_name='{project_name}', function_name_pattern='{function_name_pattern}'")
    all_functions = introspector.get_all_functions(project_name=project_name)

    if not all_functions:
        msg = f"No functions found for {project_name}"
        logger.info(f"Tool(search_function): {msg}")
        return msg

    # Filter functions based on the name pattern
    matched_functions = [func for func in all_functions if function_name_pattern in func["function_name"]]

    if not matched_functions:
        msg = f"No functions matching '{function_name_pattern}' found for {project_name}"
        logger.info(f"Tool(search_function): {msg}")
        return msg

    # Format the output
    result = []
    for func in matched_functions:
        function_signature = func["function_signature"]
        function_filename = func.get("function_filename", "")
        source_line_begin = func.get("source_line_begin", 0)
        source_line_end = func.get("source_line_end", 0)

        # Format source location as filepath:start_line:end_line
        source_location = ""
        if function_filename and source_line_begin > 0 and source_line_end > 0:
            source_location = f"{function_filename}:{source_line_begin}:{source_line_end}"
        elif function_filename:
            source_location = function_filename
        else:
            source_location = "(Source location not available)"

        # Get source code for this function
        source_code = introspector.function_source_code(project_name=project_name, function_signature=function_signature)

        result.extend(
            [
                f"Function signature: {function_signature}",
                f"Possible header files: {func.get('possible_header_files', [])}",
                f"Source location: {source_location}",
                "Source code:",
                source_code if source_code else "(Source code not available)",
                "",  # Empty line for better readability
            ]
        )

    final_result = "\n".join(result).strip()
    logger.info(
        f"Retrieved, Tool(search_function): function_name_pattern='{function_name_pattern}', functions_found={len(matched_functions)}"
    )
    return final_result


@tool(parse_docstring=True)
def project_source_code(project_name: str, filepath: str, begin_line: int = 1, end_line: int = 9999) -> str:
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
        project_name (str): The target project or library name. Examples: "tinyxml2", "cjson"
        filepath (str): Path to the file within the project, e.g., "/src/tinyxml2/tinyxml2.cpp".
        begin_line (int, optional): Starting line number (inclusive, 1-based).
        end_line (int, optional): Ending line number (inclusive, 1-based).

    Returns:
        str: The source code of the specified file (or line range). Returns an empty string if the file is not found, or a message if the filepath is not provided.
    """
    project_name = project_name.lower()
    logger.info(
        f"Tool(project_source_code): project_name='{project_name}', filepath='{filepath}', begin_line={begin_line}, end_line={end_line}"
    )
    if not filepath:
        msg = "No filepath provided"
        logger.warning(f"Tool(project_source_code): {msg}")
        return msg

    # Retrieve the specified line range
    source_code = introspector.get_project_source_code(
        project_name=project_name, filepath=filepath, begin_line=begin_line, end_line=end_line
    )
    logger.info(
        f"Retrieved, Tool(project_source_code): project_name='{project_name}', filepath='{filepath}', begin_line={begin_line}, end_line={end_line}"
    )
    return source_code


@tool(parse_docstring=True)
def get_line_coverage_report(project_name: str, function_name_pattern: str) -> str:
    """
    Retrieves a detailed, line-by-line coverage report for functions within a project that match a specific name pattern.
    Examples:
        To get the coverage for a single function:
        >>> get_line_coverage_report(project_name='cJSON', function_name_pattern='compare_double')
        cJSON.c:compare_double:
        547|     45|{
        548|     45|    double maxVal = fabs(a) > fabs(b) ? fabs(a) : fabs(b);
        ------------------
        |  Branch (548:21): [True: 13, False: 32]
        ------------------
        549|     45|    return (fabs(a - b) <= maxVal * DBL_EPSILON);
        550|     45|}

        To get the coverage for multiple functions using a '|' separator:
        >>> get_line_coverage_report(project_name='cJSON', function_name_pattern='compare_double|suffix_object')
        cJSON.c:suffix_object:
        1947|   389k|{
        1948|   389k|    prev->next = item;
        1949|   389k|    item->prev = prev;
        1950|   389k|}
        cJSON.c:compare_double:
        547|  84.9k|{
        548|  84.9k|    double maxVal = fabs(a) > fabs(b) ? fabs(a) : fabs(b);
        ------------------
        |  Branch (548:21): [True: 20.9k, False: 64.0k]
        ------------------
        549|  84.9k|    return (fabs(a - b) <= maxVal * DBL_EPSILON);
        550|  84.9k|}

    Args:
        project_name (str): The target project or library name. Examples: "tinyxml2", "cjson"
        function_name_pattern (str): A regex pattern to filter function names. Use a '|' separator for multiple functions. This is required to prevent excessive output.

    Returns:
        str: A formatted, line-by-line coverage report for the matching functions, or a message if not found.

    """
    project_name = project_name.lower()
    logger.info(f"Tool(get_line_coverage_report): project_name='{project_name}', function_name_pattern='{function_name_pattern}'")
    with coverage_lock:
        if not all((project_name, function_name_pattern)):
            msg = f"Tool(get_line_coverage_report): Missing required parameters: project_name={project_name}, function_name_pattern={function_name_pattern}"
            logger.warning(msg)
            return msg
        report = oss_fuzz.proj_linecov_reports(proj_name=project_name, fun_name_regex=function_name_pattern)
        if not report:
            msg = f"No coverage report found for pattern '{function_name_pattern}'. Try using a substring of the function name, e.g., 'SetAttribute' instead of 'tinyxml2::XMLElement::SetAttribute'."
            logger.info(f"Tool(get_line_coverage_report): {msg}")
            return msg
        logger.info(
            f"Retrieved, Tool(get_line_coverage_report): project_name='{project_name}', function_name_pattern='{function_name_pattern}'"
        )
        return report


tools = [
    function_cross_references,
    project_source_code,
    get_line_coverage_report,
    search_function,
]
