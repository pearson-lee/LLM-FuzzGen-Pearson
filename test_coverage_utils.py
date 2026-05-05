import unittest

from blocker_process.coverage_utils import get_line_execution_count


class LineCovParserTest(unittest.TestCase):
    def test_extracts_from_cpp_function_section(self) -> None:
        report = """tinyxml2::XMLAttribute::ParseDeep(char*, bool, int*):
 1443|  11.7k|{
 1444|       |    // comment
 1445|  11.7k|    p = _name.ParseName( p );
"""
        count = get_line_execution_count(
            report,
            1445,
            function_name="tinyxml2::XMLAttribute::ParseDeep(char*, bool, int*)",
        )
        self.assertEqual(count, "11.7k")

    def test_extracts_from_c_function_section_with_file_prefix(self) -> None:
        report = """ftsystem.c:FT_New_Memory:
  404|      2|  {
  405|      2|    FT_Memory  memory;
ftsystem.c:ft_alloc:
  110|  78.5k|  {
  111|  78.5k|    FT_UNUSED( memory );
"""
        count = get_line_execution_count(report, 110, function_name="ft_alloc")
        self.assertEqual(count, "78.5k")

    def test_falls_back_to_single_file_report(self) -> None:
        report = """/src/cjson/cJSON.c:
   99|  5.68k|{
  100|  5.68k|    if (!cJSON_IsString(item))
  101|  3.87k|    {
"""
        count = get_line_execution_count(report, 100, function_name="cJSON_GetStringValue")
        self.assertEqual(count, "5.68k")

    def test_prefers_matching_function_section_when_line_numbers_repeat(self) -> None:
        report = """ftsystem.c:FT_New_Memory:
  404|      2|  {
  405|      2|    FT_Memory  memory;
other.c:unrelated:
  404|     99|  {
  405|     99|    return;
"""
        count = get_line_execution_count(report, 404, function_name="FT_New_Memory")
        self.assertEqual(count, "2")


if __name__ == "__main__":
    unittest.main()
