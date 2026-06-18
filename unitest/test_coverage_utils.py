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


    def test_source_file_lookup_avoids_cross_file_collision(self) -> None:
        # Simulates project.linecovreport where the same line number appears in
        # multiple file sections. The first occurrence (grammar.c) has an empty count;
        # the correct one (optimize.c) has a real hit count.
        report = """/src/libpcap/grammar.c:
 2021|       |   1752, 1753, 1755,
/src/libpcap/gencode.c:
 2021|    901|   b0 = gen_cmp(cstate, OR_LINKTYPE, 0, ETHERTYPE_IPV6);
/src/libpcap/optimize.c:
 2018|  4.49M|   if (JT(b) == JF(b)) {
 2021|  1.63M|   diffp = &JT(*diffp);
/src/libpcap/pcap-linux.c:
 2021|      0|   case ARPHRD_LOOPBACK:
"""
        # Without source_file: global fallback returns the first (empty) entry
        count_no_sf = get_line_execution_count(report, 2021, function_name="and_pullup")
        self.assertEqual(count_no_sf, "")

        # With source_file: correctly returns the optimize.c hit count
        count_with_sf = get_line_execution_count(
            report, 2021, function_name="and_pullup", source_file="optimize.c"
        )
        self.assertEqual(count_with_sf, "1.63M")

    def test_source_file_suffix_match(self) -> None:
        # source_file as relative path should still match the absolute path section header
        report = """/src/libpcap/grammar.c:
 2021|       |   1752, 1753,
/src/libpcap/optimize.c:
 2021|  1.63M|   diffp = &JT(*diffp);
"""
        count = get_line_execution_count(
            report, 2021, function_name="and_pullup", source_file="libpcap/optimize.c"
        )
        self.assertEqual(count, "1.63M")

    def test_source_file_cpp_template_any_nonzero(self) -> None:
        # In C++ reports, the same line can appear multiple times (template instantiations).
        # Any non-zero count means the line was covered.
        report = """/src/mylib/foo.cc:
 42|      0|   return process<int>(x);
 42|    123|   return process<double>(x);
"""
        count = get_line_execution_count(
            report, 42, function_name="process", source_file="foo.cc"
        )
        self.assertEqual(count, "123")


if __name__ == "__main__":
    unittest.main()
