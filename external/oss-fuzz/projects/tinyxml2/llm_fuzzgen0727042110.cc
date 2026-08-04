#include <cstddef>
#include <cstdint>
#include <string>
#include <unistd.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/tinyxml2/tinyxml2.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Create a temporary file path for file operations.
  const std::string path = std::string("/tmp/") + _FUZZ_TARGET_NAME + ".tmp";

  /*
   * ANALYSIS: The function-level coverage report showed that
   * tinyxml2::XMLUtil::SetBoolSerialization has low branch coverage. The
   * line-level report confirmed that the false branches for the ternary
   * operators at lines 387 and 388 are never taken.
   * IMPLEMENTATION: The following code block calls SetBoolSerialization with
   * null arguments to exercise these uncovered branches.
   */
  if (fdp.ConsumeBool()) {
    tinyxml2::XMLUtil::SetBoolSerialization(nullptr, nullptr);
  } else {
    std::string true_str = fdp.ConsumeRandomLengthString(10);
    std::string false_str = fdp.ConsumeRandomLengthString(10);
    tinyxml2::XMLUtil::SetBoolSerialization(true_str.c_str(), false_str.c_str());
  }

  tinyxml2::XMLDocument doc;

  /*
   * ANALYSIS: The function-level coverage report showed that the
   * tinyxml2::XMLDocument::LoadFile(FILE*) overload has low line and branch
   * coverage. Several error conditions related to file I/O were not being
   * triggered.
   * IMPLEMENTATION: The following code block creates a temporary file with
   * fuzzed data and calls LoadFile with a FILE* to that file. This will
   * exercise the file reading logic in the LoadFile(FILE*) overload.
   */
  std::string xml_data = fdp.ConsumeRemainingBytesAsString();
  FILE* fp = fopen(path.c_str(), "w");
  if (fp) {
    fwrite(xml_data.c_str(), 1, xml_data.size(), fp);
    fclose(fp);
    doc.LoadFile(path.c_str());
  }

  /*
   * ANALYSIS: The line-level coverage for tinyxml2::XMLDocument::LoadFile(const
   * char*) shows that the if (!filename) check at line 2354 is never true.
   * IMPLEMENTATION: The following code block calls LoadFile with a null
   * filename to trigger this error condition.
   */
  if (fdp.ConsumeBool()) {
    doc.LoadFile(static_cast<const char*>(nullptr));
  }

  tinyxml2::XMLElement* root = doc.RootElement();
  if (root) {
    /*
     * ANALYSIS: The line-level coverage for
     * tinyxml2::XMLElement::Attribute(const char*, const char*) shows that the
     * branch at line 1639 is not fully covered. The 'false' path of the
     * StringEqual check is never taken.
     * IMPLEMENTATION: The following code adds an attribute to the root element
     * and then calls Attribute with a non-matching value to exercise the
     * uncovered path.
     */
    std::string attr_name = fdp.ConsumeRandomLengthString(10);
    std::string attr_value = fdp.ConsumeRandomLengthString(10);
    root->SetAttribute(attr_name.c_str(), attr_value.c_str());
    std::string different_value = attr_value + "diff";
    root->Attribute(attr_name.c_str(), different_value.c_str());
  }

  /*
   * ANALYSIS: The line-level coverage for tinyxml2::XMLNode::DeleteNode shows
   * that the if (node == 0) check at line 1196 is never true.
   * IMPLEMENTATION: The following code block calls DeleteNode with a null
   * argument to cover this branch.
   */
  if (fdp.ConsumeBool()) {
    doc.DeleteNode(nullptr);
  }

  /*
   * ANALYSIS: The line-level coverage report for tinyxml2::XMLPrinter::Print
   * shows that the if (_fp) branch at line 2623 is never taken.
   * IMPLEMENTATION: The following code block creates an XMLPrinter with a FILE*
   * to a temporary file and then calls doc.Print() to exercise this branch.
   */
  FILE* printer_fp = fopen(path.c_str(), "w");
  if (printer_fp) {
    tinyxml2::XMLPrinter printer(printer_fp);
    doc.Print(&printer);
    fclose(printer_fp);
  }

  // Clean up the temporary file.
  unlink(path.c_str());

  return 0;
}