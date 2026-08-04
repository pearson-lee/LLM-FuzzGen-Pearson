#include <cstddef>
#include <cstdint>
#include <string>
#include <unistd.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/tinyxml2/tinyxml2.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Create a unique temporary file path for this fuzzer instance.
  // This is critical for stateless file I/O and avoiding race conditions.
  const std::string filename = std::string("/tmp/") + _FUZZ_TARGET_NAME + ".xml";

  // Create an XML document.
  tinyxml2::XMLDocument doc;

  // Consume data from the fuzzer to create an XML string.
  std::string xml_string = fdp.ConsumeRandomLengthString();
  doc.Parse(xml_string.c_str());

  // Get the root element. If it doesn't exist, create one.
  tinyxml2::XMLElement* root = doc.RootElement();
  if (!root) {
    const std::string root_name = fdp.ConsumeRandomLengthString(10);
    root = doc.NewElement(root_name.c_str());
    doc.InsertFirstChild(root);
  }

  /*
   * ANALYSIS: The function-level coverage report showed that
   * tinyxml2::XMLNode::InsertFirstChild had 0% coverage.
   * IMPLEMENTATION: The following code block creates a new element and
   * inserts it as the first child of the root element. This directly
   * exercises the InsertFirstChild function.
   */
  const std::string element_name = fdp.ConsumeRandomLengthString(10);
  tinyxml2::XMLElement* new_element = doc.NewElement(element_name.c_str());
  if (new_element) {
    root->InsertFirstChild(new_element);
  }

  /*
   * ANALYSIS: The function-level coverage report showed that
   * tinyxml2::XMLElement::GetText had 0% coverage.
   * IMPLEMENTATION: The following code block calls GetText() on the root
   * element. This will exercise the GetText function, which retrieves the
   * text content of an element.
   */
  root->GetText();

  /*
   * ANALYSIS: The function-level coverage report showed that
   * tinyxml2::XMLUtil::SetBoolSerialization had 0% coverage.
   * IMPLEMENTATION: The following code block calls SetBoolSerialization with
   * fuzzer-provided strings. This exercises the function's logic for setting
   * custom boolean serialization strings.
   */
  const std::string true_str = fdp.ConsumeRandomLengthString(5);
  const std::string false_str = fdp.ConsumeRandomLengthString(5);
  tinyxml2::XMLUtil::SetBoolSerialization(true_str.c_str(), false_str.c_str());

  /*
   * ANALYSIS: The function-level coverage report showed that
   * tinyxml2::XMLDocument::SaveFile had 0% coverage.
   * IMPLEMENTATION: The following code block saves the document to a
   * temporary file. This exercises the SaveFile function. The file is
   * subsequently deleted to ensure statelessness.
   */
  doc.SaveFile(filename.c_str());

  // Clean up the temporary file.
  unlink(filename.c_str());

  return 0;
}