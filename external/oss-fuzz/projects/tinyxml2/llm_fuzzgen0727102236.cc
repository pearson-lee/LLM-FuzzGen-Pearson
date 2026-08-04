#include "/src/tinyxml2/tinyxml2.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <unistd.h>
#include <vector>

// A simple visitor to exercise the XMLVisitor functions.
class FuzzingVisitor : public tinyxml2::XMLVisitor {
public:
  bool VisitEnter(const tinyxml2::XMLElement &element,
                  const tinyxml2::XMLAttribute *firstAttribute) override {
    (void)element;
    (void)firstAttribute;
    return true;
  }
  bool VisitExit(const tinyxml2::XMLElement &element) override {
    (void)element;
    return true;
  }
  bool Visit(const tinyxml2::XMLDeclaration &declaration) override {
    (void)declaration;
    return true;
  }
  bool Visit(const tinyxml2::XMLText &text) override {
    (void)text;
    return true;
  }
  bool Visit(const tinyxml2::XMLComment &comment) override {
    (void)comment;
    return true;
  }
  bool Visit(const tinyxml2::XMLUnknown &unknown) override {
    (void)unknown;
    return true;
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Create a unique temporary file path.
  const std::string path =
      std::string("/tmp/") + _FUZZ_TARGET_NAME + ".tmp";

  // Write fuzzed data to the temporary file.
  FILE *fp = fopen(path.c_str(), "wb");
  if (!fp) {
    return 0;
  }
  const std::vector<uint8_t> file_data =
      fdp.ConsumeRemainingBytes<uint8_t>();
  fwrite(file_data.data(), 1, file_data.size(), fp);
  fclose(fp);

  tinyxml2::XMLDocument doc;

  /*
   * ANALYSIS: The line-level coverage report for `XMLDocument::LoadFile` shows
   *           that several error handling paths related to file I/O are not
   *           being exercised.
   * IMPLEMENTATION: The following code block attempts to trigger these paths by
   *                 loading a file from disk. The file's content is generated
   *                 by the fuzzer, which may produce malformed XML, thus
   *                 triggering parsing errors.
   */
  doc.LoadFile(path.c_str());

  // Clean up the temporary file.
  unlink(path.c_str());

  tinyxml2::XMLElement *root = doc.RootElement();
  if (root) {
    /*
     * ANALYSIS: The line-level coverage report for `XMLElement::ShallowClone`
     *           shows that the `if (!doc)` branch is never taken.
     * IMPLEMENTATION: The following code block calls `ShallowClone` with a null
     *                 `XMLDocument` pointer to exercise this uncovered branch.
     */
    tinyxml2::XMLElement *clone =
        static_cast<tinyxml2::XMLElement *>(root->ShallowClone(nullptr));
    if (clone) {
      doc.DeleteNode(clone);
    }

    /*
     * ANALYSIS: The line-level coverage report for `XMLElement::DeleteAttribute`
     *           shows that the `if (attribute == 0)` branch is never taken.
     * IMPLEMENTATION: The following code block calls `DeleteAttribute` with a
     *                 null pointer to exercise this uncovered branch.
     */
    root->DeleteAttribute("");
  }

  /*
   * ANALYSIS: The line-level coverage report for `XMLNode::DeleteNode` shows
   *           that the `if (node == 0)` branch is never taken.
   * IMPLEMENTATION: The following code block calls `DeleteNode` with a null
   *                 pointer to exercise this uncovered branch.
   */
  doc.DeleteNode(nullptr);

  /*
   * ANALYSIS: The function-level coverage report shows that the `XMLVisitor`
   *           functions have 0% coverage.
   * IMPLEMENTATION: The following code block creates a simple `XMLVisitor` and
   *                 uses it to traverse the parsed document, thus exercising
   *                 the `XMLVisitor` functions.
   */
  FuzzingVisitor visitor;
  doc.Accept(&visitor);

  return 0;
}