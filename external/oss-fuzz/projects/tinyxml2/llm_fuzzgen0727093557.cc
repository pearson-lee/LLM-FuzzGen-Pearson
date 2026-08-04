#include "/src/tinyxml2/tinyxml2.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <unistd.h>

// A custom visitor to exercise the XMLVisitor functions.
class MyVisitor : public tinyxml2::XMLVisitor {
public:
  bool VisitEnter(const tinyxml2::XMLElement &element,
                  const tinyxml2::XMLAttribute *firstAttribute) override {
    // Return false to stop traversal sometimes.
    return fdp->ConsumeBool();
  }
  bool VisitExit(const tinyxml2::XMLElement &element) override {
    return fdp->ConsumeBool();
  }
  bool Visit(const tinyxml2::XMLDeclaration &declaration) override {
    return fdp->ConsumeBool();
  }
  bool Visit(const tinyxml2::XMLText &text) override { return fdp->ConsumeBool(); }
  bool Visit(const tinyxml2::XMLComment &comment) override {
    return fdp->ConsumeBool();
  }
  bool Visit(const tinyxml2::XMLUnknown &unknown) override {
    return fdp->ConsumeBool();
  }

  MyVisitor(FuzzedDataProvider *fdp) : fdp(fdp) {}

private:
  FuzzedDataProvider *fdp;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Create a temporary file for LoadFile testing.
  char path[256];
  snprintf(path, sizeof(path), "/tmp/%s.tmp", _FUZZ_TARGET_NAME);

  std::string xml_data = fdp.ConsumeRandomLengthString(1024);
  FILE *fp = fopen(path, "w");
  if (!fp) {
    return 0;
  }
  fwrite(xml_data.c_str(), 1, xml_data.size(), fp);
  fclose(fp);

  tinyxml2::XMLDocument doc;

  // Exercise LoadFile.
  if (fdp.ConsumeBool()) {
    doc.LoadFile(path);
  } else {
    doc.LoadFile(path);
  }

  // Clean up the temporary file.
  unlink(path);

  // Create and use a custom visitor to improve coverage of visitor functions.
  MyVisitor visitor(&fdp);
  doc.Accept(&visitor);

  tinyxml2::XMLElement *root = doc.RootElement();
  if (root) {
    /*
     * ANALYSIS: The line-level coverage report for
     * XMLElement::DeleteAttribute shows that the null check at line 2026 is
     * never hit.
     * IMPLEMENTATION: Call DeleteAttribute with a nullptr to trigger this
     * branch.
     */
    root->DeleteAttribute(static_cast<const char *>(nullptr));
  }

  /*
   * ANALYSIS: The line-level coverage report for XMLNode::DeleteNode shows
   * that the null check at line 1196 is never hit. Additionally, the
   * ToDocument() check at line 1200 is always true.
   * IMPLEMENTATION: Call DeleteNode with a nullptr to trigger the first
   * branch, and with the document itself to trigger the second.
   */
  doc.DeleteNode(nullptr);
  doc.DeleteNode(doc.RootElement());

  // Add a comment to the document.
  std::string comment_text = fdp.ConsumeRandomLengthString(100);
  tinyxml2::XMLComment *comment = doc.NewComment(comment_text.c_str());
  if (comment) {
    doc.InsertFirstChild(comment);
  }

  // Create a new element and insert it.
  std::string element_name = fdp.ConsumeRandomLengthString(50);
  tinyxml2::XMLElement *new_element = doc.NewElement(element_name.c_str());
  if (new_element) {
    doc.InsertEndChild(new_element);
  }

  /*
   * ANALYSIS: The line-level coverage report for StrPair::TransferTo shows
   * that the self-assignment check at line 153 is never hit.
   * IMPLEMENTATION: Create a StrPair and call TransferTo on itself to trigger
   * this branch.
   */
  tinyxml2::StrPair str_pair;
  str_pair.TransferTo(&str_pair);

  return 0;
}