#include "/src/tinyxml2/tinyxml2.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>

// Custom visitor to improve coverage of XMLVisitor functions
class FuzzVisitor : public tinyxml2::XMLVisitor {
public:
  FuzzVisitor(FuzzedDataProvider *fdp) : m_fdp(fdp) {}
  bool VisitEnter(const tinyxml2::XMLElement &element,
                  const tinyxml2::XMLAttribute *firstAttribute) override {
    return m_fdp->ConsumeBool();
  }
  bool VisitExit(const tinyxml2::XMLElement &element) override {
    return m_fdp->ConsumeBool();
  }
  bool Visit(const tinyxml2::XMLDeclaration &declaration) override {
    return m_fdp->ConsumeBool();
  }
  bool Visit(const tinyxml2::XMLText &text) override {
    return m_fdp->ConsumeBool();
  }
  bool Visit(const tinyxml2::XMLComment &comment) override {
    return m_fdp->ConsumeBool();
  }
  bool Visit(const tinyxml2::XMLUnknown &unknown) override {
    return m_fdp->ConsumeBool();
  }

private:
  FuzzedDataProvider *m_fdp;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  tinyxml2::XMLDocument doc;
  std::string xml_data = fdp.ConsumeRemainingBytesAsString();
  doc.Parse(xml_data.c_str());

  // Use the custom visitor
  FuzzVisitor visitor(&fdp);
  doc.Accept(&visitor);

  tinyxml2::XMLElement *root = doc.RootElement();
  if (root) {
    /*
     * ANALYSIS: The line coverage report for XMLElement::DeleteAttribute
     * showed that the null attribute case was not being tested.
     * IMPLEMENTATION: Call DeleteAttribute with a nullptr to cover this
     * branch.
     */
    root->DeleteAttribute(static_cast<const char *>(nullptr));

    // Delete attributes by name
    if (fdp.ConsumeBool()) {
      std::string attr_name = fdp.ConsumeRandomLengthString(16);
      root->DeleteAttribute(attr_name.c_str());
    }

    // Test ShallowClone
    tinyxml2::XMLElement *clone =
        (tinyxml2::XMLElement *)root->ShallowClone(&doc);
    if (clone) {
      // Clean up the clone
      doc.DeleteNode(clone);
    }
  }

  /*
   * ANALYSIS: The line coverage report for XMLNode::DeleteNode showed that
   * the null node case was not being tested.
   * IMPLEMENTATION: Call DeleteNode with a nullptr to cover this branch.
   */
  doc.DeleteNode(nullptr);

  // Test cloning with null document
  tinyxml2::XMLComment *comment = doc.NewComment(fdp.ConsumeRandomLengthString(32).c_str());
  if (comment) {
    comment->ShallowClone(nullptr);
    doc.InsertEndChild(comment);
  }

  tinyxml2::XMLDeclaration *declaration = doc.NewDeclaration();
  if (declaration) {
    declaration->ShallowClone(nullptr);
    doc.InsertEndChild(declaration);
  }

  tinyxml2::XMLUnknown *unknown = doc.NewUnknown(fdp.ConsumeRandomLengthString(32).c_str());
  if (unknown) {
    unknown->ShallowClone(nullptr);
    doc.InsertEndChild(unknown);
  }

  return 0;
}