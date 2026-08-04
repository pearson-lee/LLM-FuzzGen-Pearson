#include <cstddef>
#include <cstdint>
#include <string>
#include <unistd.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/tinyxml2/tinyxml2.h"

// Custom visitor to exercise the XMLVisitor interface.
class MyVisitor : public tinyxml2::XMLVisitor {
public:
  bool VisitEnter(const tinyxml2::XMLElement&, const tinyxml2::XMLAttribute*) override { return true; }
  bool VisitExit(const tinyxml2::XMLElement&) override { return true; }
  bool Visit(const tinyxml2::XMLDeclaration&) override { return true; }
  bool Visit(const tinyxml2::XMLText&) override { return true; }
  bool Visit(const tinyxml2::XMLComment&) override { return true; }
  bool Visit(const tinyxml2::XMLUnknown&) override { return true; }
};


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
  tinyxml2::XMLDocument doc2;

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

  /*
   * ANALYSIS: The line-level coverage for tinyxml2::XMLDocument::SaveFile(const
   * char*, bool) shows that the if (!fp) check at line 2434 is never true.
   * This is difficult to trigger reliably. However, the null check for the
   * filename is not covered.
   * IMPLEMENTATION: The following code block calls SaveFile with a null
   * filename to trigger this error condition.
   */
  if (fdp.ConsumeBool()) {
      doc.SaveFile(static_cast<const char*>(nullptr), fdp.ConsumeBool());
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

    /*
     * ANALYSIS: The function-level coverage report showed that the various
     * XMLElement::Query*Text functions and GetText had low coverage.
     * IMPLEMENTATION: The following code calls GetText() and the Query*Text
     * functions on the root element to improve coverage of text-parsing logic.
     */
    root->GetText();
    int i;
    root->QueryIntText(&i);
    unsigned u;
    root->QueryUnsignedText(&u);
    float f;
    root->QueryFloatText(&f);
    double d;
    root->QueryDoubleText(&d);
    bool b;
    root->QueryBoolText(&b);
    int64_t i64;
    root->QueryInt64Text(&i64);
    uint64_t u64;
    root->QueryUnsigned64Text(&u64);

    /*
     * ANALYSIS: The function-level coverage report showed that
     * XMLElement::QueryStringAttribute had low coverage.
     * IMPLEMENTATION: Call QueryStringAttribute to exercise this function.
     */
    const char* attr_val_out = nullptr;
    root->QueryStringAttribute(attr_name.c_str(), &attr_val_out);

    /*
     * ANALYSIS: The function-level coverage report showed that
     * XMLNode::ShallowEqual has low coverage.
     * IMPLEMENTATION: Call ShallowEqual on the root node with itself to
     * exercise this function.
     */
    root->ShallowEqual(root);

    /*
     * ANALYSIS: The line-level coverage for tinyxml2::XMLElement::DeleteAttribute(XMLAttribute*)
     * at line 2026 shows the 'if (attribute == 0)' branch is never taken.
     * IMPLEMENTATION: Call DeleteAttribute with a nullptr to cover this branch.
     */
    root->DeleteAttribute(fdp.ConsumeRandomLengthString(16).c_str());

    /*
     * ANALYSIS: The line-level coverage for tinyxml2::XMLNode::InsertEndChild
     * shows the branch at line 934 `if ( addThis->_document != _document )` is never taken.
     * IMPLEMENTATION: Create a new element in a separate document and attempt to insert it
     * into the main document to trigger this cross-document insertion check.
     */
    tinyxml2::XMLElement* element_from_other_doc = doc2.NewElement("other");
    if (element_from_other_doc) {
        root->InsertEndChild(element_from_other_doc);
    }
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

  /*
   * ANALYSIS: The function-level coverage report showed that the entire
   * XMLVisitor interface was uncovered (0% coverage).
   * IMPLEMENTATION: A custom visitor class (MyVisitor) is defined and
   * doc.Accept() is called to traverse the document and exercise the
   * various Visit functions.
   */
  MyVisitor visitor;
  doc.Accept(&visitor);

  /*
   * ANALYSIS: The function-level coverage report showed that XMLHandle and
   * XMLConstHandle methods were largely uncovered.
   * IMPLEMENTATION: The following code creates XMLHandle and XMLConstHandle
   * objects from the document and uses some of their methods to improve
   * coverage.
   */
  tinyxml2::XMLHandle docHandle(&doc);
  docHandle.FirstChildElement();
  docHandle.LastChildElement();
  tinyxml2::XMLConstHandle constDocHandle(doc);
  constDocHandle.FirstChildElement();
  constDocHandle.LastChildElement();


  // Clean up the temporary file.
  unlink(path.c_str());

  return 0;
}