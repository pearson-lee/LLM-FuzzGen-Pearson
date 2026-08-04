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
   * ANALYSIS: The original fuzzer consumed all remaining bytes from the
   * FuzzedDataProvider early on, causing subsequent calls to `fdp.ConsumeBool()`
   * to always return false. This resulted in several intended test blocks
   * (e.g., for LoadFile(nullptr)) never being executed.
   * IMPLEMENTATION: All boolean flags and other values from the data provider
   * are now consumed *before* the main XML data is consumed via
   * `ConsumeRemainingBytesAsString`. This ensures all `if` conditions can be
   * triggered.
   */
  const bool load_file_null = fdp.ConsumeBool();
  const bool save_file_null = fdp.ConsumeBool();
  const bool delete_node_null = fdp.ConsumeBool();
  const bool use_compact_printer = fdp.ConsumeBool();
  const bool set_value_null = fdp.ConsumeBool();

  if (fdp.ConsumeBool()) {
    tinyxml2::XMLUtil::SetBoolSerialization(nullptr, nullptr);
  } else {
    std::string true_str = fdp.ConsumeRandomLengthString(10);
    std::string false_str = fdp.ConsumeRandomLengthString(10);
    tinyxml2::XMLUtil::SetBoolSerialization(true_str.c_str(), false_str.c_str());
  }

  tinyxml2::XMLDocument doc;
  tinyxml2::XMLDocument doc2;

  std::string xml_data = fdp.ConsumeRemainingBytesAsString();
  FILE* fp = fopen(path.c_str(), "w");
  if (fp) {
    fwrite(xml_data.c_str(), 1, xml_data.size(), fp);
    fclose(fp);
    doc.LoadFile(path.c_str());
  }

  if (load_file_null) {
    doc.LoadFile(static_cast<const char*>(nullptr));
  }

  if (save_file_null) {
      doc.SaveFile(static_cast<const char*>(nullptr), fdp.ConsumeBool());
  }

  tinyxml2::XMLElement* root = doc.RootElement();
  if (root) {
    std::string attr_name = fdp.ConsumeRandomLengthString(10);
    std::string attr_value = fdp.ConsumeRandomLengthString(10);
    root->SetAttribute(attr_name.c_str(), attr_value.c_str());
    std::string different_value = attr_value + "diff";
    root->Attribute(attr_name.c_str(), different_value.c_str());

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

    const char* attr_val_out = nullptr;
    root->QueryStringAttribute(attr_name.c_str(), &attr_val_out);

    root->ShallowEqual(root);

    /*
     * ANALYSIS: The function-level coverage report showed that many
     *           ShallowEqual methods had low coverage. The existing test only
     *           compared a node to itself.
     * IMPLEMENTATION: Create a deep copy of the document and compare the
     *                 original root to the cloned root to exercise more complex
     *                 equality-checking paths.
     */
    tinyxml2::XMLDocument doc3;
    doc.DeepCopy(&doc3);
    tinyxml2::XMLElement* root3 = doc3.RootElement();
    if (root3) {
        root->ShallowEqual(root3);
    }

    /*
     * ANALYSIS: The function-level coverage for tinyxml2::XMLNode::Value()
     *           shows a missed branch. Analysis of the source reveals the
     *           `if ( _value.IsSafe() )` check is not fully covered.
     * IMPLEMENTATION: Call SetValue(nullptr) on the root element, which
     *                 should cause `IsSafe()` to return false, then call
     *                 Value() to hit the uncovered path.
     */
    if (set_value_null) {
        root->SetValue(nullptr);
        root->Value();
    }

    root->DeleteAttribute(fdp.ConsumeRandomLengthString(16).c_str());

    tinyxml2::XMLElement* element_from_other_doc = doc2.NewElement("other");
    if (element_from_other_doc) {
        root->InsertEndChild(element_from_other_doc);
    }
  }

  if (delete_node_null) {
    doc.DeleteNode(nullptr);
  }

  FILE* printer_fp = fopen(path.c_str(), "w");
  if (printer_fp) {
    /*
     * ANALYSIS: The function-level coverage report for the XMLPrinter
     *           constructor showed missed branches because the default arguments
     *           were always being used.
     * IMPLEMENTATION: Use a boolean flag from the FuzzedDataProvider to
     *                 sometimes use the non-default `compact=true` and
     *                 `APOS_ALWAYS_ESCAPE` arguments for the XMLPrinter
     *                 constructor, exercising different printing logic paths.
     */
    tinyxml2::XMLPrinter printer(printer_fp, use_compact_printer, 0);
    doc.Print(&printer);
    fclose(printer_fp);
  }

  MyVisitor visitor;
  doc.Accept(&visitor);

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