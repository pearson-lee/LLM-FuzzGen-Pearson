#include <cstddef>
#include <cstdint>
#include <string>
#include <unistd.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/tinyxml2/tinyxml2.h"
#include <cstdio>

// Define a simple visitor class to exercise the XMLVisitor API.
class MyVisitor : public tinyxml2::XMLVisitor {
private:
    FuzzedDataProvider* m_fdp;
public:
    MyVisitor(FuzzedDataProvider* fdp) : m_fdp(fdp) {}
    /*
     * ANALYSIS: The function-level coverage report showed that the VisitEnter
     *           and VisitExit methods in the XMLVisitor class had low branch
     *           coverage because the overridden methods in the fuzzer's
     *           visitor always returned true.
     * IMPLEMENTATION: The following methods now use the FuzzedDataProvider to
     *                 return either true or false, allowing the fuzzer to
     *                 explore both branches of the conditional logic within
     *                 the Accept() method.
     */
    bool VisitEnter(const tinyxml2::XMLElement&, const tinyxml2::XMLAttribute*) override { return m_fdp->ConsumeBool(); }
    bool VisitExit(const tinyxml2::XMLElement&) override { return m_fdp->ConsumeBool(); }
    bool Visit(const tinyxml2::XMLDeclaration&) override { return m_fdp->ConsumeBool(); }
    bool Visit(const tinyxml2::XMLText&) override { return m_fdp->ConsumeBool(); }
    bool Visit(const tinyxml2::XMLComment&) override { return m_fdp->ConsumeBool(); }
    bool Visit(const tinyxml2::XMLUnknown&) override { return m_fdp->ConsumeBool(); }
};

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
    if (!root) {
        // If NewElement fails, we can't proceed.
        return 0;
    }
    doc.InsertFirstChild(root);
  }

  /*
   * ANALYSIS: The function-level coverage report showed that
   * tinyxml2::XMLNode::InsertFirstChild had low coverage.
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
   * tinyxml2::XMLElement::GetText had low coverage.
   * IMPLEMENTATION: The following code block calls GetText() on the root
   * element. This will exercise the GetText function, which retrieves the
   * text content of an element.
   */
  root->GetText();

  /*
   * ANALYSIS: The function-level coverage report showed that
   * tinyxml2::XMLUtil::SetBoolSerialization had low coverage.
   * IMPLEMENTATION: The following code block calls SetBoolSerialization with
   * fuzzer-provided strings. This exercises the function's logic for setting
   * custom boolean serialization strings.
   */
  const std::string true_str = fdp.ConsumeRandomLengthString(5);
  const std::string false_str = fdp.ConsumeRandomLengthString(5);
  tinyxml2::XMLUtil::SetBoolSerialization(true_str.c_str(), false_str.c_str());

  /*
   * ANALYSIS: The function-level coverage report showed that many overloads of
   * tinyxml2::XMLElement::SetText and tinyxml2::XMLElement::Query...Text had 0% coverage.
   * IMPLEMENTATION: The following code block calls various overloads of SetText
   * to populate an element with different data types, and then calls the
   * corresponding Query...Text functions to read the values. This covers
   * multiple previously uncovered functions.
   */
  const std::string text_element_name = fdp.ConsumeRandomLengthString(10);
  tinyxml2::XMLElement* text_element = doc.NewElement(text_element_name.c_str());
  if (text_element) {
      root->InsertEndChild(text_element);
      text_element->SetText(fdp.ConsumeIntegral<int>());
      int i_val;
      text_element->QueryIntText(&i_val);

      text_element->SetText(fdp.ConsumeFloatingPoint<double>());
      double d_val;
      text_element->QueryDoubleText(&d_val);

      text_element->SetText(fdp.ConsumeBool());
      bool b_val;
      text_element->QueryBoolText(&b_val);

      text_element->SetText(fdp.ConsumeIntegral<unsigned int>());
      unsigned u_val;
      text_element->QueryUnsignedText(&u_val);

      /*
       * ANALYSIS: The function-level coverage report showed that the 64-bit
       *           integer and float overloads for SetText and Query...Text
       *           functions were uncovered.
       * IMPLEMENTATION: The following calls exercise the Int64, Unsigned64,
       *                 and float variations of SetText and Query...Text.
       */
      text_element->SetText(fdp.ConsumeIntegral<int64_t>());
      int64_t i64_val;
      text_element->QueryInt64Text(&i64_val);

      text_element->SetText(fdp.ConsumeIntegral<uint64_t>());
      uint64_t u64_val;
      text_element->QueryUnsigned64Text(&u64_val);

      text_element->SetText(fdp.ConsumeFloatingPoint<float>());
      float f_val;
      text_element->QueryFloatText(&f_val);
  }

  /*
   * ANALYSIS: The function-level coverage report showed that
   * tinyxml2::XMLNode::InsertAfterChild had 0% coverage.
   * IMPLEMENTATION: The following code creates two new elements and inserts
   * the second one after the first one, directly exercising InsertAfterChild.
   */
  const std::string child1_name = fdp.ConsumeRandomLengthString(10);
  tinyxml2::XMLElement* child1 = doc.NewElement(child1_name.c_str());
  if (child1) {
    root->InsertFirstChild(child1);
    const std::string child2_name = fdp.ConsumeRandomLengthString(10);
    tinyxml2::XMLElement* child2 = doc.NewElement(child2_name.c_str());
    if (child2) {
      root->InsertAfterChild(child1, child2);
    }
  }

  /*
   * ANALYSIS: The function-level coverage report showed that
   * tinyxml2::XMLDocument::NewComment had 0% coverage.
   * IMPLEMENTATION: The following code creates and inserts a comment node,
   * exercising the NewComment function.
   */
  const std::string comment_text = fdp.ConsumeRandomLengthString(20);
  tinyxml2::XMLComment* comment = doc.NewComment(comment_text.c_str());
  if (comment) {
    root->InsertEndChild(comment);
  }

  /*
   * ANALYSIS: The function-level coverage report showed that
   * tinyxml2::XMLElement::DeleteAttribute had 0% coverage.
   * IMPLEMENTATION: The following code adds an attribute to an element and
   * then immediately deletes it, exercising the attribute deletion logic.
   */
   const std::string attr_name = fdp.ConsumeRandomLengthString(10);
   const std::string attr_value = fdp.ConsumeRandomLengthString(10);
   root->SetAttribute(attr_name.c_str(), attr_value.c_str());
   root->DeleteAttribute(attr_name.c_str());

  /*
   * ANALYSIS: The function-level coverage report showed that many overloads
   * of tinyxml2::XMLElement::SetAttribute and Query...Attribute had 0% coverage.
   * IMPLEMENTATION: The following code calls various overloads of SetAttribute
   * and the corresponding Query...Attribute functions to exercise these
   * previously uncovered functions.
   */
  const std::string attr_name_typed = fdp.ConsumeRandomLengthString(10);
  root->SetAttribute(attr_name_typed.c_str(), fdp.ConsumeIntegral<int>());
  int i_attr_val;
  root->QueryIntAttribute(attr_name_typed.c_str(), &i_attr_val);

  root->SetAttribute(attr_name_typed.c_str(), fdp.ConsumeIntegral<unsigned int>());
  unsigned u_attr_val;
  root->QueryUnsignedAttribute(attr_name_typed.c_str(), &u_attr_val);

  root->SetAttribute(attr_name_typed.c_str(), fdp.ConsumeFloatingPoint<double>());
  double d_attr_val;
  root->QueryDoubleAttribute(attr_name_typed.c_str(), &d_attr_val);

  root->SetAttribute(attr_name_typed.c_str(), fdp.ConsumeBool());
  bool b_attr_val;
  root->QueryBoolAttribute(attr_name_typed.c_str(), &b_attr_val);

  /*
   * ANALYSIS: The function-level coverage report showed that the 64-bit
   *           integer and float overloads for SetAttribute and Query...Attribute
   *           functions were uncovered.
   * IMPLEMENTATION: The following calls exercise the Int64, Unsigned64,
   *                 and float variations of SetAttribute and Query...Attribute.
   */
  root->SetAttribute(attr_name_typed.c_str(), fdp.ConsumeIntegral<int64_t>());
  int64_t i64_attr_val;
  root->QueryInt64Attribute(attr_name_typed.c_str(), &i64_attr_val);

  root->SetAttribute(attr_name_typed.c_str(), fdp.ConsumeIntegral<uint64_t>());
  uint64_t u64_attr_val;
  root->QueryUnsigned64Attribute(attr_name_typed.c_str(), &u64_attr_val);

  root->SetAttribute(attr_name_typed.c_str(), fdp.ConsumeFloatingPoint<float>());
  float f_attr_val;
  root->QueryFloatAttribute(attr_name_typed.c_str(), &f_attr_val);

  /*
   * ANALYSIS: The function-level coverage report showed that
   * tinyxml2::XMLDocument::DeepCopy had 0% coverage.
   * IMPLEMENTATION: The following code creates a new document and calls
   * DeepCopy to clone the existing document, exercising this function.
   * The newDoc is stack-allocated, so no memory leak occurs.
   */
  tinyxml2::XMLDocument newDoc;
  doc.DeepCopy(&newDoc);

  /*
   * ANALYSIS: The function-level coverage report showed that many functions
   * in the tinyxml2::XMLPrinter class had 0% or low coverage.
   * IMPLEMENTATION: The following code block creates an XMLPrinter, uses it to
   * print the document to a string buffer, and then clears the buffer. This
   * exercises Print(), CStr(), and ClearBuffer().
   */
  tinyxml2::XMLPrinter printer;
  doc.Print(&printer);
  printer.CStr();
  printer.ClearBuffer();
  
  /*
   * ANALYSIS: The function-level coverage report showed that the PushAttribute
   *           and PushText families of functions in XMLPrinter were completely
   *           uncovered.
   * IMPLEMENTATION: The following code creates a new XMLPrinter and directly
   *                 calls the various PushAttribute and PushText overloads
   *                 with fuzzer-generated data to exercise these functions.
   */
  tinyxml2::XMLPrinter manual_printer;
  manual_printer.PushAttribute(fdp.ConsumeRandomLengthString(10).c_str(), fdp.ConsumeRandomLengthString(10).c_str());
  manual_printer.PushAttribute(fdp.ConsumeRandomLengthString(10).c_str(), fdp.ConsumeIntegral<int>());
  manual_printer.PushAttribute(fdp.ConsumeRandomLengthString(10).c_str(), fdp.ConsumeIntegral<unsigned int>());
  manual_printer.PushAttribute(fdp.ConsumeRandomLengthString(10).c_str(), fdp.ConsumeIntegral<int64_t>());
  manual_printer.PushAttribute(fdp.ConsumeRandomLengthString(10).c_str(), fdp.ConsumeIntegral<uint64_t>());
  manual_printer.PushAttribute(fdp.ConsumeRandomLengthString(10).c_str(), fdp.ConsumeBool());
  manual_printer.PushAttribute(fdp.ConsumeRandomLengthString(10).c_str(), fdp.ConsumeFloatingPoint<double>());
  manual_printer.PushText(fdp.ConsumeRandomLengthString(20).c_str());
  manual_printer.PushText(fdp.ConsumeIntegral<int64_t>());
  manual_printer.PushText(fdp.ConsumeIntegral<uint64_t>());
  manual_printer.PushText(fdp.ConsumeIntegral<int>());
  manual_printer.PushText(fdp.ConsumeIntegral<unsigned int>());
  manual_printer.PushText(fdp.ConsumeBool());
  manual_printer.PushText(fdp.ConsumeFloatingPoint<float>());
  manual_printer.PushText(fdp.ConsumeFloatingPoint<double>());

  /*
   * ANALYSIS: The function-level coverage report showed that the XMLVisitor
   *           class and its virtual methods were completely uncovered.
   * IMPLEMENTATION: An instance of the custom MyVisitor class is passed to
   *                 the document's Accept() method. This triggers the
   *                 traversal and calls the visitor's methods, covering this
   *                 previously untouched API surface.
   */
  MyVisitor visitor(&fdp);
  doc.Accept(&visitor);

  /*
   * ANALYSIS: The function-level coverage report showed that the XMLHandle
   *           and XMLConstHandle classes and their methods were completely uncovered.
   * IMPLEMENTATION: The following code creates an XMLHandle and an XMLConstHandle
   *                 from the root element and calls various methods to exercise
   *                 this functionality. This also covers related navigation
   *                 functions like FirstChildElement and NextSiblingElement.
   */
  tinyxml2::XMLHandle handle(root);
  handle.FirstChildElement();
  handle.LastChild();
  handle.PreviousSibling();
  handle.NextSibling();
  handle.ToNode();
  /*
   * ANALYSIS: The function-level coverage report showed that many of the
   *           To...() conversion functions in XMLHandle were uncovered.
   * IMPLEMENTATION: The following code calls ToElement(), ToText(), ToComment(),
   *                 ToUnknown(), and ToDeclaration() on the handle to exercise
   *                 these type-safe conversion methods.
   */
  handle.ToElement();
  handle.ToText();
  if (handle.ToNode()) {
    handle.ToNode()->ToComment();
  }
  handle.ToUnknown();
  handle.ToDeclaration();


  tinyxml2::XMLConstHandle constHandle(root);
  constHandle.FirstChildElement();
  constHandle.LastChild();
  constHandle.PreviousSibling();
  constHandle.NextSibling();
  constHandle.ToNode();

  /*
   * ANALYSIS: The function-level coverage report showed that the error
   *           reporting functions (ErrorStr, PrintError, ErrorName, etc.)
   *           were completely uncovered.
   * IMPLEMENTATION: The following code block attempts to parse a deliberately
   *                 malformed XML string. If parsing fails, it calls the
   *                 various error reporting functions to exercise their logic.
   */
  tinyxml2::XMLDocument error_doc;
  error_doc.Parse("<unclosed>");
  if (error_doc.Error()) {
      error_doc.ErrorStr();
      error_doc.PrintError();
      error_doc.ErrorName();
      error_doc.ErrorID();
      error_doc.ErrorLineNum();
  }

  /*
   * ANALYSIS: The function-level coverage report showed that the family of
   *           InsertNew... helper functions in XMLElement were completely uncovered.
   * IMPLEMENTATION: The following code calls InsertNewChildElement, InsertNewComment,
   *                 InsertNewText, InsertNewDeclaration, and InsertNewUnknown on the
   *                 root element to exercise these convenience functions.
   */
  root->InsertNewChildElement(fdp.ConsumeRandomLengthString(10).c_str());
  root->InsertNewComment(fdp.ConsumeRandomLengthString(20).c_str());
  root->InsertNewText(fdp.ConsumeRandomLengthString(20).c_str());
  root->InsertNewDeclaration(fdp.ConsumeRandomLengthString(20).c_str());
  root->InsertNewUnknown(fdp.ConsumeRandomLengthString(20).c_str());

  /*
   * ANALYSIS: The function-level coverage report showed that the ShallowEqual
   *           methods for various XMLNode subclasses (XMLElement, XMLComment, etc.)
   *           were completely uncovered.
   * IMPLEMENTATION: The following code creates pairs of different node types
   *                 and calls ShallowEqual on them. This exercises the comparison
   *                 logic for each node type. The created nodes are managed by the
   *                 XML document, ensuring no memory leaks.
   */
  tinyxml2::XMLElement* se1 = doc.NewElement("se1");
  tinyxml2::XMLElement* se2 = doc.NewElement("se2");
  if (se1 && se2) {
    /*
     * ANALYSIS: The function-level coverage report showed that
     *           XMLElement::ShallowEqual had low coverage (30%). The original fuzzer
     *           only added an attribute to one element.
     * IMPLEMENTATION: Attributes are now added to both elements. With a 50%
     *                 chance, the attributes are identical, and with a 50% chance,
     *                 they are different. This forces ShallowEqual to execute its
     *                 attribute comparison logic more thoroughly, covering more
     *                 branches related to finding both matching and non-matching attributes.
     */
    const std::string se_attr_name = fdp.ConsumeRandomLengthString(10);
    const std::string se_attr_value1 = fdp.ConsumeRandomLengthString(10);
    se1->SetAttribute(se_attr_name.c_str(), se_attr_value1.c_str());
    if (fdp.ConsumeBool()) {
        se2->SetAttribute(se_attr_name.c_str(), se_attr_value1.c_str());
    } else {
        const std::string se_attr_value2 = fdp.ConsumeRandomLengthString(10);
        se2->SetAttribute(se_attr_name.c_str(), se_attr_value2.c_str());
    }
    se1->ShallowEqual(se2);
  }
  tinyxml2::XMLComment* sc1 = doc.NewComment("sc1");
  tinyxml2::XMLComment* sc2 = doc.NewComment("sc2");
  if (sc1 && sc2) {
    sc1->ShallowEqual(sc2);
  }
  tinyxml2::XMLText* st1 = doc.NewText("st1");
  tinyxml2::XMLText* st2 = doc.NewText("st2");
  if (st1 && st2) {
    st1->ShallowEqual(st2);
  }
  tinyxml2::XMLDeclaration* sd1 = doc.NewDeclaration("sd1");
  tinyxml2::XMLDeclaration* sd2 = doc.NewDeclaration("sd2");
  if (sd1 && sd2) {
    sd1->ShallowEqual(sd2);
  }
  tinyxml2::XMLUnknown* su1 = doc.NewUnknown("su1");
  tinyxml2::XMLUnknown* su2 = doc.NewUnknown("su2");
  if (su1 && su2) {
    su1->ShallowEqual(su2);
  }

  /*
   * ANALYSIS: The function-level coverage report showed that the ...Attribute
   *           and ...Text functions which take default values were uncovered.
   * IMPLEMENTATION: The following code calls these functions on an element
   *                 to exercise the logic of returning a default value when
   *                 an attribute or text is not present.
   */
  if (text_element) {
    text_element->IntText(fdp.ConsumeIntegral<int>());
    text_element->UnsignedText(fdp.ConsumeIntegral<unsigned int>());
    text_element->Int64Text(fdp.ConsumeIntegral<int64_t>());
    text_element->Unsigned64Text(fdp.ConsumeIntegral<uint64_t>());
    text_element->BoolText(fdp.ConsumeBool());
    text_element->DoubleText(fdp.ConsumeFloatingPoint<double>());
    text_element->FloatText(fdp.ConsumeFloatingPoint<float>());
  }
  const std::string missing_attr_name = fdp.ConsumeRandomLengthString(10);
  root->IntAttribute(missing_attr_name.c_str(), fdp.ConsumeIntegral<int>());
  root->UnsignedAttribute(missing_attr_name.c_str(), fdp.ConsumeIntegral<unsigned int>());
  root->Int64Attribute(missing_attr_name.c_str(), fdp.ConsumeIntegral<int64_t>());
  root->Unsigned64Attribute(missing_attr_name.c_str(), fdp.ConsumeIntegral<uint64_t>());
  root->BoolAttribute(missing_attr_name.c_str(), fdp.ConsumeBool());
  root->DoubleAttribute(missing_attr_name.c_str(), fdp.ConsumeFloatingPoint<double>());
  root->FloatAttribute(missing_attr_name.c_str(), fdp.ConsumeFloatingPoint<float>());
  
  /*
   * ANALYSIS: The function-level coverage report showed that the `XMLAttribute::...Value()`
   *           functions (e.g., IntValue, BoolValue) were completely uncovered.
   * IMPLEMENTATION: The following code adds an attribute to an element and then calls
   *                 the various `...Value()` methods on that attribute to exercise the
   *                 direct value retrieval logic.
   */
  const std::string direct_val_attr = fdp.ConsumeRandomLengthString(10);
  root->SetAttribute(direct_val_attr.c_str(), fdp.ConsumeRandomLengthString(10).c_str());
  const tinyxml2::XMLAttribute* attr = root->FindAttribute(direct_val_attr.c_str());
  if (attr) {
      attr->IntValue();
      attr->UnsignedValue();
      attr->Int64Value();
      attr->Unsigned64Value();
      attr->BoolValue();
      attr->DoubleValue();
      attr->FloatValue();
  }

  /*
   * ANALYSIS: The function-level coverage report showed that the named
   *           overloads for element navigation and counting (e.g.,
   *           ChildElementCount(name)) were completely uncovered.
   * IMPLEMENTATION: The following code calls these specific overloads on the
   *                 root element, passing a fuzzer-generated name. This
   *                 exercises the name-matching logic within these functions.
   */
  const std::string search_name = fdp.ConsumeRandomLengthString(10);
  root->ChildElementCount(search_name.c_str());
  /*
   * ANALYSIS: The function-level coverage report showed that the no-argument
   *           version of `XMLNode::ChildElementCount` was not covered.
   * IMPLEMENTATION: The following line calls the `ChildElementCount()` method
   *                 without arguments to cover this function.
   */
  root->ChildElementCount();
  root->LastChildElement(search_name.c_str());
  if (child1) {
    child1->NextSiblingElement(search_name.c_str());
    child1->PreviousSiblingElement(search_name.c_str());
    /*
     * ANALYSIS: The function-level coverage report showed several simple navigation
     *           and property functions in `XMLNode` were uncovered, such as `Parent()`
     *           and `NoChildren()`.
     * IMPLEMENTATION: The following lines call these methods on a child element
     *                 to exercise their logic.
     */
    child1->Parent();
    child1->NoChildren();
  }

  /*
   * ANALYSIS: The function-level coverage report showed that
   *           StrPair::CollapseWhitespace was at 0%. The original implementation
   *           did not guarantee input with varied whitespace.
   * IMPLEMENTATION: A new document is created with COLLAPSE_WHITESPACE enabled. It
   *                 parses a crafted string containing leading, trailing, and multiple
   *                 internal whitespace characters to ensure the CollapseWhitespace
   *                 function's logic is fully exercised.
   */
  tinyxml2::XMLDocument ws_doc(true, tinyxml2::COLLAPSE_WHITESPACE);
  ws_doc.Parse("  <a >  \t\n\r b  </a >  ");


  /*
   * ANALYSIS: The function-level coverage report showed that the `XMLPrinter`
   *           constructor taking a `FILE*` argument was not covered.
   * IMPLEMENTATION: The following code opens a temporary file, creates an
   *                 `XMLPrinter` with the file handle, prints the document to it,
   *                 and then closes and deletes the file. This covers the file-based
   *                 printing logic.
   */
  FILE* printer_fp = fopen(filename.c_str(), "w");
  if (printer_fp) {
      tinyxml2::XMLPrinter file_printer(printer_fp);
      doc.Print(&file_printer);
      fclose(printer_fp);
  }

  /*
   * ANALYSIS: The function-level coverage report showed that `SetUserData` and
   *           `GetUserData` were uncovered.
   * IMPLEMENTATION: The following code sets a pointer as user data on the root
   *                 element and immediately retrieves it, exercising this functionality.
   */
  root->SetUserData(root);
  root->GetUserData();

  /*
   * ANALYSIS: The function-level coverage report showed that
   * tinyxml2::XMLDocument::SaveFile had low coverage.
   * IMPLEMENTATION: The following code block saves the document to a
   * temporary file. This exercises the SaveFile function. The file is
   * subsequently deleted to ensure statelessness.
   */
  doc.SaveFile(filename.c_str());

  // Clean up the temporary file.
  unlink(filename.c_str());

  return 0;
}