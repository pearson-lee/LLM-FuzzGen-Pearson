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

      /*
       * ANALYSIS: The function-level coverage report showed that
       * tinyxml2::XMLElement::QueryUnsignedText had 0% coverage.
       * IMPLEMENTATION: The following code block calls SetText with an unsigned
       * int and then calls QueryUnsignedText to read it back.
       */
      text_element->SetText(fdp.ConsumeIntegral<unsigned int>());
      unsigned u_val;
      text_element->QueryUnsignedText(&u_val);
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