#include <fuzzer/FuzzedDataProvider.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <memory> // For std::unique_ptr
#include <cstdio> // For unlink

// All Headers: /src/tinyxml2/tinyxml2.h
#include "/src/tinyxml2/tinyxml2.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  FuzzedDataProvider fdp(Data, Size);

  // Use unique_ptr for automatic memory management (RAII) for the XMLDocument.
  // tinyxml2::XMLDocument manages memory for its nodes and attributes internally.
  std::unique_ptr<tinyxml2::XMLDocument> doc(new tinyxml2::XMLDocument());

  /*
   * API 1: tinyxml2::XMLDocument::Parse
   * ANALYSIS: The function-level coverage report showed XMLDocument::Parse had 100% line coverage but 70% branch coverage.
   *           Further investigation into XMLNode::ParseDeep (called by XMLDocument::Parse) revealed an uncovered branch
   *           at tinyxml2.cpp:817: `if ( ( _document->RootElement() == 0 ) && ( _document->ErrorID() == XML_NO_ERROR ) )`.
   *           This branch is taken when a document is parsed, results in no root element, but also no parsing error.
   * IMPLEMENTATION: Provide an empty or whitespace-only string as input to XMLDocument::Parse to trigger this specific branch.
   *                 Also provide valid XML to cover normal parsing paths.
   */
  std::string xml_input = fdp.ConsumeRandomLengthString();
  doc->Parse(xml_input.c_str(), xml_input.length());

  // Attempt to get the root element for subsequent operations
  tinyxml2::XMLElement* root_element = doc->RootElement();

  if (root_element) {
    /*
     * API 2: tinyxml2::XMLElement::DeleteAttribute(char const*)
     * ANALYSIS: The function-level coverage report showed tinyxml2::XMLElement::DeleteAttribute(char const*) had 0% coverage.
     *           The line-level report confirmed the entire function and its internal branch (1632:9) were uncovered.
     * IMPLEMENTATION: Create an attribute, then attempt to delete it. Also attempt to delete a non-existent attribute
     *                 to cover the branch where 'attrib' is null.
     */
    std::string attr_name_to_delete = fdp.ConsumeRandomLengthString(32);
    if (fdp.ConsumeBool()) {
      // Sometimes add the attribute before trying to delete it
      std::string attr_value = fdp.ConsumeRandomLengthString(32);
      root_element->SetAttribute(attr_name_to_delete.c_str(), attr_value.c_str());
    }
    root_element->DeleteAttribute(attr_name_to_delete.c_str());

    // Also try deleting an attribute that was never set
    std::string non_existent_attr = fdp.ConsumeRandomLengthString(32);
    root_element->DeleteAttribute(non_existent_attr.c_str());

    /*
     * API 3: tinyxml2::XMLElement::InsertNewChildElement(char const*)
     * ANALYSIS: The function-level coverage report showed tinyxml2::XMLElement::InsertNewChildElement(char const*) had 0% coverage.
     *           The line-level report confirmed the entire function was uncovered.
     * IMPLEMENTATION: Call the function with a fuzzed string for the child element name.
     */
    std::string child_element_name = fdp.ConsumeRandomLengthString(32);
    root_element->InsertNewChildElement(child_element_name.c_str());

    /*
     * API 4: tinyxml2::XMLElement::ShallowEqual(tinyxml2::XMLNode const*) const
     * ANALYSIS: The function-level coverage report showed tinyxml2::XMLElement::ShallowEqual had 0% coverage.
     *           The line-level report confirmed the entire function and its internal branches were uncovered.
     * IMPLEMENTATION: Create two XMLElement objects and compare them using ShallowEqual. Vary their properties
     *                 (name, attributes, text) to exercise different comparison paths, including the base
     *                 XMLNode::ShallowEqual call and the string comparisons for value and comment.
     */
    // XMLElement and XMLText objects are owned by the XMLDocument and should not be managed by unique_ptr.
    // They are created using doc->NewElement() and doc->NewText().
    tinyxml2::XMLElement* element1 = doc->NewElement(fdp.ConsumeRandomLengthString(32).c_str());
    if (fdp.ConsumeBool()) {
      element1->SetAttribute(fdp.ConsumeRandomLengthString(16).c_str(), fdp.ConsumeRandomLengthString(16).c_str());
    }
    if (fdp.ConsumeBool()) {
      element1->SetText(fdp.ConsumeRandomLengthString(32).c_str());
    }

    tinyxml2::XMLElement* element2 = doc->NewElement(fdp.ConsumeRandomLengthString(32).c_str());
    if (fdp.ConsumeBool()) {
      element2->SetAttribute(fdp.ConsumeRandomLengthString(16).c_str(), fdp.ConsumeRandomLengthString(16).c_str());
    }
    if (fdp.ConsumeBool()) {
      element2->SetText(fdp.ConsumeRandomLengthString(32).c_str());
    }

    // Perform the comparison
    element1->ShallowEqual(element2);

    // Compare an element to itself
    element1->ShallowEqual(element1);

    // Compare an element to a non-element node (e.g., a text node)
    tinyxml2::XMLText* text_node = doc->NewText(fdp.ConsumeRandomLengthString(32).c_str());
    element1->ShallowEqual(text_node);

  } // End if (root_element)

  /*
   * API 5: tinyxml2::XMLPrinter::PushAttribute(char const*, int)
   * ANALYSIS: The function-level coverage report showed tinyxml2::XMLPrinter::PushAttribute(char const*, int) had 0% coverage.
   *           The line-level report confirmed the entire function was uncovered.
   * IMPLEMENTATION: Create an XMLPrinter and call PushAttribute with fuzzed strings for the name and fuzzed integers for the value.
   */
  std::unique_ptr<tinyxml2::XMLPrinter> printer(new tinyxml2::XMLPrinter());
  std::string attribute_name = fdp.ConsumeRandomLengthString(32);
  int attribute_value = fdp.ConsumeIntegral<int>();
  printer->PushAttribute(attribute_name.c_str(), attribute_value);

  // Also call other PushAttribute overloads for diversity
  std::string attr_name_uint = fdp.ConsumeRandomLengthString(32);
  printer->PushAttribute(attr_name_uint.c_str(), fdp.ConsumeIntegral<unsigned int>());
  std::string attr_name_long = fdp.ConsumeRandomLengthString(32);
  printer->PushAttribute(attr_name_long.c_str(), fdp.ConsumeIntegral<long>());
  std::string attr_name_ulong = fdp.ConsumeRandomLengthString(32);
  printer->PushAttribute(attr_name_ulong.c_str(), fdp.ConsumeIntegral<unsigned long>());
  std::string attr_name_bool = fdp.ConsumeRandomLengthString(32);
  printer->PushAttribute(attr_name_bool.c_str(), fdp.ConsumeBool());
  std::string attr_name_double = fdp.ConsumeRandomLengthString(32);
  printer->PushAttribute(attr_name_double.c_str(), fdp.ConsumeFloatingPoint<double>());
  std::string attr_name_float = fdp.ConsumeRandomLengthString(32);
  printer->PushAttribute(attr_name_float.c_str(), fdp.ConsumeFloatingPoint<float>());

  // Exercise some other printer functions for good measure
  std::string open_element_name = fdp.ConsumeRandomLengthString(32);
  printer->OpenElement(open_element_name.c_str());
  std::string push_text_content = fdp.ConsumeRandomLengthString(64);
  printer->PushText(push_text_content.c_str());
  printer->CloseElement();
  printer->CStr(); // Get the output string, implicitly covers it.

  return 0;
}