#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>

#include "/src/tinyxml2/tinyxml2.h" // Include the necessary tinyxml2 header

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  FuzzedDataProvider fdp(Data, Size);

  // Create an XMLDocument. This object uses RAII to manage memory for all
  // XML nodes (elements, attributes, text, etc.) created through it.
  tinyxml2::XMLDocument doc;

  // Consume fuzzed data for various string and numeric inputs.
  // These std::string objects will be automatically deallocated when they go out of scope.
  std::string elementName = fdp.ConsumeRandomLengthString(32);
  std::string attributeName = fdp.ConsumeRandomLengthString(32);
  // This name is specifically for testing the "attribute not found" branch.
  std::string nonExistentAttributeName = fdp.ConsumeRandomLengthString(32);
  std::string textContent = fdp.ConsumeRandomLengthString(64);
  // This string will be used to test conversion failures for numeric text.
  std::string invalidNumericText = fdp.ConsumeRandomLengthString(64);
  std::string printerAttributeName = fdp.ConsumeRandomLengthString(32);

  // Consume various numeric types for attributes and text.
  int64_t int64Val = fdp.ConsumeIntegral<int64_t>();
  uint64_t uint64Val = fdp.ConsumeIntegral<uint64_t>();
  float floatVal = fdp.ConsumeFloatingPoint<float>();
  double doubleVal = fdp.ConsumeFloatingPoint<double>();
  int intVal = fdp.ConsumeIntegral<int>();
  unsigned int uintVal = fdp.ConsumeIntegral<unsigned int>();
  bool boolVal = fdp.ConsumeBool();

  // --- Fuzzing tinyxml2::XMLElement::Int64Attribute and Unsigned64Attribute ---
  // These functions internally call QueryInt64Attribute/QueryUnsigned64Attribute.
  // We aim to cover branches where the attribute exists and where it doesn't.
  {
    tinyxml2::XMLElement* element = doc.NewElement(elementName.c_str());
    doc.InsertFirstChild(element); // Add element to the document

    // Case 1: Attribute exists and has a valid numeric value.
    element->SetAttribute(attributeName.c_str(), int64Val);
    element->SetAttribute("unsigned_attr", uint64Val);

    // Call Int64Attribute and Unsigned64Attribute with existing attribute names.
    int64_t resultInt64 = element->Int64Attribute(attributeName.c_str(), 0);
    uint64_t resultUInt64 = element->Unsigned64Attribute("unsigned_attr", 0);

    // Case 2: Attribute does not exist. This targets the 'if (!a)' branch
    // within QueryInt64Attribute/QueryUnsigned64Attribute, returning XML_NO_ATTRIBUTE.
    int64_t resultInt64NonExistent = element->Int64Attribute(nonExistentAttributeName.c_str(), 0);
    uint64_t resultUInt64NonExistent = element->Unsigned64Attribute(nonExistentAttributeName.c_str(), 0);
  }

  // --- Fuzzing tinyxml2::XMLElement::Int64Text and Unsigned64Text ---
  // These functions internally call QueryInt64Text/QueryUnsigned64Text.
  // We aim to cover valid text, invalid text, no text node, and non-text child cases.
  {
    // Case 1: Element with valid numeric text.
    tinyxml2::XMLElement* elementWithText = doc.NewElement("ElementWithText");
    doc.InsertEndChild(elementWithText);
    elementWithText->SetText(std::to_string(int64Val).c_str());
    int64_t textInt64 = elementWithText->Int64Text(0);
    elementWithText->SetText(std::to_string(uint64Val).c_str());
    uint64_t textUInt64 = elementWithText->Unsigned64Text(0);

    // Case 2: Element with invalid numeric text. This targets the 'XMLUtil::ToInt64'
    // conversion failure branch, returning XML_CAN_NOT_CONVERT_TEXT.
    tinyxml2::XMLElement* elementWithInvalidText = doc.NewElement("ElementWithInvalidText");
    doc.InsertEndChild(elementWithInvalidText);
    elementWithInvalidText->SetText(invalidNumericText.c_str());
    int64_t textInt64Invalid = elementWithInvalidText->Int64Text(0);
    uint64_t textUInt64Invalid = elementWithInvalidText->Unsigned64Text(0);

    // Case 3: Element with no text node. This targets the 'FirstChild() == null'
    // branch, returning XML_NO_TEXT_NODE.
    tinyxml2::XMLElement* elementNoText = doc.NewElement("ElementNoText");
    doc.InsertEndChild(elementNoText);
    int64_t textInt64NoText = elementNoText->Int64Text(0);
    uint64_t textUInt64NoText = elementNoText->Unsigned64Text(0);

    // Case 4: Element with a non-text child. This targets the 'FirstChild()->ToText() == false'
    // branch, also returning XML_NO_TEXT_NODE.
    tinyxml2::XMLElement* elementWithNonTextChild = doc.NewElement("ElementWithNonTextChild");
    doc.InsertEndChild(elementWithNonTextChild);
    elementWithNonTextChild->InsertNewChildElement("ChildElement"); // Insert an element, not text
    int64_t textInt64NonTextChild = elementWithNonTextChild->Int64Text(0);
    uint64_t textUInt64NonTextChild = elementWithNonTextChild->Unsigned64Text(0);
  }

  // --- Fuzzing tinyxml2::XMLNode::ChildElementCount() ---
  // We test elements with and without children to cover the loop condition.
  {
    tinyxml2::XMLElement* parentElement = doc.NewElement("ParentElement");
    doc.InsertEndChild(parentElement);

    // Case 1: Element with multiple children.
    int numChildren = fdp.ConsumeIntegralInRange<int>(0, 5); // Fuzz the number of children
    for (int i = 0; i < numChildren; ++i) {
      parentElement->InsertNewChildElement(fdp.ConsumeRandomLengthString(16).c_str());
    }
    int countWithChildren = parentElement->ChildElementCount();

    // Case 2: Element with no children.
    tinyxml2::XMLElement* emptyElement = doc.NewElement("EmptyElement");
    doc.InsertEndChild(emptyElement);
    int countNoChildren = emptyElement->ChildElementCount();
  }

  // --- Fuzzing tinyxml2::XMLPrinter::PushText and PushAttribute overloads ---
  // These functions were identified as having 0% coverage for specific numeric types.
  {
    tinyxml2::XMLPrinter printer; // XMLPrinter manages its own internal buffer.

    // Push various types of text using the respective PushText overloads.
    printer.PushText(int64Val);
    printer.PushText(uint64Val);
    printer.PushText(floatVal);
    printer.PushText(doubleVal);
    printer.PushText(boolVal);
    printer.PushText(intVal);
    printer.PushText(uintVal);
    printer.PushText(textContent.c_str()); // Also test string PushText

    // Open an element to push attributes.
    printer.OpenElement("PrinterElement");

    // Push various types of attributes using the respective PushAttribute overloads.
    printer.PushAttribute(printerAttributeName.c_str(), int64Val);
    printer.PushAttribute("unsigned_attr_printer", uint64Val);
    printer.PushAttribute("float_attr_printer", floatVal);
    printer.PushAttribute("double_attr_printer", doubleVal);
    printer.PushAttribute("bool_attr_printer", boolVal);
    printer.PushAttribute("int_attr_printer", intVal);
    printer.PushAttribute("uint_attr_printer", uintVal);
    printer.PushAttribute("string_attr_printer", textContent.c_str()); // Also test string PushAttribute

    printer.CloseElement(); // Close the element to finalize its representation.
  }

  // All memory allocated by tinyxml2::XMLDocument (nodes, attributes, text) is
  // automatically freed when 'doc' goes out of scope.
  // FuzzedDataProvider's internal data and std::string objects are also managed automatically.

  return 0;
}