#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <memory> // For std::unique_ptr
#include <algorithm> // For std::all_of
#include <cstdio> // For printf, if needed for debugging, though generally avoided in fuzzers
#include <limits> // For std::numeric_limits
#include <fuzzer/FuzzedDataProvider.h> // Required for FuzzedDataProvider

// Include tinyxml2 headers with full project-relative path
#include "/src/tinyxml2/tinyxml2.h"

// The tinyxml2::XMLDocument class manages the memory of all nodes (XMLElement, XMLText, etc.)
// created via its New* methods (e.g., NewElement, NewText). When the XMLDocument is
// destructed, it automatically frees all associated nodes. Using std::unique_ptr
// for the XMLDocument itself ensures its proper destruction and, consequently,
// the proper cleanup of all its managed nodes, preventing memory leaks.
// XMLPrinter objects manage their own internal buffers and are typically stack-allocated
// or managed explicitly, requiring no special smart pointer handling here.

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  FuzzedDataProvider fdp(Data, Size);

  // Use std::unique_ptr for XMLDocument to ensure proper destruction and memory safety.
  // Replaced std::make_unique with new and std::unique_ptr constructor for broader compiler compatibility.
  std::unique_ptr<tinyxml2::XMLDocument> doc(new tinyxml2::XMLDocument());

  // --- Fuzzing tinyxml2::XMLElement::BoolText(bool) ---
  // This function has 0% coverage and calls QueryBoolText, which has uncovered branches.
  // Goals: Cover XML_NO_TEXT_NODE, XML_CAN_NOT_CONVERT_TEXT, and XML_SUCCESS.
  {
    // Scenario 1: Element with no text node (to cover XML_NO_TEXT_NODE in QueryBoolText)
    tinyxml2::XMLElement* elementNoText = doc->NewElement("NoTextElement");
    doc->InsertEndChild(elementNoText); // Link to document for memory management
    bool defaultBool = fdp.ConsumeBool();
    elementNoText->BoolText(defaultBool);

    // Scenario 2: Element with non-boolean text (to cover XML_CAN_NOT_CONVERT_TEXT in QueryBoolText)
    tinyxml2::XMLElement* elementNonBoolText = doc->NewElement("NonBoolTextElement");
    doc->InsertEndChild(elementNonBoolText);
    std::string nonBoolStr = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange(1, 20));
    // Ensure the string is not "true" or "false" to reliably hit the conversion failure path.
    if (nonBoolStr == "true" || nonBoolStr == "false" || nonBoolStr == "TRUE" || nonBoolStr == "FALSE" || nonBoolStr.empty()) {
        nonBoolStr = "notaboolean" + nonBoolStr;
    }
    elementNonBoolText->SetText(nonBoolStr.c_str());
    elementNonBoolText->BoolText(defaultBool);

    // Scenario 3: Element with valid boolean text (to cover XML_SUCCESS in QueryBoolText)
    tinyxml2::XMLElement* elementBoolText = doc->NewElement("BoolTextElement");
    doc->InsertEndChild(elementBoolText);
    bool randomBool = fdp.ConsumeBool();
    elementBoolText->SetText(randomBool ? "true" : "false");
    elementBoolText->BoolText(defaultBool);
  }

  // --- Fuzzing tinyxml2::XMLElement::IntAttribute(const char *, int) ---
  // This function has 0% coverage and calls QueryIntAttribute, which has an uncovered branch.
  // Goals: Cover XML_NO_ATTRIBUTE and successful conversion.
  {
    // Scenario 1: Attribute not found (to cover XML_NO_ATTRIBUTE in QueryIntAttribute)
    tinyxml2::XMLElement* elementNoAttr = doc->NewElement("NoAttrElement");
    doc->InsertEndChild(elementNoAttr);
    std::string nonExistentAttrName = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange(1, 20));
    elementNoAttr->IntAttribute(nonExistentAttrName.c_str(), fdp.ConsumeIntegral<int>());

    // Scenario 2: Valid integer attribute
    tinyxml2::XMLElement* elementIntAttr = doc->NewElement("IntAttrElement");
    doc->InsertEndChild(elementIntAttr);
    std::string intAttrName = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange(1, 20));
    int intValue = fdp.ConsumeIntegral<int>();
    elementIntAttr->SetAttribute(intAttrName.c_str(), intValue);
    elementIntAttr->IntAttribute(intAttrName.c_str(), fdp.ConsumeIntegral<int>());

    // Scenario 3: Non-integer attribute (to test robustness of underlying QueryIntValue)
    tinyxml2::XMLElement* elementNonIntAttr = doc->NewElement("NonIntAttrElement");
    doc->InsertEndChild(elementNonIntAttr);
    std::string nonIntAttrName = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange(1, 20));
    std::string nonIntAttrValue = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange(1, 20));
    // Ensure the string is not a valid integer to test conversion failure.
    if (std::all_of(nonIntAttrValue.begin(), nonIntAttrValue.end(), ::isdigit) || nonIntAttrValue.empty()) {
        nonIntAttrValue = "notanint" + nonIntAttrValue;
    }
    elementNonIntAttr->SetAttribute(nonIntAttrName.c_str(), nonIntAttrValue.c_str());
    elementNonIntAttr->IntAttribute(nonIntAttrName.c_str(), fdp.ConsumeIntegral<int>());
  }

  // --- Fuzzing tinyxml2::XMLElement::DoubleText(double) ---
  // This function has 0% coverage. Similar to BoolText, it likely calls QueryDoubleText.
  // Goals: Cover cases with no text, non-double text, and valid double text.
  {
    // Scenario 1: Element with no text node
    tinyxml2::XMLElement* elementNoDoubleText = doc->NewElement("NoDoubleTextElement");
    doc->InsertEndChild(elementNoDoubleText);
    double defaultDouble = fdp.ConsumeFloatingPoint<double>();
    elementNoDoubleText->DoubleText(defaultDouble);

    // Scenario 2: Element with non-double text
    tinyxml2::XMLElement* elementNonDoubleText = doc->NewElement("NonDoubleTextElement");
    doc->InsertEndChild(elementNonDoubleText);
    std::string nonDoubleStr = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange(1, 20));
    // Ensure the string is not a valid double to test conversion failure.
    if (std::all_of(nonDoubleStr.begin(), nonDoubleStr.end(), [](char c){ return ::isdigit(c) || c == '.' || c == '-' || c == 'e' || c == 'E'; }) || nonDoubleStr.empty()) {
        nonDoubleStr = "notadouble" + nonDoubleStr;
    }
    elementNonDoubleText->SetText(nonDoubleStr.c_str());
    elementNonDoubleText->DoubleText(defaultDouble);

    // Scenario 3: Element with valid double text
    tinyxml2::XMLElement* elementDoubleText = doc->NewElement("DoubleTextElement");
    doc->InsertEndChild(elementDoubleText);
    double randomDouble = fdp.ConsumeFloatingPoint<double>();
    elementDoubleText->SetText(std::to_string(randomDouble).c_str());
    elementDoubleText->DoubleText(defaultDouble);
  }

  // --- Fuzzing tinyxml2::XMLDocument::PrintError() ---
  // This function has 0% coverage. To cover it, an error needs to be set in the document.
  // Goal: Trigger an XML parsing error and then call PrintError.
  {
    // Create a new document specifically to induce an error.
    std::unique_ptr<tinyxml2::XMLDocument> errorDoc(new tinyxml2::XMLDocument());
    std::string invalidXml = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange(1, 100));
    // Make sure the XML is likely invalid to trigger an error.
    if (invalidXml.length() > 0 && invalidXml[0] == '<') {
        invalidXml = "invalid" + invalidXml; // Prepend to make it invalid
    } else if (invalidXml.empty()) {
        invalidXml = "<"; // Minimal invalid XML
    }
    errorDoc->Parse(invalidXml.c_str());
    // PrintError will output error details if an error occurred during parsing.
    errorDoc->PrintError();
  }

  // --- Fuzzing tinyxml2::XMLPrinter::PushHeader(bool, bool) ---
  // This function has 0% coverage and branches based on its boolean parameters.
  // Goals: Cover all combinations of writeBOM and writeDeclaration.
  {
    // XMLPrinter can be stack-allocated as it manages its own internal buffer.
    tinyxml2::XMLPrinter printer;

    // Scenario 1: writeBOM = true, writeDeclaration = true
    printer.PushHeader(true, true);
    printer.ClearBuffer(); // Clear buffer for the next test case

    // Scenario 2: writeBOM = true, writeDeclaration = false
    printer.PushHeader(true, false);
    printer.ClearBuffer();

    // Scenario 3: writeBOM = false, writeDeclaration = true
    printer.PushHeader(false, true);
    printer.ClearBuffer(); // Clear buffer for the next test case

    // Scenario 4: writeBOM = false, writeDeclaration = false
    printer.PushHeader(false, false);
    printer.ClearBuffer();
  }

  // The std::unique_ptr 'doc' will automatically call the XMLDocument destructor
  // at the end of the function scope, which in turn frees all associated XML nodes
  // and attributes, ensuring no memory leaks. Stack-allocated objects like 'printer'
  // are also automatically destructed.

  return 0;
}