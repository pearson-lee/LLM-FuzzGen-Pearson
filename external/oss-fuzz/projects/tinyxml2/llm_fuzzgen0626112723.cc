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

// Custom XMLVisitor to cover tinyxml2::XMLVisitor::Visit* methods.
class CustomVisitor : public tinyxml2::XMLVisitor {
public:
    bool VisitEnter(const tinyxml2::XMLDocument& /*doc*/) override { return true; }
    bool VisitExit(const tinyxml2::XMLDocument& /*doc*/) override { return true; }
    bool VisitEnter(const tinyxml2::XMLElement& /*element*/, const tinyxml2::XMLAttribute* /*firstAttribute*/) override { return true; }
    bool VisitExit(const tinyxml2::XMLElement& /*element*/) override { return true; }
    bool Visit(const tinyxml2::XMLDeclaration& /*declaration*/) override { return true; }
    bool Visit(const tinyxml2::XMLText& /*text*/) override { return true; }
    bool Visit(const tinyxml2::XMLComment& /*comment*/) override { return true; }
    bool Visit(const tinyxml2::XMLUnknown& /*unknown*/) override { return true; }
};

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
    // Added to ensure the nonBoolStr.empty() branch is hit in the condition.
    if (fdp.ConsumeBool()) {
        nonBoolStr = "";
    }
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
    // Added to ensure the nonIntAttrValue.empty() branch is hit in the condition.
    if (fdp.ConsumeBool()) {
        nonIntAttrValue = "";
    }
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
    // Added to ensure the nonDoubleStr.empty() branch is hit in the condition.
    if (fdp.ConsumeBool()) {
        nonDoubleStr = "";
    }
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

  // --- New Fuzzing Sections for Coverage Improvement ---

  // Fuzzing XMLVisitor methods by traversing a document.
  // This covers many tinyxml2::XMLVisitor::Visit* and tinyxml2::XMLNode::Accept methods.
  {
    std::unique_ptr<tinyxml2::XMLDocument> visitorDoc(new tinyxml2::XMLDocument());
    // Parse a diverse XML string to create various node types for the visitor to encounter.
    visitorDoc->Parse("<root><element attr='val'>text</element><!--comment--><?proc instruction?><![CDATA[cdata section]]></root>");

    CustomVisitor visitor;
    visitorDoc->Accept(&visitor);

    // Also test with an empty document to cover edge cases for visitor.
    std::unique_ptr<tinyxml2::XMLDocument> emptyVisitorDoc(new tinyxml2::XMLDocument());
    emptyVisitorDoc->Accept(&visitor);
  }

  // Fuzzing tinyxml2::XMLHandle and tinyxml2::XMLConstHandle methods.
  // These functions had 0% coverage.
  {
    std::unique_ptr<tinyxml2::XMLDocument> handleDoc(new tinyxml2::XMLDocument());
    handleDoc->Parse("<root><child1><grandchild/></child1><child2/></root>");

    tinyxml2::XMLHandle handle(handleDoc.get());
    tinyxml2::XMLElement* rootElement = handle.FirstChildElement("root").ToElement();
    if (rootElement) {
        tinyxml2::XMLHandle rootHandle(rootElement);
        tinyxml2::XMLElement* child1 = rootHandle.FirstChildElement("child1").ToElement();
        if (child1) {
            tinyxml2::XMLHandle child1Handle(child1);
            child1Handle.FirstChildElement("grandchild").ToElement();
            child1Handle.NextSiblingElement("child2").ToElement();
            child1Handle.PreviousSiblingElement("child1").ToElement(); // Should be null
        }
    }

    // Test with const handle
    const tinyxml2::XMLConstHandle constHandle(handleDoc.get());
    const tinyxml2::XMLElement* constRootElement = constHandle.FirstChildElement("root").ToElement();
    if (constRootElement) {
        const tinyxml2::XMLConstHandle constRootHandle(constRootElement);
        constRootHandle.FirstChildElement("child1").ToElement();
    }

    // Test other handle methods with a null handle to cover null paths.
    tinyxml2::XMLHandle nullHandle(nullptr); // Corrected: XMLHandle requires an argument
    nullHandle.ToNode();
    nullHandle.ToElement();
    nullHandle.FirstChild();
    nullHandle.LastChild();
    nullHandle.NextSibling();
    nullHandle.PreviousSibling();
    nullHandle.FirstChildElement();
    nullHandle.LastChildElement();
    nullHandle.NextSiblingElement();
    nullHandle.PreviousSiblingElement();
  }

  // Fuzzing various XMLNode and XMLAttribute direct accessors and const methods.
  // Many of these had 0% coverage.
  {
    tinyxml2::XMLDocument* docPtr = doc.get(); // Get raw pointer for node creation

    // Create a base element for testing
    tinyxml2::XMLElement* element = docPtr->NewElement("TestNode");
    docPtr->InsertEndChild(element);

    // XMLNode methods
    element->GetDocument(); // tinyxml2::XMLNode::GetDocument()
    static_cast<const tinyxml2::XMLNode*>(element)->GetDocument(); // tinyxml2::XMLNode::GetDocument() const
    element->GetLineNum(); // tinyxml2::XMLNode::GetLineNum() const
    element->Parent(); // tinyxml2::XMLNode::Parent()
    static_cast<const tinyxml2::XMLNode*>(element)->Parent(); // tinyxml2::XMLNode::Parent() const
    element->NoChildren(); // tinyxml2::XMLNode::NoChildren() const (for an empty element)

    // Add children for sibling/child access tests
    tinyxml2::XMLElement* child1 = docPtr->NewElement("Child1");
    tinyxml2::XMLElement* child2 = docPtr->NewElement("Child2");
    element->InsertEndChild(child1);
    element->InsertEndChild(child2);
    element->FirstChild(); // tinyxml2::XMLNode::FirstChild()
    static_cast<const tinyxml2::XMLNode*>(element)->FirstChild(); // tinyxml2::XMLNode::FirstChild() const
    element->LastChild(); // tinyxml2::XMLNode::LastChild()
    static_cast<const tinyxml2::XMLNode*>(element)->LastChild(); // tinyxml2::XMLNode::LastChild() const
    child2->PreviousSibling(); // tinyxml2::XMLNode::PreviousSibling()
    static_cast<const tinyxml2::XMLNode*>(child2)->PreviousSibling(); // tinyxml2::XMLNode::PreviousSibling() const
    child1->NextSibling(); // tinyxml2::XMLNode::NextSibling()
    static_cast<const tinyxml2::XMLNode*>(child1)->NextSibling(); // tinyxml2::XMLNode::NextSibling() const
    child1->NextSiblingElement("Child2"); // tinyxml2::XMLNode::NextSiblingElement(char const*)

    // XMLNode::To*() methods for specific node types (had 0% coverage for const versions)
    tinyxml2::XMLText* textNode = docPtr->NewText("some text");
    element->InsertEndChild(textNode);
    textNode->ToText(); // tinyxml2::XMLNode::ToText()
    static_cast<const tinyxml2::XMLText*>(textNode)->ToText(); // tinyxml2::XMLNode::ToText() const

    tinyxml2::XMLComment* commentNode = docPtr->NewComment("a comment");
    element->InsertEndChild(commentNode);
    commentNode->ToComment(); // tinyxml2::XMLNode::ToComment()
    static_cast<const tinyxml2::XMLComment*>(commentNode)->ToComment(); // tinyxml2::XMLNode::ToComment() const

    tinyxml2::XMLDeclaration* declNode = docPtr->NewDeclaration("version='1.0'");
    element->InsertEndChild(declNode);
    declNode->ToDeclaration(); // tinyxml2::XMLNode::ToDeclaration()
    static_cast<const tinyxml2::XMLDeclaration*>(declNode)->ToDeclaration(); // tinyxml2::XMLNode::ToDeclaration() const

    tinyxml2::XMLUnknown* unknownNode = docPtr->NewUnknown("<!DOCTYPE doc>");
    element->InsertEndChild(unknownNode);
    unknownNode->ToUnknown(); // tinyxml2::XMLNode::ToUnknown()
    static_cast<const tinyxml2::XMLUnknown*>(unknownNode)->ToUnknown(); // tinyxml2::XMLNode::ToUnknown() const

    // XMLNode::SetUserData / GetUserData (had 0% coverage)
    void* userData = (void*)fdp.ConsumeIntegral<uintptr_t>(); // Use fuzzed data for user data
    element->SetUserData(userData);
    element->GetUserData();

    // XMLAttribute direct value accessors (had 0% coverage for many types)
    // Corrected: FindOrCreateAttribute is private, use SetAttribute and FindAttribute
    element->SetAttribute("testAttr", "dummyValue"); // Create the attribute
    const tinyxml2::XMLAttribute* attr = element->FindAttribute("testAttr"); // Corrected: Use const XMLAttribute*
    if (attr) { // Ensure attr is not null before using
        // Need a non-const attribute to call SetAttribute, so we'll create a new one or cast if safe.
        // For fuzzing, it's better to use SetAttribute directly on the element.
        // The goal here is to test the *getter* methods (IntValue, etc.) on an existing attribute.
        // We can set the attribute value via the element, then retrieve and test.
        element->SetAttribute("intAttr", fdp.ConsumeIntegral<int>());
        if (const tinyxml2::XMLAttribute* intAttr = element->FindAttribute("intAttr")) {
            intAttr->IntValue(); // tinyxml2::XMLAttribute::IntValue() const
        }

        element->SetAttribute("longAttr", fdp.ConsumeIntegral<long>());
        if (const tinyxml2::XMLAttribute* longAttr = element->FindAttribute("longAttr")) {
            longAttr->Int64Value(); // tinyxml2::XMLAttribute::Int64Value() const
        }

        element->SetAttribute("unsignedAttr", fdp.ConsumeIntegral<unsigned int>());
        if (const tinyxml2::XMLAttribute* unsignedAttr = element->FindAttribute("unsignedAttr")) {
            unsignedAttr->UnsignedValue(); // tinyxml2::XMLAttribute::UnsignedValue() const
        }

        element->SetAttribute("unsignedLongAttr", fdp.ConsumeIntegral<unsigned long>());
        if (const tinyxml2::XMLAttribute* unsignedLongAttr = element->FindAttribute("unsignedLongAttr")) {
            unsignedLongAttr->Unsigned64Value(); // tinyxml2::XMLAttribute::Unsigned64Value() const
        }

        element->SetAttribute("boolAttr", fdp.ConsumeBool());
        if (const tinyxml2::XMLAttribute* boolAttr = element->FindAttribute("boolAttr")) {
            boolAttr->BoolValue(); // tinyxml2::XMLAttribute::BoolValue() const
        }

        element->SetAttribute("doubleAttr", fdp.ConsumeFloatingPoint<double>());
        if (const tinyxml2::XMLAttribute* doubleAttr = element->FindAttribute("doubleAttr")) {
            doubleAttr->DoubleValue(); // tinyxml2::XMLAttribute::DoubleValue() const
        }

        element->SetAttribute("floatAttr", fdp.ConsumeFloatingPoint<float>());
        if (const tinyxml2::XMLAttribute* floatAttr = element->FindAttribute("floatAttr")) {
            floatAttr->FloatValue(); // tinyxml2::XMLAttribute::FloatValue() const
        }

        // GetLineNum can be called on the original 'attr' if it's still valid
        attr->GetLineNum(); // tinyxml2::XMLAttribute::GetLineNum() const
    }
  }

  // Fuzzing tinyxml2::StrPair::CollapseWhitespace()
  // This function had 0% coverage and is called when parsing with XML_WHITESPACE_COLLAPSE.
  {
    // Create a new document with XML_WHITESPACE_COLLAPSE mode.
    // Corrected: Use tinyxml2::Whitespace::COLLAPSE_WHITESPACE
    std::unique_ptr<tinyxml2::XMLDocument> collapseDoc(new tinyxml2::XMLDocument(false, tinyxml2::Whitespace::COLLAPSE_WHITESPACE));
    // Parse XML with excessive whitespace to trigger the collapse logic.
    std::string xmlWithWhitespace = "<root>  <element>   text   </element>  </root>";
    collapseDoc->Parse(xmlWithWhitespace.c_str());
  }

  // Fuzzing tinyxml2::XMLPrinter::Print(char const*, ...)
  // This section is removed as Print is a protected member and cannot be called directly.
  // The existing XMLPrinter fuzzing covers its public interface.

  // Fuzzing tinyxml2::StrPair::SetInternedStr(char const*)
  // This function had 0% coverage and is called when XMLElement::SetName is called with interned=true.
  {
    tinyxml2::XMLElement* element = doc->NewElement("InternedNameElement");
    doc->InsertEndChild(element);
    std::string name = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange(1, 20));
    element->SetName(name.c_str(), true); // Set interned to true to cover StrPair::SetInternedStr
  }

  // Fuzzing XMLDocument::SetBOM(bool)
  // This function had 0% coverage.
  {
    doc->SetBOM(fdp.ConsumeBool());
  }

  // Fuzzing XMLDocument::ErrorLineNum() const
  // This function had 0% coverage.
  {
    // Create a new document and induce an error to get an error line number.
    std::unique_ptr<tinyxml2::XMLDocument> errorDocForLineNum(new tinyxml2::XMLDocument());
    errorDocForLineNum->Parse("<invalid xml"); // Induce a parsing error
    errorDocForLineNum->ErrorLineNum(); // Call ErrorLineNum()
  }

  // Fuzzing ShallowClone and ShallowEqual methods for various node types.
  // Many of these had 0% coverage.
  {
    tinyxml2::XMLDocument* docPtr = doc.get();

    // XMLDocument::ShallowClone and ShallowEqual
    std::unique_ptr<tinyxml2::XMLDocument> cloneDoc(new tinyxml2::XMLDocument());
    docPtr->ShallowClone(cloneDoc.get());
    docPtr->ShallowEqual(cloneDoc.get());
    docPtr->ShallowEqual(docPtr->NewElement("dummy")); // Test false case for ShallowEqual

    // Create a new element for this section to avoid "undeclared identifier 'element'"
    tinyxml2::XMLElement* currentElement = docPtr->NewElement("ShallowTestElement");
    docPtr->InsertEndChild(currentElement); // Link to document for memory management

    // XMLElement::ShallowEqual
    tinyxml2::XMLElement* elem1 = docPtr->NewElement("SameElement");
    tinyxml2::XMLElement* elem2 = docPtr->NewElement("SameElement");
    currentElement->InsertEndChild(elem1); // Link to currentElement for memory management
    currentElement->InsertEndChild(elem2);
    elem1->ShallowEqual(elem2);
    elem1->ShallowEqual(docPtr->NewElement("DifferentElement")); // Test false case

    // XMLText::ShallowEqual
    tinyxml2::XMLText* text1 = docPtr->NewText("SameText");
    tinyxml2::XMLText* text2 = docPtr->NewText("SameText");
    currentElement->InsertEndChild(text1);
    currentElement->InsertEndChild(text2);
    text1->ShallowEqual(text2);
    text1->ShallowEqual(docPtr->NewText("DifferentText"));

    // XMLComment::ShallowEqual
    tinyxml2::XMLComment* comment1 = docPtr->NewComment("SameComment");
    tinyxml2::XMLComment* comment2 = docPtr->NewComment("SameComment");
    currentElement->InsertEndChild(comment1);
    currentElement->InsertEndChild(comment2);
    comment1->ShallowEqual(comment2);
    comment1->ShallowEqual(docPtr->NewComment("DifferentComment"));

    // XMLDeclaration::ShallowEqual
    tinyxml2::XMLDeclaration* decl1 = docPtr->NewDeclaration("SameDecl");
    tinyxml2::XMLDeclaration* decl2 = docPtr->NewDeclaration("SameDecl");
    currentElement->InsertEndChild(decl1);
    currentElement->InsertEndChild(decl2);
    decl1->ShallowEqual(decl2);
    decl1->ShallowEqual(docPtr->NewDeclaration("DifferentDecl"));

    // XMLUnknown::ShallowEqual
    tinyxml2::XMLUnknown* unk1 = docPtr->NewUnknown("SameUnknown");
    tinyxml2::XMLUnknown* unk2 = docPtr->NewUnknown("SameUnknown");
    currentElement->InsertEndChild(unk1);
    currentElement->InsertEndChild(unk2);
    unk1->ShallowEqual(unk2);
    unk1->ShallowEqual(docPtr->NewUnknown("DifferentUnknown"));
  }

  // Fuzzing XMLPrinter with more complex document structure to exercise DynArray.
  // This aims to improve coverage for DynArray<char const*, 10ul>::EnsureCapacity and its destructor.
  {
    tinyxml2::XMLPrinter printer;
    printer.OpenElement("root");
    printer.OpenElement("child1");
    printer.PushAttribute("attr1", "value1");
    printer.PushText("Some text here.");
    printer.CloseElement(); // Close child1
    printer.OpenElement("child2");
    printer.PushComment("This is a comment.");
    printer.CloseElement(); // Close child2
    printer.CloseElement(); // Close root
    printer.CStr(); // tinyxml2::XMLPrinter::CStr() const (had 0% coverage)
    printer.CStrSize(); // tinyxml2::XMLPrinter::CStrSize() const (had 0% coverage)
    printer.ClearBuffer();
  }

  // The std::unique_ptr 'doc' will automatically call the XMLDocument destructor
  // at the end of the function scope, which in turn frees all associated XML nodes
  // and attributes, ensuring no memory leaks. Stack-allocated objects like 'printer'
  // are also automatically destructed. All new XMLDocuments created with std::unique_ptr
  // are also properly managed.

  return 0;
}