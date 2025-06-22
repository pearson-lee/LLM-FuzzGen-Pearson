#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <memory> // For std::unique_ptr
#include <cstdio> // For va_list, vprintf, etc. (used by tinyxml2's Print)
#include <fuzzer/FuzzedDataProvider.h> // For FuzzedDataProvider

// Include tinyxml2 headers
#include "/src/tinyxml2/tinyxml2.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  FuzzedDataProvider fdp(Data, Size);

  // Fuzzing XMLDocument::Parse
  // This function is a primary entry point for parsing XML and indirectly
  // exercises XMLDocument::Identify and XMLNode::ParseDeep.
  // We set Whitespace::PEDANTIC_WHITESPACE to target specific uncovered branches in Identify.
  {
    std::string xml_input = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 4096));
    // Use new directly with unique_ptr as std::make_unique might not be available in older C++ standards.
    std::unique_ptr<tinyxml2::XMLDocument> doc(new tinyxml2::XMLDocument(true, tinyxml2::Whitespace::PEDANTIC_WHITESPACE));
    doc->Parse(xml_input.c_str(), xml_input.length());
  }

  // Fuzzing XMLUtil::GetCharacterRef
  // This function parses character references (e.g., &#x20AC;).
  // We generate various inputs to cover valid, malformed, and out-of-range references.
  {
    std::string char_ref_str;
    // Randomly choose between generating a valid or a malformed/large character reference
    if (fdp.ConsumeBool()) {
        // Generate a valid decimal or hexadecimal character reference
        if (fdp.ConsumeBool()) {
            char_ref_str = "&#" + std::to_string(fdp.ConsumeIntegralInRange<int>(0, 0x10FFFF)) + ";";
        } else {
            // Generate hexadecimal string using FuzzedDataProvider
            size_t hex_len = fdp.ConsumeIntegralInRange<size_t>(1, 6);
            std::string hex_digits = "";
            const char hex_chars[] = "0123456789abcdefABCDEF";
            for (size_t i = 0; i < hex_len; ++i) {
                hex_digits += fdp.PickValueInArray(hex_chars);
            }
            char_ref_str = "&#x" + hex_digits + ";";
        }
    } else {
        // Generate malformed or very large character references to hit uncovered branches:
        // 1. To trigger 'length == 0' from ConvertUTF32ToUTF8 (e.g., invalid Unicode scalar value).
        //    A very large hex value exceeding MAX_CODE_POINT (0x10FFFF) should achieve this.
        // 2. To trigger 'mult > MAX_CODE_POINT' branch in GetCharacterRef itself.
        if (fdp.ConsumeBool()) {
            // Very large hex
            size_t hex_len = 10; // Fixed length for large value
            std::string hex_digits = "";
            const char hex_chars[] = "0123456789abcdefABCDEF";
            for (size_t i = 0; i < hex_len; ++i) {
                hex_digits += fdp.PickValueInArray(hex_chars);
            }
            char_ref_str = "&#x" + hex_digits + ";";
        } else {
            // Very large decimal
            size_t dec_len = 10; // Fixed length for large value
            std::string dec_digits = "";
            const char dec_chars[] = "0123456789";
            for (size_t i = 0; i < dec_len; ++i) {
                dec_digits += fdp.PickValueInArray(dec_chars);
            }
            char_ref_str = "&#" + dec_digits + ";";
        }
    }

    // Ensure null termination for the input string
    std::vector<char> char_ref_buffer(char_ref_str.begin(), char_ref_str.end());
    char_ref_buffer.push_back('\0');
    const char* p_char_ref = char_ref_buffer.data();

    char value_buffer[10]; // Buffer to store the converted character (max 4 bytes for UTF-8 + null)
    int length = 0; // Length of the converted character

    tinyxml2::XMLUtil::GetCharacterRef(p_char_ref, value_buffer, &length);
  }

  // Fuzzing tinyxml2::XMLPrinter by using its public API.
  // The 'Print' method is protected, so we exercise the printer's internal
  // logic by calling public methods that generate XML output.
  {
    tinyxml2::XMLPrinter printer; // Default constructor, _fp is NULL

    std::string element_name = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(1, 32));
    std::string attribute_name = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(1, 32));
    std::string attribute_value = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 64));
    std::string text_content = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 128));

    printer.OpenElement(element_name.c_str());
    if (fdp.ConsumeBool()) {
        printer.PushAttribute(attribute_name.c_str(), attribute_value.c_str());
    }
    if (fdp.ConsumeBool()) {
        printer.PushText(text_content.c_str());
    }
    printer.CloseElement();

    // Also test printing a comment
    std::string comment_content = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 128));
    printer.PushComment(comment_content.c_str());

    // Test printing a declaration
    std::string declaration_content = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 128));
    printer.PushDeclaration(declaration_content.c_str());

    // Test printing a unknown
    std::string unknown_content = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 128));
    printer.PushUnknown(unknown_content.c_str());

    // The internal buffer of the printer will be automatically cleaned up when 'printer' goes out of scope.
  }

  // Fuzzing XMLElement::ParseAttributes is not directly possible as it's a private member.
  // This functionality is implicitly covered by fuzzing XMLDocument::Parse,
  // which internally calls ParseAttributes when parsing elements with attributes.
  // Therefore, the dedicated block for ParseAttributes is removed.

  // Fuzzing XMLNode::InsertAfterChild
  // This function inserts a node after another child node.
  // We create scenarios to hit previously uncovered branches related to document ownership,
  // parent-child relationships, and inserting the same node.
  {
    // Use two separate documents to test cross-document insertion scenarios
    std::unique_ptr<tinyxml2::XMLDocument> doc1(new tinyxml2::XMLDocument());
    std::unique_ptr<tinyxml2::XMLDocument> doc2(new tinyxml2::XMLDocument());

    // Create nodes within doc1
    tinyxml2::XMLElement* parent_node = doc1->NewElement("parent");
    tinyxml2::XMLElement* after_this_node = doc1->NewElement("afterThis");
    tinyxml2::XMLElement* add_this_node = doc1->NewElement("addThis");

    if (parent_node && after_this_node && add_this_node) {
        // Link after_this_node as a child of parent_node for valid scenarios
        parent_node->InsertEndChild(after_this_node);

        // Scenario 1: addThis->_document != _document (addThis from a different document)
        // This targets the branch at line 989: 'if ( addThis->_document != _document )'
        tinyxml2::XMLElement* add_this_from_doc2 = doc2->NewElement("addThisFromDoc2");
        if (add_this_from_doc2) {
            parent_node->InsertAfterChild(after_this_node, add_this_from_doc2);
        }

        // Scenario 2: afterThis->_parent != this (afterThis is not a child of parent_node)
        // This targets the branch at line 996: 'if ( afterThis->_parent != this )'
        tinyxml2::XMLElement* orphan_after_this = doc1->NewElement("orphanAfterThis"); // Not inserted into parent_node
        parent_node->InsertAfterChild(orphan_after_this, add_this_node);

        // Scenario 3: afterThis == addThis (inserting a node after itself)
        // This targets the branch at line 1000: 'if ( afterThis == addThis )'
        parent_node->InsertAfterChild(after_this_node, after_this_node);

        // Scenario 4: Normal insertion (afterThis is a child of parent_node, addThis is a new node)
        // This covers the main execution path.
        tinyxml2::XMLElement* new_add_this = doc1->NewElement("newAddThis");
        if (new_add_this) {
            parent_node->InsertAfterChild(after_this_node, new_add_this);
        }
    }
    // unique_ptr for doc1 and doc2 will ensure all allocated nodes are freed.
  }

  return 0;
}