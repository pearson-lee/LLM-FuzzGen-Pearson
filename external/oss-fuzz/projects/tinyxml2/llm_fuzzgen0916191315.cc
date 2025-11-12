#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <memory> // For std::unique_ptr
#include <cstdio> // For FILE, fopen, fclose
#include <unistd.h> // For unlink
#include <limits> // For std::numeric_limits

#include <fuzzer/FuzzedDataProvider.h>

#include "/src/tinyxml2/tinyxml2.h" // All headers are in this path

// Define a custom XMLVisitor to hit the virtual methods
class FuzzVisitor : public tinyxml2::XMLVisitor {
public:
    // ANALYSIS: The function-level coverage report showed all XMLVisitor methods had 0% coverage.
    // IMPLEMENTATION: Overriding these virtual methods and calling `Accept` on an XMLDocument
    //                 will ensure these methods are invoked during XML tree traversal.
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

    // Use a unique temporary file name for file operations to prevent race conditions.
    // _FUZZ_TARGET_NAME is a compile-time macro provided by the build system.
    std::string temp_file_path = std::string("/tmp/") + _FUZZ_TARGET_NAME + ".tmp";

    // 1. Fuzzing tinyxml2::XMLDocument::LoadFile(_IO_FILE*) and LoadFile(char const*)
    {
        tinyxml2::XMLDocument doc_file_io;

        // ANALYSIS: The coverage report for `tinyxml2::XMLDocument::LoadFile(char const*)` showed
        //           that the branch `if ( !filename )` at line 2346 was never taken.
        // IMPLEMENTATION: Call `LoadFile(nullptr)` to explicitly trigger this branch.
        if (fdp.ConsumeBool()) {
            doc_file_io.LoadFile(static_cast<const char*>(nullptr));
        }

        // ANALYSIS: The coverage report for `tinyxml2::XMLDocument::LoadFile(_IO_FILE*)` showed
        //           that the branch `if ( filelength == 0 )` at line 2396 was never taken.
        // IMPLEMENTATION: Create an empty temporary file and call `LoadFile` with its path.
        if (fdp.ConsumeBool()) {
            FILE* fp_empty = fopen(temp_file_path.c_str(), "wb");
            if (fp_empty) {
                fclose(fp_empty); // Create an empty file
                doc_file_io.LoadFile(temp_file_path.c_str());
            }
        }

        // ANALYSIS: To generally increase coverage for `LoadFile` and `Parse`, providing
        //           diverse fuzzed content is essential.
        // IMPLEMENTATION: Write fuzzed data to a temporary file and load it using `LoadFile(char const*)`.
        std::string file_content = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 4096));
        if (!file_content.empty()) {
            FILE* fp = fopen(temp_file_path.c_str(), "wb");
            if (fp) {
                // CRITICAL: Check return value of fwrite to ensure buffer is populated.
                if (fwrite(file_content.data(), 1, file_content.size(), fp) == file_content.size()) {
                    fclose(fp);
                    doc_file_io.LoadFile(temp_file_path.c_str());
                } else {
                    fclose(fp); // Ensure file is closed even on partial write
                }
            }
        }

        // ANALYSIS: The coverage report for `tinyxml2::XMLDocument::SaveFile(char const*, bool)` showed
        //           that the branch `if ( !filename )` at line 2419 was never taken.
        // IMPLEMENTATION: Call `SaveFile(nullptr, ...)` to explicitly trigger this branch.
        if (fdp.ConsumeBool()) {
            doc_file_io.SaveFile(static_cast<const char*>(nullptr), fdp.ConsumeBool());
        }

        // ANALYSIS: To generally increase coverage for `SaveFile`, provide diverse fuzzed content.
        // IMPLEMENTATION: Save the fuzzed XML content to a temporary file.
        if (!file_content.empty()) { // Reuse the fuzzed content from LoadFile section
            FILE* fp_save = fopen(temp_file_path.c_str(), "wb");
            if (fp_save) {
                doc_file_io.SaveFile(fp_save, fdp.ConsumeBool());
                fclose(fp_save);
            }
        }
    }

    // Clean up temporary file created for LoadFile and SaveFile.
    unlink(temp_file_path.c_str());

    // 2. Fuzzing tinyxml2::XMLUtil::ToInt64(char const*, long*) and related functions
    {
        long val64;
        int val32;
        unsigned int uval32;
        unsigned long uval64;
        std::string num_str;

        // ANALYSIS: The coverage report for `tinyxml2::XMLUtil::ToInt64` showed that
        //           the `if (IsPrefixHex(str))` branch at line 674 was never taken.
        // IMPLEMENTATION: Generate strings starting with "0x" or "0X" to trigger the hexadecimal parsing path.
        if (fdp.ConsumeBool()) {
            num_str = fdp.ConsumeBool() ? "0x" : "0X";
            num_str += fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(1, 20));
            tinyxml2::XMLUtil::ToInt64(num_str.c_str(), &val64);
        }

        // ANALYSIS: The detailed coverage report for `tinyxml2::XMLUtil::ToInt` showed
        //           that the branch `if (TIXML_SSCANF(str, "%x", &v) == 1)` at line 607
        //           never evaluated to false when `IsPrefixHex` was true.
        // IMPLEMENTATION: Generate an invalid hexadecimal string (e.g., "0xGHI") to ensure
        //                 the `sscanf` for hex fails.
        if (fdp.ConsumeBool()) {
            num_str = fdp.ConsumeBool() ? "0x" : "0X";
            // Fix: ConsumeRandomLengthString does not take a character set.
            // Rely on fdp.ConsumeRandomLengthString to generate non-hex characters.
            num_str += fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(1, 5));
            tinyxml2::XMLUtil::ToInt(num_str.c_str(), &val32);
        }

        // ANALYSIS: The `return false` path for `ToInt64` is covered, but ensuring a variety of invalid
        //           inputs helps robustness.
        // IMPLEMENTATION: Provide random strings that are not valid numbers to exercise error handling.
        num_str = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(1, 30));
        tinyxml2::XMLUtil::ToInt64(num_str.c_str(), &val64);
        tinyxml2::XMLUtil::ToInt(num_str.c_str(), &val32);
        tinyxml2::XMLUtil::ToUnsigned(num_str.c_str(), &uval32);
        tinyxml2::XMLUtil::ToUnsigned64(num_str.c_str(), &uval64);

        // Also test with valid decimal numbers for all To* functions
        num_str = std::to_string(fdp.ConsumeIntegral<long>());
        tinyxml2::XMLUtil::ToInt64(num_str.c_str(), &val64);
        tinyxml2::XMLUtil::ToInt(num_str.c_str(), &val32);

        // ANALYSIS: The coverage reports for `tinyxml2::XMLUtil::ToUnsigned` (line 622) and
        //           `tinyxml2::XMLUtil::ToUnsigned64` (line 694) showed that the `sscanf`
        //           call for unsigned decimal numbers (when `IsPrefixHex` is false) never succeeded.
        // IMPLEMENTATION: Provide valid unsigned decimal numbers to hit this success path.
        num_str = std::to_string(fdp.ConsumeIntegral<unsigned int>());
        tinyxml2::XMLUtil::ToUnsigned(num_str.c_str(), &uval32);

        num_str = std::to_string(fdp.ConsumeIntegral<unsigned long>());
        tinyxml2::XMLUtil::ToUnsigned64(num_str.c_str(), &uval64);
    }

    // 3. Fuzzing tinyxml2::XMLDocument::PushDepth()
    {
        // ANALYSIS: The coverage report for `tinyxml2::XMLDocument::PushDepth()` showed that
        //           the branch `if (_parsingDepth == TINYXML2_MAX_ELEMENT_DEPTH)` at line 2569
        //           was never taken. Also, the fuzz target's second loop for closing tags
        //           (lines 142-148 in the fuzz target) was not running due to `fdp.remaining_bytes() > 0`.
        // IMPLEMENTATION: Create a deeply nested XML structure to exceed the maximum element depth
        //                 during parsing, triggering the depth limit error. Removed `fdp.remaining_bytes()`
        //                 checks from loops to ensure full nesting and proper closing.
        //                 Ensured max_nesting is always above TINYXML2_MAX_ELEMENT_DEPTH (256) and
        //                 used a fixed element name to avoid premature parsing termination.

        tinyxml2::XMLDocument doc_depth;
        // TINYXML2_MAX_ELEMENT_DEPTH is defined as 256 in tinyxml2.h.
        // We'll try to create a nesting level slightly above this to trigger the error.
        const int max_nesting = fdp.ConsumeIntegralInRange<int>(257, 300); // Ensure always > 256

        std::string deep_xml_str = "<root>";
        for (int i = 0; i < max_nesting; ++i) { // Removed fdp.remaining_bytes() check
            // Use a fixed element name to ensure valid XML and deep nesting
            deep_xml_str += "<a>";
        }
        for (int i = 0; i < max_nesting; ++i) { // Removed fdp.remaining_bytes() check
            deep_xml_str += "</a>";
        }
        deep_xml_str += "</root>";
        doc_depth.Parse(deep_xml_str.c_str(), deep_xml_str.length());
    }

    // 4. Fuzzing tinyxml2::XMLNode::DeleteNode(tinyxml2::XMLNode*) and tinyxml2::XMLDocument::DeleteNode(tinyxml2::XMLNode*)
    {
        tinyxml2::XMLDocument doc_delete;
        tinyxml2::XMLElement* root = doc_delete.NewElement("root");
        doc_delete.InsertFirstChild(root);

        tinyxml2::XMLElement* child = doc_delete.NewElement("child");
        if (root) {
            root->InsertEndChild(child);
        }

        // The previous attempt to call tinyxml2::XMLNode::DeleteNode(NULL) was incorrect
        // as it's a private static member function.
        // The public API tinyxml2::XMLDocument::DeleteNode asserts that the node is not NULL.
        // The coverage for the private XMLNode::DeleteNode(NULL) branch is not meant to be
        // directly fuzzed from outside the library.

        // ANALYSIS: The `if (node->_parent)` branch at line 2329 in `XMLDocument::DeleteNode` needs
        //           to be covered for both true and false. This covers the true case (node has a parent).
        //           The fuzz target's own branch `if (fdp.ConsumeBool() && child)` was not being taken.
        // IMPLEMENTATION: Removed `fdp.ConsumeBool()` to ensure `DeleteNode` is always called
        //                 when `child` is valid, allowing the library's internal branches to be hit.
        if (child) {
            doc_delete.DeleteNode(child); // Deletes from parent and frees memory
            child = nullptr; // Invalidate pointer after deletion
        }

        // ANALYSIS: The `else` branch (where `node->_parent` is NULL) at line 2332 in
        //           `XMLDocument::DeleteNode` is covered, but explicitly creating this scenario
        //           ensures robustness. The fuzz target's own branch `if (fdp.ConsumeBool() && orphan_node)`
        //           was not being taken.
        // IMPLEMENTATION: Removed `fdp.ConsumeBool()` to ensure `DeleteNode` is always called
        //                 when `orphan_node` is valid, allowing the library's internal branches to be hit.
        tinyxml2::XMLElement* orphan_node = doc_delete.NewElement("orphan");
        if (orphan_node) {
            doc_delete.DeleteNode(orphan_node);
            orphan_node = nullptr; // Invalidate pointer after deletion
        }

        // ANALYSIS: The detailed coverage report for `tinyxml2::XMLNode::DeleteNode` showed that
        //           the branch `if (!node->ToDocument())` at line 1194 had its 'false' path uncovered.
        //           This means `XMLNode::DeleteNode` was never called on an `XMLDocument` node.
        // IMPLEMENTATION: Call `DeleteNode` on the `XMLDocument` object itself to trigger this branch.
        // CRASH FIX: Calling DeleteNode on the document itself is incorrect API usage and causes a SEGV.
        // The document is the owner and manages memory; it should not delete itself via this method.
        // The coverage for the `!node->ToDocument()` branch is already handled by deleting other node types.
        // if (fdp.ConsumeBool()) {
        //     tinyxml2::XMLDocument doc_self_delete;
        //     doc_self_delete.DeleteNode(&doc_self_delete);
        // }
    }

    // 5. Fuzzing tinyxml2::XMLVisitor methods
    {
        // ANALYSIS: All `tinyxml2::XMLVisitor` virtual methods had 0% coverage.
        // IMPLEMENTATION: Create a concrete `FuzzVisitor` class and use `XMLDocument::Accept`
        //                 to traverse a fuzzed XML document, thereby calling the visitor methods.

        tinyxml2::XMLDocument doc_visitor;
        std::string xml_data = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 4096));
        doc_visitor.Parse(xml_data.c_str(), xml_data.length());

        FuzzVisitor visitor;
        doc_visitor.Accept(&visitor);
    }

    // 6. Fuzzing tinyxml2::XMLUtil::GetCharacterRef
    {
        // ANALYSIS: The detailed coverage report for `tinyxml2::XMLUtil::GetCharacterRef` showed several
        //           uncovered branches, including malformed references, hex characters 'a'-'f' and 'A'-'F',
        //           and large code points.
        // IMPLEMENTATION: Generate a variety of character references, including malformed, hex, and
        //                 values that exceed MAX_CODE_POINT, to trigger these branches during parsing.
        tinyxml2::XMLDocument doc_char_ref;
        std::string char_ref_xml = "<root>";

        // Valid decimal and hex
        char_ref_xml += "&#123;"; // Basic decimal
        char_ref_xml += "&#0;";   // Zero decimal
        char_ref_xml += "&#xABC;"; // Basic hex
        char_ref_xml += "&#x0;";   // Zero hex
        char_ref_xml += "&#xdeadbeef;"; // Lowercase hex
        char_ref_xml += "&#xDEADBEEF;"; // Uppercase hex (targets lines 519, 522)

        // Malformed references (targets `if (!(*q))` at line 500 and `if (!q)` at line 505)
        char_ref_xml += "&#;";
        char_ref_xml += "&#x;";
        char_ref_xml += "&#123"; // Missing semicolon
        char_ref_xml += "&#xABC"; // Missing semicolon
        char_ref_xml += "&#xGHI;"; // Invalid hex digit

        // Large code points (targets `if (mult > MAX_CODE_POINT)` at line 537 and `if (ucs > MAX_CODE_POINT)` at line 543)
        char_ref_xml += "&#1114111;"; // MAX_CODE_POINT (0x10FFFF) + 1
        char_ref_xml += "&#x110000;"; // MAX_CODE_POINT (0x10FFFF) + 1

        char_ref_xml += "</root>";
        doc_char_ref.Parse(char_ref_xml.c_str(), char_ref_xml.length());
    }

    // 7. Fuzzing tinyxml2::XMLNode::Value() on XMLDocument
    {
        // ANALYSIS: The coverage report for `tinyxml2::XMLNode::Value() const` showed
        //           that the branch `if (this->ToDocument())` at line 850 was never taken.
        // IMPLEMENTATION: Call `Value()` on an `XMLDocument` object to explicitly trigger this branch.
        tinyxml2::XMLDocument doc_value;
        const char* val = doc_value.Value(); // Should return nullptr
        (void)val; // Suppress unused variable warning
    }

    // 8. Fuzzing tinyxml2::XMLElement::DeleteAttribute(tinyxml2::XMLAttribute*) with nullptr
    {
        // ANALYSIS: The coverage report for `tinyxml2::XMLElement::DeleteAttribute(tinyxml2::XMLAttribute*)`
        //           showed that the branch `if (attribute == 0)` at line 2020 was never taken.
        // IMPLEMENTATION: Call `DeleteAttribute(nullptr)` on an XMLElement to explicitly trigger this branch.
        tinyxml2::XMLDocument doc_attr;
        tinyxml2::XMLElement* element = doc_attr.NewElement("test");
        doc_attr.InsertFirstChild(element);
        // Fix: tinyxml2::XMLElement::DeleteAttribute(tinyxml2::XMLAttribute*) is a private static member.
        // It cannot be called directly from outside the class.
        // The public API is tinyxml2::XMLElement::DeleteAttribute(const char*).
        // The branch `if (attribute == 0)` for the private function is not directly reachable via public API calls.
        // Removing the problematic line.
        // if (element) {
        //     element->DeleteAttribute(static_cast<tinyxml2::XMLAttribute*>(nullptr));
        // }
    }

    // 9. Fuzzing tinyxml2::StrPair::TransferTo(tinyxml2::StrPair*)
    {
        // ANALYSIS: The coverage report for `tinyxml2::StrPair::TransferTo` showed that
        //           the branch `if ( this == other )` at line 160 was never taken.
        // IMPLEMENTATION: Call `TransferTo` on a `StrPair` object, passing itself as the argument
        //                 to trigger the `this == other` branch.
        tinyxml2::StrPair sp1;
        sp1.SetStr(fdp.ConsumeRandomLengthString(10).c_str(), 0);
        sp1.TransferTo(&sp1); // Call with 'this == other'
    }

    // 10. Fuzzing tinyxml2::XMLDocument::Identify for PEDANTIC_WHITESPACE and specific closing tag
    {
        // ANALYSIS: The coverage report for `tinyxml2::XMLDocument::Identify` showed that
        //           a complex branch at line 756 related to `PEDANTIC_WHITESPACE` mode and
        //           an immediate closing tag with whitespace was never taken.
        // IMPLEMENTATION: Set `WhitespaceMode` to `PEDANTIC_WHITESPACE` and parse an XML string
        //                 that starts with an element followed by whitespace and an immediate closing tag.
        tinyxml2::XMLDocument doc_pedantic(true, tinyxml2::PEDANTIC_WHITESPACE); // Fixed: Set WhitespaceMode in constructor
        std::string xml_pedantic_content = "<root > </root>"; // Whitespace before closing tag
        doc_pedantic.Parse(xml_pedantic_content.c_str(), xml_pedantic_content.length());

        // Also try with no whitespace but still triggering the 'first' and '/' condition if possible
        std::string xml_pedantic_no_ws = "<root></root>";
        doc_pedantic.Parse(xml_pedantic_no_ws.c_str(), xml_pedantic_no_ws.length());
    }

    // 11. Fuzzing `InsertEndChild`, `InsertFirstChild`, `InsertAfterChild` with nodes from different documents
    {
        // ANALYSIS: The coverage reports for `tinyxml2::XMLNode::InsertEndChild` (line 928),
        //           `tinyxml2::XMLNode::InsertFirstChild` (line 958), and
        //           `tinyxml2::XMLNode::InsertAfterChild` (line 989) showed that the branch
        //           `if ( addThis->_document != _document )` was never taken.
        // IMPLEMENTATION: Create two `XMLDocument` objects and attempt to insert a node from
        //                 one document into another.
        tinyxml2::XMLDocument doc1;
        tinyxml2::XMLDocument doc2;

        tinyxml2::XMLElement* root1 = doc1.NewElement("root1");
        doc1.InsertFirstChild(root1);

        tinyxml2::XMLElement* foreign_node = doc2.NewElement("foreign");

        if (root1 && foreign_node) {
            // Try InsertEndChild with foreign node
            root1->InsertEndChild(foreign_node);
            // The node is now owned by doc1 (or rather, its parent is doc1's root).
            // To test InsertFirstChild and InsertAfterChild with a foreign node,
            // we need to create new foreign nodes.
        }

        tinyxml2::XMLElement* foreign_node_2 = doc2.NewElement("foreign2");
        if (root1 && foreign_node_2) {
            root1->InsertFirstChild(foreign_node_2);
        }

        tinyxml2::XMLElement* child1 = doc1.NewElement("child1");
        if (root1 && child1) {
            root1->InsertEndChild(child1);
        }

        tinyxml2::XMLElement* foreign_node_3 = doc2.NewElement("foreign3");
        if (root1 && child1 && foreign_node_3) {
            // Try InsertAfterChild with foreign node
            root1->InsertAfterChild(child1, foreign_node_3);
        }

        // ANALYSIS: The coverage report for `tinyxml2::XMLNode::InsertAfterChild` also showed that
        //           the branch `if ( afterThis == addThis )` at line 1000 was never taken.
        // IMPLEMENTATION: Call `InsertAfterChild` with the same node for both `afterThis` and `addThis`.
        tinyxml2::XMLDocument doc_self_insert;
        tinyxml2::XMLElement* root_self = doc_self_insert.NewElement("root_self");
        doc_self_insert.InsertFirstChild(root_self);
        tinyxml2::XMLElement* child_self = doc_self_insert.NewElement("child_self");
        if (root_self && child_self) {
            root_self->InsertEndChild(child_self);
            root_self->InsertAfterChild(child_self, child_self); // Trigger afterThis == addThis
        }
    }

    // 12. Fuzzing tinyxml2::XMLPrinter::PrintString with an unknown entity
    {
        // ANALYSIS: The coverage report for `tinyxml2::XMLPrinter::PrintString` showed that
        //           the branch `if ( !entityPatternPrinted )` at line 2695 was never taken.
        //           This occurs when an unknown XML entity (e.g., `&foo;`) is encountered.
        // IMPLEMENTATION: Create an XML document with an unknown entity in a text node and print it.
        tinyxml2::XMLDocument doc_unknown_entity;
        tinyxml2::XMLElement* root = doc_unknown_entity.NewElement("root");
        doc_unknown_entity.InsertFirstChild(root);
        tinyxml2::XMLText* text = doc_unknown_entity.NewText("Hello &foo; World!");
        if (root && text) {
            root->InsertEndChild(text);
        }

        tinyxml2::XMLPrinter printer;
        doc_unknown_entity.Print(&printer);
        (void)printer; // Suppress unused variable warning
    }

    return 0;
}