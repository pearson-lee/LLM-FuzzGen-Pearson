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

        tinyxml2::XMLDocument doc_depth;
        // TINYXML2_MAX_ELEMENT_DEPTH is defined as 256 in tinyxml2.h.
        // We'll try to create a nesting level slightly above this to trigger the error.
        const int max_nesting = fdp.ConsumeIntegralInRange<int>(250, 300);

        std::string deep_xml_str = "<root>";
        for (int i = 0; i < max_nesting; ++i) { // Removed fdp.remaining_bytes() check
            std::string element_name = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(1, 5));
            if (element_name.empty()) {
                element_name = "a"; // Ensure element name is not empty
            }
            deep_xml_str += "<" + element_name + ">";
        }
        for (int i = 0; i < max_nesting; ++i) { // Removed fdp.remaining_bytes() check
            std::string element_name = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(1, 5));
            if (element_name.empty()) {
                element_name = "a";
            }
            deep_xml_str += "</" + element_name + ">";
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

    return 0;
}