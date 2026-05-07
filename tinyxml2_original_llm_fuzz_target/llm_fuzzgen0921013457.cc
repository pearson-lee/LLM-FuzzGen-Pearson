#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <memory> // For std::unique_ptr
#include <cstdio> // For FILE operations
#include <unistd.h> // For unlink

#include <fuzzer/FuzzedDataProvider.h>

#include "/src/tinyxml2/tinyxml2.h"

// Custom XMLVisitor to cover the virtual Visit/VisitEnter/VisitExit methods.
// All methods simply return true to continue traversal.
class MyXMLVisitor : public tinyxml2::XMLVisitor {
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

    // Create a tinyxml2 document. Using unique_ptr for RAII.
    // Replaced std::make_unique with new T() for broader compiler compatibility.
    std::unique_ptr<tinyxml2::XMLDocument> doc(new tinyxml2::XMLDocument());

    // Consume data for parsing XML
    std::string xml_string = fdp.ConsumeRandomLengthString(fdp.remaining_bytes() / 2);
    if (xml_string.empty() && fdp.remaining_bytes() > 0) {
        xml_string = fdp.ConsumeRemainingBytesAsString();
    }

        /*
     * ANALYSIS: Line 1170 in XMLNode::ParseDeep requires a scenario where:
     *           - endTag is not empty (line 1169: else branch)
     *           - ele->ClosingType() != XMLElement::OPEN
     *           This happens when there's a self-closing tag followed by an unmatched end tag.
     * IMPLEMENTATION: Add specific test cases to trigger this XML parsing error scenario.
     */
    if (fdp.ConsumeBool() && fdp.remaining_bytes() > 10) {
        // Generate malformed XML with self-closing tag followed by mismatched end tag
        std::string tag_name = fdp.ConsumeBytesAsString(fdp.ConsumeIntegralInRange<size_t>(1, 10));
        if (!tag_name.empty()) {
            // Create variations of malformed XML
            switch (fdp.ConsumeIntegralInRange<int>(0, 3)) {
                case 0:
                    // Self-closing tag with unexpected end tag
                    xml_string = "<root><" + tag_name + "/></" + tag_name + "></root>";
                    break;
                case 1:
                    // Nested structure with self-closing and mismatched end
                    xml_string = "<root><outer><" + tag_name + "/></outer></" + tag_name + "></root>";
                    break;
                case 2:
                    // Empty element with duplicate end tag
                    xml_string = "<root><" + tag_name + "></" + tag_name + "></" + tag_name + "></root>";
                    break;
                case 3:
                    // Multiple nested self-closing with wrong end
                    xml_string = "<a><b><c/></b></c></a>";
                    break;
            }
        }
    }



    doc->Parse(xml_string.c_str());

    /*
     * ANALYSIS: The function-level coverage report showed tinyxml2::XMLVisitor::VisitEnter,
     *           VisitExit, and Visit methods had 0% line and branch coverage.
     * IMPLEMENTATION: An instance of MyXMLVisitor (which overrides all virtual methods)
     *                 is created, and XMLDocument::Accept is called to traverse the document,
     *                 thereby exercising these previously uncovered visitor methods.
     */
    MyXMLVisitor visitor;
    doc->Accept(&visitor);

    // Fuzzing XMLNode deletion via public API
    // Direct calls to tinyxml2::XMLNode::DeleteNode are removed as it is a private member.
    // Instead, we rely on public APIs like DeleteChild.
    tinyxml2::XMLNode* child = doc->FirstChild();
    if (child) {
        doc->DeleteChild(child); // This calls XMLNode::DeleteNode internally
    }

    // Fuzzing XMLElement::DeleteAttribute(const char* name)
    // Direct calls to tinyxml2::XMLElement::DeleteAttribute are removed as it is a private member.
    tinyxml2::XMLElement* rootElement = doc->RootElement();
    if (rootElement) {
        const tinyxml2::XMLAttribute* attr = rootElement->FirstAttribute(); // Const-correctness fix
        if (attr) {
            // Use the public DeleteAttribute(const char* name) method
            rootElement->DeleteAttribute(attr->Name());
        }
    }
    // New: Trigger XMLNode::InsertChildPreamble branch where insertThis->_parent != nullptr
    // Move an already parented node into a new parent in the same document.
    // This forces InsertChildPreamble to take the unlink path (line 1208).
    {
        tinyxml2::XMLElement* root = doc->RootElement();
        if (root) {
            // Ensure there is at least one child under root to move.
            tinyxml2::XMLNode* nodeToMove = root->FirstChild();
            if (!nodeToMove) {
                // If no child exists, create one so it gets parented by root.
                tinyxml2::XMLElement* tempChild = doc->NewElement("TempChild");
                root->InsertEndChild(tempChild);
                nodeToMove = tempChild;
            }
            // Create a new parent element in the same document.
            tinyxml2::XMLElement* newParent = doc->NewElement("NewParent");
            // Insert new parent under root (so it is part of the tree).
            root->InsertEndChild(newParent);
            // Now move the existing node into newParent. nodeToMove already has a parent,
            // so InsertChildPreamble will see insertThis->_parent != nullptr and unlink it.
            newParent->InsertEndChild(nodeToMove);
        }
    }

    // Fuzzing XMLDocument::LoadFile(_IO_FILE*)
    // Create a unique temporary file path
    std::string temp_filepath = std::string("/tmp/") + _FUZZ_TARGET_NAME + ".tmp";
    FILE* fp = nullptr;

    /*
     * ANALYSIS: The line-level coverage for tinyxml2::XMLDocument::LoadFile(_IO_FILE*)
     *           at line 2396 showed the branch `if ( filelength == 0 )` was taken,
     *           but line 2368 (inner branch `ferror(fp) != 0`) and line 2379
     *           (`fileLengthSigned == -1L`), and line 2405 (`read != size`) were not.
     * IMPLEMENTATION: We will try to trigger the `filelength == 0` by sometimes creating an empty file.
     *                 Other branches are harder to trigger deterministically in a fuzzer.
     */
    if (fdp.ConsumeBool()) { // Sometimes create an empty file to hit filelength == 0
        fp = fopen(temp_filepath.c_str(), "wb");
        if (fp) {
            fclose(fp); // Close the empty file
            fp = fopen(temp_filepath.c_str(), "rb"); // Reopen for reading
        }
    } else {
        fp = fopen(temp_filepath.c_str(), "wb");
        if (fp) {
            std::string file_content = fdp.ConsumeRandomLengthString(fdp.remaining_bytes() / 2);
            if (!file_content.empty()) {
                fwrite(file_content.c_str(), 1, file_content.length(), fp);
            }
            fclose(fp); // Close after writing
            fp = fopen(temp_filepath.c_str(), "rb"); // Reopen for reading
        }
    }

    if (fp) {
        tinyxml2::XMLDocument file_doc;
        file_doc.LoadFile(fp); 
        fclose(fp);
    }
    unlink(temp_filepath.c_str()); // Clean up the temporary file

    // Fuzzing XMLDocument::PushDepth()
    /*
     * ANALYSIS: The line-level coverage for tinyxml2::XMLDocument::PushDepth()
     *           at line 2569 showed the branch `if (_parsingDepth == TINYXML2_MAX_ELEMENT_DEPTH)`
     *           was never taken.
     * IMPLEMENTATION: We generate a deeply nested XML string to try and exceed
     *                 TINYXML2_MAX_ELEMENT_DEPTH, thereby exercising this branch.
     */
    if (fdp.ConsumeBool()) {
        std::string deep_xml = "<root>";
        // TINYXML2_MAX_ELEMENT_DEPTH is a macro defined in tinyxml2.h
        for (int i = 0; i < TINYXML2_MAX_ELEMENT_DEPTH + 5; ++i) { // Go beyond max depth
            deep_xml += "<A>";
        }
        deep_xml += "content";
        for (int i = 0; i < TINYXML2_MAX_ELEMENT_DEPTH + 5; ++i) {
            deep_xml += "</A>";
        }
        deep_xml += "</root>";
        tinyxml2::XMLDocument deep_doc;
        deep_doc.Parse(deep_xml.c_str());
    }

    {
        tinyxml2::XMLElement* root = doc->RootElement();
        if (!root) {
            root = doc->NewElement("root");
            doc->InsertEndChild(root);
        }
        // 建立子元素並以 staticMem=true 設定名稱，觸發 XMLNode::SetValue 的 staticMem 分支
        tinyxml2::XMLElement* staticElem = doc->NewElement("temp");
        root->InsertEndChild(staticElem);
        staticElem->SetName("STATIC_NAME", true);
    }
    
    return 0;
}