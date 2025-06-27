#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>

// Include the tinyxml2 header with its full project-relative path.
#include "/src/tinyxml2/tinyxml2.h"

// Custom visitor class to exercise the virtual methods of tinyxml2::XMLVisitor.
// These methods are called when XMLDocument::Accept() is invoked.
class FuzzVisitor : public tinyxml2::XMLVisitor {
public:
    // Override all Visit and VisitEnter/Exit methods to ensure they are called.
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

    // Use a local scope to ensure all tinyxml2 objects (like doc and printer)
    // are properly destructed at the end of the function, which in turn
    // handles memory deallocation for nodes owned by the document.
    {
        tinyxml2::XMLDocument doc;

        // 1. Fuzz tinyxml2::XMLPrinter.
        // By using the default constructor, _fp (file pointer) will be NULL,
        // which forces XMLPrinter::Print to use its internal buffer and call TIXML_VSCPRINTF.
        tinyxml2::XMLPrinter printer;

        // 2. Fuzz tinyxml2::XMLDocument::Print(tinyxml2::XMLPrinter*) const.
        // Parse some fuzzed XML data into the document.
        std::string xml_string = fdp.ConsumeRandomLengthString(1024);
        doc.Parse(xml_string.c_str());

        // Call Print with a nullptr for the printer to hit the internal branch
        // where a default XMLPrinter is created.
        doc.Print(nullptr);

        // Call Print with a valid XMLPrinter instance.
        doc.Print(&printer);

        // 3. Fuzz destructors of tinyxml2::XMLDeclaration, tinyxml2::XMLUnknown,
        // tinyxml2::XMLComment, and tinyxml2::XMLText.
        // These destructors will be implicitly called when the 'doc' object goes
        // out of scope, as 'doc' owns these nodes.
        if (fdp.ConsumeBool()) {
            tinyxml2::XMLDeclaration* decl = doc.NewDeclaration(fdp.ConsumeRandomLengthString(20).c_str());
            if (decl) doc.LinkEndChild(decl);
        }
        if (fdp.ConsumeBool()) {
            tinyxml2::XMLUnknown* unknown = doc.NewUnknown(fdp.ConsumeRandomLengthString(20).c_str());
            if (unknown) doc.LinkEndChild(unknown);
        }
        if (fdp.ConsumeBool()) {
            tinyxml2::XMLComment* comment = doc.NewComment(fdp.ConsumeRandomLengthString(50).c_str());
            if (comment) doc.LinkEndChild(comment);
        }
        if (fdp.ConsumeBool()) {
            tinyxml2::XMLText* text = doc.NewText(fdp.ConsumeRandomLengthString(50).c_str());
            if (text) doc.LinkEndChild(text);
        }

        // Create a root element to add children and attributes for further fuzzing.
        tinyxml2::XMLElement* root = doc.NewElement(fdp.ConsumeRandomLengthString(10).c_str());
        if (root) {
            doc.LinkEndChild(root); // Link root to the document.

            // Add some attributes to the root element.
            root->SetAttribute(fdp.ConsumeRandomLengthString(10).c_str(), fdp.ConsumeRandomLengthString(20).c_str());
            root->SetAttribute(fdp.ConsumeRandomLengthString(10).c_str(), fdp.ConsumeIntegral<int>());

            // 4. Fuzz tinyxml2::XMLNode::DeepClone(tinyxml2::XMLDocument*) const.
            // Clone the root element. The cloned node is owned by 'doc'.
            tinyxml2::XMLNode* cloned_root = root->DeepClone(&doc);
            // No explicit deletion needed for 'cloned_root' as it's managed by 'doc'.

            // Add a child element to the root to test DeepClone with children.
            tinyxml2::XMLElement* child_element = doc.NewElement(fdp.ConsumeRandomLengthString(10).c_str());
            if (child_element) {
                root->LinkEndChild(child_element);
                child_element->SetText(fdp.ConsumeRandomLengthString(30).c_str());
            }
            // Clone again with children to exercise the recursive cloning logic.
            tinyxml2::XMLNode* cloned_root_with_children = root->DeepClone(&doc);
            // No explicit deletion needed for 'cloned_root_with_children' as it's managed by 'doc'.

            // 5. Fuzz XMLElement::InsertNewChildElement and related InsertNew... functions.
            // These functions create new nodes and link them to the current element.
            // The newly created nodes are owned by the document.
            if (fdp.ConsumeBool()) {
                root->InsertNewChildElement(fdp.ConsumeRandomLengthString(15).c_str());
            }
            if (fdp.ConsumeBool()) {
                root->InsertNewComment(fdp.ConsumeRandomLengthString(50).c_str());
            }
            if (fdp.ConsumeBool()) {
                root->InsertNewText(fdp.ConsumeRandomLengthString(50).c_str());
            }
            if (fdp.ConsumeBool()) {
                root->InsertNewDeclaration(fdp.ConsumeRandomLengthString(20).c_str());
            }
            if (fdp.ConsumeBool()) {
                root->InsertNewUnknown(fdp.ConsumeRandomLengthString(20).c_str());
            }
        }

        // Exercise tinyxml2::XMLVisitor methods by accepting a custom visitor.
        // This will traverse the document and call the appropriate Visit methods.
        FuzzVisitor visitor;
        doc.Accept(&visitor);

    } // The 'doc' and 'printer' objects go out of scope here.
      // 'doc's destructor will automatically free all XML nodes it owns,
      // ensuring memory safety and covering node destructors.

    return 0;
}