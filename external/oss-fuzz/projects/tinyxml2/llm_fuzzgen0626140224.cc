#include "/src/tinyxml2/tinyxml2.h"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include <memory>
#include <cstdio> // For FILE and related operations if needed, though Parse is preferred.
#include <cmath> // For fabs

// Custom visitor to control return values for coverage of Accept methods.
// The return values are fuzzed to explore different branches in the Accept logic.
class FuzzVisitor : public tinyxml2::XMLVisitor {
public:
    FuzzVisitor(FuzzedDataProvider& provider) : fdp(provider) {}

    bool VisitEnter(const tinyxml2::XMLDocument& /*doc*/) override {
        return fdp.ConsumeBool();
    }
    bool VisitExit(const tinyxml2::XMLDocument& /*doc*/) override {
        return fdp.ConsumeBool();
    }
    bool VisitEnter(const tinyxml2::XMLElement& /*element*/, const tinyxml2::XMLAttribute* /*firstAttribute*/) override {
        return fdp.ConsumeBool();
    }
    bool VisitExit(const tinyxml2::XMLElement& /*element*/) override {
        return fdp.ConsumeBool();
    }
    bool Visit(const tinyxml2::XMLText& /*text*/) override {
        return fdp.ConsumeBool();
    }
    bool Visit(const tinyxml2::XMLComment& /*comment*/) override {
        return fdp.ConsumeBool();
    }
    bool Visit(const tinyxml2::XMLDeclaration& /*declaration*/) override {
        return fdp.ConsumeBool();
    }
    bool Visit(const tinyxml2::XMLUnknown& /*unknown*/) override {
        return fdp.ConsumeBool();
    }

private:
    FuzzedDataProvider& fdp;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // Consume data for various operations and inputs.
    // Prioritize consuming data for the main XML string to be parsed.
    std::string xml_string = fdp.ConsumeRandomLengthString(fdp.remaining_bytes() / 2);

    // Consume data for other operations
    std::string element_name = fdp.ConsumeRandomLengthString(20);
    std::string attribute_name = fdp.ConsumeRandomLengthString(20);
    std::string attribute_value = fdp.ConsumeRandomLengthString(20);
    std::string text_value = fdp.ConsumeRandomLengthString(20);
    std::string comment_value = fdp.ConsumeRandomLengthString(20);
    std::string declaration_value = fdp.ConsumeRandomLengthString(20);
    std::string unknown_value = fdp.ConsumeRandomLengthString(20);
    bool use_bom = fdp.ConsumeBool();
    // Fuzz whitespace mode to hit related branches in parsing and printing.
    // Corrected enum member access.
    tinyxml2::Whitespace whitespace_mode = fdp.PickValueInArray({tinyxml2::COLLAPSE_WHITESPACE, tinyxml2::PRESERVE_WHITESPACE, tinyxml2::PEDANTIC_WHITESPACE});

    // 1. Fuzz tinyxml2::XMLDocument::Parse
    // Use unique_ptr for automatic memory management of the document.
    // Using 'new' with unique_ptr for compatibility with older C++ standards if make_unique is not available.
    std::unique_ptr<tinyxml2::XMLDocument> doc(new tinyxml2::XMLDocument(use_bom, whitespace_mode));
    // Parse the fuzzed XML string.
    doc->Parse(xml_string.c_str(), xml_string.size());

    // Exercise error handling functions if parsing failed.
    if (doc->Error()) {
        doc->PrintError(); // Exercise PrintError
        doc->ErrorIDToName(doc->ErrorID()); // Exercise ErrorIDToName
        doc->ErrorStr(); // Exercise ErrorStr
        doc->ErrorLineNum(); // Exercise ErrorLineNum
    }

    // 2. Fuzz node creation and manipulation, including tinyxml2::XMLNode::InsertAfterChild
    if (doc->RootElement()) {
        tinyxml2::XMLElement* root = doc->RootElement();

        // Fuzz tinyxml2::XMLElement::SetAttribute with various types.
        root->SetAttribute(attribute_name.c_str(), attribute_value.c_str());
        root->SetAttribute("int_attr", fdp.ConsumeIntegral<int>());
        root->SetAttribute("unsigned_int_attr", fdp.ConsumeIntegral<unsigned int>());
        root->SetAttribute("long_attr", fdp.ConsumeIntegral<long>());
        root->SetAttribute("unsigned_long_attr", fdp.ConsumeIntegral<unsigned long>());
        root->SetAttribute("bool_attr", fdp.ConsumeBool());
        root->SetAttribute("double_attr", fdp.ConsumeFloatingPoint<double>());
        root->SetAttribute("float_attr", fdp.ConsumeFloatingPoint<float>());

        // Fuzz InsertAfterChild and other node insertions to cover tree manipulation.
        tinyxml2::XMLNode* child_to_insert_after = root->FirstChild();
        if (child_to_insert_after) {
             // Insert a new element after an existing child.
            tinyxml2::XMLElement* new_elem = doc->NewElement(element_name.c_str());
            if (new_elem) {
                root->InsertAfterChild(child_to_insert_after, new_elem);
            }

            // Attempt to insert a node from a different document to hit the missed branch in InsertAfterChild.
            // Using 'new' with unique_ptr.
            std::unique_ptr<tinyxml2::XMLDocument> another_doc(new tinyxml2::XMLDocument());
            tinyxml2::XMLElement* elem_from_another_doc = another_doc->NewElement("foreign_element");
            if (elem_from_another_doc) {
                 root->InsertAfterChild(child_to_insert_after, elem_from_another_doc); // Should trigger assertion/branch
            }


            // Attempt to insert after a node that is not a child to hit the missed branch in InsertAfterChild.
            tinyxml2::XMLElement* orphan_elem = doc->NewElement("orphan");
            tinyxml2::XMLElement* non_child = doc->NewElement("non_child"); // Not added to root
            if (orphan_elem && non_child) {
                root->InsertAfterChild(non_child, orphan_elem); // Should trigger assertion/branch
            }

            // Attempt to insert a node after itself to hit the missed branch in InsertAfterChild.
            if (new_elem) {
                 root->InsertAfterChild(new_elem, new_elem); // Should trigger assertion/branch
            }

        } else {
            // If no children, insert the first child to ensure some nodes exist for other operations.
            tinyxml2::XMLElement* first_elem = doc->NewElement(element_name.c_str());
            if (first_elem) {
                root->InsertFirstChild(first_elem);
            }
        }

        // Add other node types to the document to ensure their Visit methods are called during printing/visiting.
        if (doc->NewText(text_value.c_str())) root->LinkEndChild(doc->NewText(text_value.c_str()));
        if (doc->NewComment(comment_value.c_str())) root->LinkEndChild(doc->NewComment(comment_value.c_str()));
        if (doc->NewDeclaration(declaration_value.c_str())) root->LinkEndChild(doc->NewDeclaration(declaration_value.c_str()));
        if (doc->NewUnknown(unknown_value.c_str())) root->LinkEndChild(doc->NewUnknown(unknown_value.c_str()));

    } else {
        // If no root element after parsing (e.g., empty or invalid XML), create a simple structure.
        tinyxml2::XMLElement* new_root = doc->NewElement(element_name.c_str());
        if (new_root) {
            doc->LinkEndChild(new_root);
            if (doc->NewText(text_value.c_str())) new_root->LinkEndChild(doc->NewText(text_value.c_str()));
        }
    }

    // 3. Fuzz tinyxml2::XMLDocument::Print with tinyxml2::XMLPrinter (which is a visitor)
    // and explicitly fuzz tinyxml2::XMLDocument::Accept with our custom FuzzVisitor.
    FuzzVisitor visitor(fdp);
    tinyxml2::XMLPrinter printer;

    // Calling Print exercises the XMLPrinter's Visit methods.
    doc->Print(&printer);

    // Calling Accept with our custom visitor exercises the XMLDocument::Accept
    // and the FuzzVisitor's Visit methods, with fuzzed return values to hit branches.
    doc->Accept(&visitor);

    // 4. Exercise other diverse functions with low coverage or important functionality.
    // tinyxml2::XMLDocument::SetBOM
    doc->SetBOM(fdp.ConsumeBool());

    // tinyxml2::XMLDocument::ClearError
    doc->ClearError();

    // tinyxml2::XMLDocument::DeepCopy (requires another document)
    // Using 'new' with unique_ptr.
    std::unique_ptr<tinyxml2::XMLDocument> doc_copy(new tinyxml2::XMLDocument());
    doc->DeepCopy(doc_copy.get());


    // Memory management:
    // The 'doc' and 'doc_copy' unique_ptrs ensure the XMLDocument objects and
    // all nodes created via doc->New* are automatically deallocated when they go out of scope.
    // The 'visitor' and 'printer' objects are stack-allocated and cleaned up automatically.
    // No explicit delete calls are needed for nodes or documents due to unique_ptr.

    return 0;
}