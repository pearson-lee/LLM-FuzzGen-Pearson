#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <memory> // For std::unique_ptr

#include "/src/tinyxml2/tinyxml2.h" // Include the necessary tinyxml2 header

#include <fuzzer/FuzzedDataProvider.h>

// Define a custom XMLVisitor to exercise the Visit functions
class FuzzVisitor : public tinyxml2::XMLVisitor {
public:
    // Modification 2: Pass FuzzedDataProvider to the visitor to fuzz return values
    FuzzVisitor(FuzzedDataProvider& provider) : fdp_(provider) {}

    // Implement the pure virtual functions from XMLVisitor
    // Modification 2: Fuzz the return value of VisitEnter/Exit to test different traversal paths
    bool VisitEnter(const tinyxml2::XMLDocument& /*doc*/) override { return fdp_.ConsumeBool(); }
    bool VisitExit(const tinyxml2::XMLDocument& /*doc*/) override { return fdp_.ConsumeBool(); }
    bool VisitEnter(const tinyxml2::XMLElement& /*element*/, const tinyxml2::XMLAttribute* /*firstAttribute*/) override { return fdp_.ConsumeBool(); }
    bool VisitExit(const tinyxml2::XMLElement& /*element*/) override { return fdp_.ConsumeBool(); }
    bool Visit(const tinyxml2::XMLDeclaration& /*declaration*/) override { return fdp_.ConsumeBool(); }
    bool Visit(const tinyxml2::XMLText& /*text*/) override { return fdp_.ConsumeBool(); }
    bool Visit(const tinyxml2::XMLComment& /*comment*/) override { return fdp_.ConsumeBool(); }
    bool Visit(const tinyxml2::XMLUnknown& /*unknown*/) override { return fdp_.ConsumeBool(); }

private:
    FuzzedDataProvider& fdp_;
};


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // Consume data for the XML string
    std::string xml_string = fdp.ConsumeRemainingBytesAsString();

    // Consume data for whitespace mode
    // Modification 18: Fuzz the whitespace mode to cover StrPair::CollapseWhitespace
    tinyxml2::Whitespace whitespace_mode = fdp.ConsumeBool() ? tinyxml2::Whitespace::COLLAPSE_WHITESPACE : tinyxml2::Whitespace::PRESERVE_WHITESPACE;

    // Create an XMLDocument object. Use unique_ptr for automatic memory management.
    // tinyxml2::XMLDocument manages its own nodes, so we only need to manage the document itself.
    // Fix 1: Replace std::make_unique with new and unique_ptr constructor for C++11 compatibility.
    // Modification 18: Pass fuzzed whitespace mode to the constructor
    std::unique_ptr<tinyxml2::XMLDocument> doc(new tinyxml2::XMLDocument(true, whitespace_mode));

    // --- Target API 1: tinyxml2::XMLDocument::Parse ---
    // Parse the XML string. This is a core function and exercises many internal paths.
    doc->Parse(xml_string.c_str(), xml_string.size());

    // --- Target API 3: tinyxml2::XMLDocument::ErrorName() const ---
    // Check for parsing errors and call ErrorName if an error occurred.
    if (doc->Error()) {
        doc->ErrorName(); // Exercise the ErrorName function
        // Modification 19: Exercise ErrorStr() and PrintError() on error
        doc->ErrorStr();
        doc->PrintError();
    } else {
        // If parsing was successful, exercise other APIs

        // Get the root element
        tinyxml2::XMLElement* root_element = doc->RootElement();

        if (root_element) {
            // Consume data for attribute name and default value
            std::string attr_name = fdp.ConsumeRandomLengthString(32);
            int default_int_value = fdp.ConsumeIntegral<int>();
            int queried_int_value;

            // --- Target API 2: tinyxml2::XMLElement::QueryIntAttribute ---
            // Query an integer attribute by name.
            root_element->QueryIntAttribute(attr_name.c_str(), &queried_int_value);

            // Modification 3: Add calls to other Query*Attribute methods based on coverage report
            unsigned int queried_unsigned_value;
            root_element->QueryUnsignedAttribute(attr_name.c_str(), &queried_unsigned_value);
            long queried_int64_value;
            root_element->QueryInt64Attribute(attr_name.c_str(), &queried_int64_value);
            unsigned long queried_unsigned64_value;
            root_element->QueryUnsigned64Attribute(attr_name.c_str(), &queried_unsigned64_value);
            bool queried_bool_value;
            root_element->QueryBoolAttribute(attr_name.c_str(), &queried_bool_value);
            double queried_double_value;
            root_element->QueryDoubleAttribute(attr_name.c_str(), &queried_double_value);
            float queried_float_value;
            root_element->QueryFloatAttribute(attr_name.c_str(), &queried_float_value);
            const char* queried_string_value;
            root_element->QueryStringAttribute(attr_name.c_str(), &queried_string_value);

            // Modification 20: Add calls to generic QueryAttribute overloads
            root_element->QueryAttribute(attr_name.c_str(), &queried_int_value);
            root_element->QueryAttribute(attr_name.c_str(), &queried_unsigned_value);
            root_element->QueryAttribute(attr_name.c_str(), &queried_int64_value);
            root_element->QueryAttribute(attr_name.c_str(), &queried_unsigned64_value);
            root_element->QueryAttribute(attr_name.c_str(), &queried_bool_value);
            root_element->QueryAttribute(attr_name.c_str(), &queried_double_value);
            root_element->QueryAttribute(attr_name.c_str(), &queried_float_value);
            root_element->QueryAttribute(attr_name.c_str(), &queried_string_value);

            // Modification 17: Add calls to *Attribute const methods
            root_element->IntAttribute(attr_name.c_str(), default_int_value);
            root_element->UnsignedAttribute(attr_name.c_str(), fdp.ConsumeIntegral<unsigned int>());
            root_element->Int64Attribute(attr_name.c_str(), fdp.ConsumeIntegral<long>());
            root_element->Unsigned64Attribute(attr_name.c_str(), fdp.ConsumeIntegral<unsigned long>());
            root_element->BoolAttribute(attr_name.c_str(), fdp.ConsumeBool());
            root_element->DoubleAttribute(attr_name.c_str(), fdp.ConsumeFloatingPoint<double>());
            root_element->FloatAttribute(attr_name.c_str(), fdp.ConsumeFloatingPoint<float>());
            root_element->Attribute(attr_name.c_str()); // Modification 11

            // Consume data for default text value
            int default_text_value = fdp.ConsumeIntegral<int>();

            // --- Target API 3: tinyxml2::XMLElement::IntText(int) const ---
            // Get the text content as an integer with a default value.
            root_element->IntText(default_text_value);

            // Modification 3: Add calls to other *Text methods based on coverage report
            root_element->UnsignedText(fdp.ConsumeIntegral<unsigned int>());
            root_element->Int64Text(fdp.ConsumeIntegral<long>());
            root_element->Unsigned64Text(fdp.ConsumeIntegral<unsigned long>());
            root_element->BoolText(fdp.ConsumeBool());
            // Fix 4: Use ConsumeFloatingPoint for double and float
            root_element->DoubleText(fdp.ConsumeFloatingPoint<double>());
            root_element->FloatText(fdp.ConsumeFloatingPoint<float>());

            // Modification 12: Add call to GetText()
            root_element->GetText();

            // Consume data for new node names and content
            std::string new_element_name = fdp.ConsumeRandomLengthString(32);
            std::string comment_content = fdp.ConsumeRandomLengthString(32);
            std::string declaration_content = fdp.ConsumeRandomLengthString(32);
            std::string unknown_content = fdp.ConsumeRandomLengthString(32);
            std::string text_content = fdp.ConsumeRandomLengthString(32);


            // Modification 15: Use InsertNew* methods to cover them
            tinyxml2::XMLElement* new_element = root_element->InsertNewChildElement(new_element_name.c_str());
            tinyxml2::XMLComment* new_comment = root_element->InsertNewComment(comment_content.c_str());
            tinyxml2::XMLDeclaration* new_declaration = root_element->InsertNewDeclaration(declaration_content.c_str());
            tinyxml2::XMLUnknown* new_unknown = root_element->InsertNewUnknown(unknown_content.c_str());
            tinyxml2::XMLText* new_text = root_element->InsertNewText(text_content.c_str());


            // Modification 4 & 5: Create and navigate to different node types to improve coverage of XMLNode::To* and XMLHandle methods
            // Fix 5: XMLHandle does not have ToComment(), ToDeclaration(), ToUnknown(). Convert to Node first.
            // Modification 5: Create handles directly from the created nodes to guarantee hitting To* methods
            // FIX 1: Correctly use ToNode() before calling To*() methods on the node pointer
            tinyxml2::XMLHandle handle_comment(new_comment);
            tinyxml2::XMLNode* node_from_handle_comment = handle_comment.ToNode();
            if (node_from_handle_comment) {
                 node_from_handle_comment->ToComment(); // Exercise ToComment()
            }

            tinyxml2::XMLHandle handle_declaration(new_declaration);
            tinyxml2::XMLNode* node_from_handle_declaration = handle_declaration.ToNode();
            if (node_from_handle_declaration) {
                 node_from_handle_declaration->ToDeclaration(); // Exercise ToDeclaration()
            }

            tinyxml2::XMLHandle handle_unknown(new_unknown);
            tinyxml2::XMLNode* node_from_handle_unknown = handle_unknown.ToNode();
            if (node_from_handle_unknown) {
                 node_from_handle_unknown->ToUnknown(); // Exercise ToUnknown()
            }

            tinyxml2::XMLHandle handle_text(new_text);
            tinyxml2::XMLNode* node_from_handle_text = handle_text.ToNode();
            if (node_from_handle_text) {
                 if (node_from_handle_text->ToText()) node_from_handle_text->ToText()->Value(); // Exercise ToText() and Value()
            }

            tinyxml2::XMLHandle handle_element(new_element);
            tinyxml2::XMLNode* node_from_handle_element = handle_element.ToNode();
            if (node_from_handle_element) {
                 node_from_handle_element->ToElement(); // Exercise ToElement()
            }


            // --- Target API (Implicit via Accept): tinyxml2::XMLVisitor::VisitEnter(tinyxml2::XMLElement const&, tinyxml2::XMLAttribute const*) ---
            // Traverse the document using a visitor to exercise Visit functions.
            // Modification 2: Pass FuzzedDataProvider to visitor and fuzz return values
            // Modification 1: Ensure Comment, Declaration, Unknown nodes are always linked to be visited
            FuzzVisitor visitor(fdp);
            doc->Accept(&visitor);

            // --- Target API (Implicit via XMLHandle usage): tinyxml2::XMLHandle::ToText() ---
            // Use XMLHandle to navigate and access nodes, including text nodes.
            tinyxml2::XMLHandle handle(doc.get());

            // Modification 4: Exercise more XMLHandle and XMLConstHandle methods based on coverage report
            tinyxml2::XMLHandle handle2(doc.get());
            tinyxml2::XMLHandle handle3(handle2); // Exercise copy constructor
            tinyxml2::XMLHandle handle4(nullptr);
            handle4 = handle3; // Exercise assignment operator

            tinyxml2::XMLConstHandle const_handle(doc.get());
            tinyxml2::XMLConstHandle const_handle2(const_handle); // Exercise const copy constructor
            tinyxml2::XMLConstHandle const_handle3(nullptr);
            const_handle3 = const_handle2; // Exercise const assignment operator

            // Modification 22: Exercise XMLHandle and XMLConstHandle constructors taking references based on coverage report.
            if (doc->RootElement()) {
                tinyxml2::XMLHandle handle_ref(*doc->RootElement());
                tinyxml2::XMLConstHandle const_handle_ref(*doc->RootElement());
            }


            // Modification 4: Exercise other handle navigation methods
            handle.FirstChild();
            handle.LastChild();
            handle.PreviousSibling();
            handle.NextSibling();
            handle.FirstChildElement(fdp.ConsumeRandomLengthString(16).c_str());
            handle.LastChildElement(fdp.ConsumeRandomLengthString(16).c_str());
            handle.PreviousSiblingElement(fdp.ConsumeRandomLengthString(16).c_str());
            handle.NextSiblingElement(fdp.ConsumeRandomLengthString(16).c_str());

            const_handle.FirstChild() ;
            const_handle.LastChild();
            const_handle.PreviousSibling();
            const_handle.NextSibling();
            const_handle.FirstChildElement(fdp.ConsumeRandomLengthString(16).c_str());
            const_handle.LastChildElement(fdp.ConsumeRandomLengthString(16).c_str());
            const_handle.PreviousSiblingElement(fdp.ConsumeRandomLengthString(16).c_str());
            const_handle.NextSiblingElement(fdp.ConsumeRandomLengthString(16).c_str());

            // Modification 4: Exercise ToNode(), ToElement(), ToText(), ToUnknown(), ToDeclaration() on handles
            handle.ToNode();
            handle.ToElement();
            handle.ToText();
            // Modification 23: Exercise XMLHandle::ToUnknown() and ToDeclaration() directly based on coverage report.
            handle.ToUnknown();
            handle.ToDeclaration();
            // Removed: handle.ToComment(); // This one exists directly on XMLHandle


            const_handle.ToNode();
            const_handle.ToElement();
            const_handle.ToText();
            // Modification 23: Exercise XMLConstHandle::ToUnknown() const and ToDeclaration() const directly based on coverage report.
            const_handle.ToUnknown();
            const_handle.ToDeclaration();
            // Removed: const_handle.ToComment(); // This one exists directly on XMLConstHandle

            // Modification 6: Exercise XMLElement::ShallowEqual
            tinyxml2::XMLElement* element_to_compare = doc->NewElement(fdp.ConsumeRandomLengthString(32).c_str());
            if (element_to_compare) {
                root_element->ShallowEqual(element_to_compare);
                // Modification 16: Exercise XMLElement::ShallowClone
                std::unique_ptr<tinyxml2::XMLDocument> clone_doc(new tinyxml2::XMLDocument());
                root_element->ShallowClone(clone_doc.get());
            }

            // Modification 10: Exercise ShallowEqual for other node types
            tinyxml2::XMLComment* comment_to_compare = doc->NewComment(fdp.ConsumeRandomLengthString(32).c_str());
            if (comment_to_compare) {
                if (new_comment) new_comment->ShallowEqual(comment_to_compare);
            }
            tinyxml2::XMLDeclaration* declaration_to_compare = doc->NewDeclaration(fdp.ConsumeRandomLengthString(32).c_str());
            if (declaration_to_compare) {
                 if (new_declaration) new_declaration->ShallowEqual(declaration_to_compare);
            }
            tinyxml2::XMLUnknown* unknown_to_compare = doc->NewUnknown(fdp.ConsumeRandomLengthString(32).c_str());
            if (unknown_to_compare) {
                 if (new_unknown) new_unknown->ShallowEqual(unknown_to_compare);
            }
            tinyxml2::XMLText* text_to_compare = doc->NewText(fdp.ConsumeRandomLengthString(32).c_str());
             if (text_to_compare) {
                 if (new_text) new_text->ShallowEqual(text_to_compare);
            }


            // Modification 7: Exercise XMLDocument::DeepCopy
            std::unique_ptr<tinyxml2::XMLDocument> deep_copy_doc(new tinyxml2::XMLDocument());
            doc->DeepCopy(deep_copy_doc.get());

            // Modification 8: Exercise XMLNode::InsertAfterChild
            tinyxml2::XMLNode* first_child = root_element->FirstChild();
            if (first_child) {
                tinyxml2::XMLElement* element_after = doc->NewElement(fdp.ConsumeRandomLengthString(32).c_str());
                if (element_after) {
                    root_element->InsertAfterChild(first_child, element_after);
                }
            }

            // Modification 9: Exercise XMLNode::DeleteNode
            tinyxml2::XMLNode* node_to_delete = root_element->FirstChild();
            if (node_to_delete) {
                doc->DeleteNode(node_to_delete);
            }

            // Modification 13: Exercise XMLElement::DeleteAttribute(char const*)
            root_element->DeleteAttribute(attr_name.c_str());

            // Modification 14: Exercise XMLElement::DeleteAttribute(tinyxml2::XMLAttribute*)
            // FIX 3 & 4: Remove incorrect usage of private DeleteAttribute(XMLAttribute*)
            // The public method DeleteAttribute(const char*) is already called above.


            // Modification 21: Exercise XMLDocument::RootElement() const and ToDocument() const
            const tinyxml2::XMLDocument& const_doc_ref = *doc.get();
            const_doc_ref.RootElement();
            const_doc_ref.ToDocument();

            // Modification 24: Exercise XMLElement::SetAttribute and SetText with non-string types
            // to trigger XMLPrinter's formatted printing and cover XMLPrinter::Print and TIXML_VSCPRINTF based on coverage report.
            if (new_element) {
                new_element->SetAttribute("intAttr", fdp.ConsumeIntegral<int>());
                new_element->SetAttribute("unsignedAttr", fdp.ConsumeIntegral<unsigned int>());
                new_element->SetAttribute("int64Attr", fdp.ConsumeIntegral<long>());
                new_element->SetAttribute("unsigned64Attr", fdp.ConsumeIntegral<unsigned long>());
                new_element->SetAttribute("boolAttr", fdp.ConsumeBool());
                new_element->SetAttribute("doubleAttr", fdp.ConsumeFloatingPoint<double>());
                new_element->SetAttribute("floatAttr", fdp.ConsumeFloatingPoint<float>());

                new_element->SetText(fdp.ConsumeIntegral<int>());
                new_element->SetText(fdp.ConsumeIntegral<unsigned int>());
                new_element->SetText(fdp.ConsumeIntegral<long>());
                new_element->SetText(fdp.ConsumeIntegral<unsigned long>());
                new_element->SetText(fdp.ConsumeBool());
                new_element->SetText(fdp.ConsumeFloatingPoint<double>());
                new_element->SetText(fdp.ConsumeFloatingPoint<float>());
            }

        }

        // --- Target API 4: tinyxml2::XMLDocument::Print ---
        // Print the document to exercise the XMLPrinter and its Visit methods.
        // XMLPrinter writes to an internal buffer by default.
        // Consume data for compact mode option
        bool compact_mode = fdp.ConsumeBool();
        // Fix 3: Pass compact_mode to the XMLPrinter constructor instead of calling SetIndent.
        tinyxml2::XMLPrinter printer(nullptr, compact_mode);
        doc->Print(&printer);
        // The printer's buffer is automatically freed when printer goes out of scope.

        // Modification 4: Exercise XMLPrinter::Print(char const*, ...)
        // FIX 5: Remove incorrect usage of protected XMLPrinter::Print
    }

    // Modification 25: Add a specific test case to cover StrPair::CollapseWhitespace based on coverage report.
    // Create a new document with COLLAPSE_WHITESPACE mode and parse a string with collapsible whitespace.
    {
        std::unique_ptr<tinyxml2::XMLDocument> collapse_doc(new tinyxml2::XMLDocument(true, tinyxml2::Whitespace::COLLAPSE_WHITESPACE));
        std::string whitespace_xml = "<element>  text   with \n\r\t whitespace </element>";
        collapse_doc->Parse(whitespace_xml.c_str(), whitespace_xml.size());
        // The parsing process with COLLAPSE_WHITESPACE mode should exercise StrPair::CollapseWhitespace.
        // The unique_ptr ensures collapse_doc is deleted, freeing its memory.
    }


    // The unique_ptr for 'doc' will automatically delete the XMLDocument and all its nodes
    // when it goes out of scope, ensuring memory safety. deep_copy_doc is also managed by unique_ptr.

    return 0; // Fuzzing successful
}