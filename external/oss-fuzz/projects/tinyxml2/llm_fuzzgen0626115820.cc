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

    // Create an XMLDocument object. Use unique_ptr for automatic memory management.
    // tinyxml2::XMLDocument manages its own nodes, so we only need to manage the document itself.
    // Fix 1: Replace std::make_unique with new and unique_ptr constructor for C++11 compatibility.
    std::unique_ptr<tinyxml2::XMLDocument> doc(new tinyxml2::XMLDocument());

    // --- Target API 1: tinyxml2::XMLDocument::Parse ---
    // Parse the XML string. This is a core function and exercises many internal paths.
    doc->Parse(xml_string.c_str(), xml_string.size());

    // --- Target API 3: tinyxml2::XMLDocument::ErrorName() const ---
    // Check for parsing errors and call ErrorName if an error occurred.
    if (doc->Error()) {
        doc->ErrorName(); // Exercise the ErrorName function
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


            // Consume data for a new element name
            std::string new_element_name = fdp.ConsumeRandomLengthString(32);
            // Modification 1: Always attempt to create and link a new element
            // to cover the branch previously missed due to empty string input.
            tinyxml2::XMLElement* new_element = doc->NewElement(new_element_name.c_str());
            if (new_element) {
                root_element->LinkEndChild(new_element);
            }

            // Modification 4 & 5: Create and navigate to different node types to improve coverage of XMLNode::To* and XMLHandle methods
            std::string comment_content = fdp.ConsumeRandomLengthString(32);
            if (!comment_content.empty()) {
                tinyxml2::XMLComment* new_comment = doc->NewComment(comment_content.c_str());
                if (new_comment) {
                    root_element->LinkEndChild(new_comment);
                }
            }

            std::string declaration_content = fdp.ConsumeRandomLengthString(32);
            if (!declaration_content.empty()) {
                 tinyxml2::XMLDeclaration* new_declaration = doc->NewDeclaration(declaration_content.c_str());
                 if (new_declaration) {
                     root_element->LinkEndChild(new_declaration); // Linking declaration here for fuzzing purposes
                 }
            }

            std::string unknown_content = fdp.ConsumeRandomLengthString(32);
            if (!unknown_content.empty()) {
                tinyxml2::XMLUnknown* new_unknown = doc->NewUnknown(unknown_content.c_str());
                if (new_unknown) {
                    root_element->LinkEndChild(new_unknown);
                }
            }

            // --- Target API (Implicit via Accept): XMLVisitor::VisitEnter(tinyxml2::XMLElement const&, tinyxml2::XMLAttribute const*) ---
            // Traverse the document using a visitor to exercise Visit functions.
            // Modification 2: Pass FuzzedDataProvider to visitor and fuzz return values
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

            tinyxml2::XMLNode* first_child = handle.FirstChild().ToNode();
            if (first_child) {
                tinyxml2::XMLHandle child_handle(first_child);
                tinyxml2::XMLText* text_node = child_handle.ToText();
                if (text_node) {
                    // Accessing the text node exercises the ToText() path
                    // Fix 2: Replace GetText() with Value()
                    text_node->Value();
                }

                // Modification 5: Navigate to different node types using handles and exercise To* methods
                // Fix 5: XMLHandle does not have ToComment(), ToDeclaration(), ToUnknown(). Convert to Node first.
                tinyxml2::XMLNode* comment_node = child_handle.ToNode()->ToComment();
                if (comment_node) {
                    comment_node->ToComment(); // Exercise ToComment()
                }

                tinyxml2::XMLNode* declaration_node = child_handle.ToNode()->ToDeclaration();
                if (declaration_node) {
                    declaration_node->ToDeclaration(); // Exercise ToDeclaration()
                }

                tinyxml2::XMLNode* unknown_node = child_handle.ToNode()->ToUnknown();
                if (unknown_node) {
                    unknown_node->ToUnknown(); // Exercise ToUnknown()
                }
            }

            // Modification 4: Exercise other handle navigation methods
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
            // Fix 5: XMLHandle does not have ToComment(), ToDeclaration(), ToUnknown(). Convert to Node first.
            handle.ToNode()->ToUnknown();
            handle.ToNode()->ToDeclaration();
            handle.ToNode()->ToComment();


            const_handle.ToNode();
            const_handle.ToElement();
            const_handle.ToText();
            // Fix 5: XMLHandle does not have ToComment(), ToDeclaration(), ToUnknown(). Convert to Node first.
            const_handle.ToNode()->ToUnknown();
            const_handle.ToNode()->ToDeclaration();
            const_handle.ToNode()->ToComment();
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
    }

    // The unique_ptr for 'doc' will automatically delete the XMLDocument and all its nodes
    // when it goes out of scope, ensuring memory safety.

    return 0; // Fuzzing successful
}