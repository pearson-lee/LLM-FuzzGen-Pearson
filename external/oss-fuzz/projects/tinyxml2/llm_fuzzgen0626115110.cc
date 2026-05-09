#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <memory> // For std::unique_ptr
#include <cstdio> // For FILE operations if needed, though tinyxml2 has in-memory parsing
#include <cstring> // For strlen

#include "/src/tinyxml2/tinyxml2.h" // Include the necessary tinyxml2 header

#include <fuzzer/FuzzedDataProvider.h>

// Define a custom XMLVisitor to exercise the Visit functions
class FuzzVisitor : public tinyxml2::XMLVisitor {
public:
    // Implement the pure virtual functions from XMLVisitor
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

            // Consume data for default text value
            int default_text_value = fdp.ConsumeIntegral<int>();

            // --- Target API 3: tinyxml2::XMLElement::IntText(int) const ---
            // Get the text content as an integer with a default value.
            root_element->IntText(default_text_value);

            // Consume data for a new element name
            std::string new_element_name = fdp.ConsumeRandomLengthString(32);
            if (!new_element_name.empty()) {
                // --- Target API 5: tinyxml2::XMLNode::LinkEndChild ---
                // Create a new element and link it as a child.
                // tinyxml2::XMLDocument::NewElement allocates the node using the document's memory pool.
                tinyxml2::XMLElement* new_element = doc->NewElement(new_element_name.c_str());
                if (new_element) {
                    root_element->LinkEndChild(new_element);
                }
            }

            // --- Target API (Implicit via Accept): XMLVisitor::VisitEnter(tinyxml2::XMLElement const&, tinyxml2::XMLAttribute const*) ---
            // Traverse the document using a visitor to exercise Visit functions.
            FuzzVisitor visitor;
            doc->Accept(&visitor);

            // --- Target API (Implicit via XMLHandle usage): tinyxml2::XMLHandle::ToText() ---
            // Use XMLHandle to navigate and access nodes, including text nodes.
            tinyxml2::XMLHandle handle(doc.get());
            tinyxml2::XMLNode* first_child = handle.FirstChild().ToNode();
            if (first_child) {
                tinyxml2::XMLHandle child_handle(first_child);
                tinyxml2::XMLText* text_node = child_handle.ToText();
                if (text_node) {
                    // Accessing the text node exercises the ToText() path
                    // Fix 2: Replace GetText() with Value()
                    text_node->Value();
                }
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
    }

    // The unique_ptr for 'doc' will automatically delete the XMLDocument and all its nodes
    // when it goes out of scope, ensuring memory safety.

    return 0; // Fuzzing successful
}