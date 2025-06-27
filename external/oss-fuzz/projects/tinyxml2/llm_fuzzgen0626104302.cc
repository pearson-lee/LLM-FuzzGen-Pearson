#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <memory> // For std::unique_ptr
#include <fuzzer/FuzzedDataProvider.h>

// Include the necessary tinyxml2 header with the full project-relative path.
#include "/src/tinyxml2/tinyxml2.h"

// Define a custom deleter for XMLDocument to be used with std::unique_ptr.
// This ensures proper cleanup of the XMLDocument object and its associated memory.
struct XMLDocumentDeleter {
    void operator()(tinyxml2::XMLDocument* doc) const {
        if (doc) {
            doc->Clear(); // Clear all nodes and release memory
            delete doc;
        }
    }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // Use std::unique_ptr with a custom deleter for memory-safe management of XMLDocument.
    // The XMLDocument manages the memory for its nodes and attributes.
    std::unique_ptr<tinyxml2::XMLDocument, XMLDocumentDeleter> doc(new tinyxml2::XMLDocument());

    // Create a root element for the XML document.
    // NewElement allocates memory for the element, which is owned by the document.
    tinyxml2::XMLElement* root = doc->NewElement("root");
    if (!root) {
        return 0; // Allocation failed, nothing to do.
    }
    doc->InsertFirstChild(root);

    // --- Fuzzing tinyxml2::XMLElement::SetText(const char *) and tinyxml2::XMLElement::GetText() ---
    // These functions currently have 0% runtime coverage.
    // Generate a random string to set as the element's text content.
    std::string text_content = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange(0, 200));
    root->SetText(text_content.c_str());
    // Retrieve the text content. The returned const char* is owned by the document.
    root->GetText();

    // --- Fuzzing tinyxml2::XMLElement::BoolAttribute(const char *, bool) and QueryBoolAttribute ---
    // These functions currently have 0% runtime coverage for BoolAttribute and
    // the 'if (!a)' branch (XML_NO_ATTRIBUTE) in QueryBoolAttribute.

    // Scenario 1: Test with an attribute name that does NOT exist.
    // This aims to cover the 'XML_NO_ATTRIBUTE' branch in QueryBoolAttribute.
    std::string non_existent_attr_name = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange(1, 50));
    bool default_bool_val = fdp.ConsumeBool();
    root->BoolAttribute(non_existent_attr_name.c_str(), default_bool_val);

    // Scenario 2: Test with an attribute name that DOES exist.
    // This aims to cover the successful path in QueryBoolAttribute.
    std::string existent_attr_name = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange(1, 50));
    bool attr_value_to_set = fdp.ConsumeBool();
    // Set the attribute first. This also helps cover SetAttribute overloads.
    root->SetAttribute(existent_attr_name.c_str(), attr_value_to_set);
    root->BoolAttribute(existent_attr_name.c_str(), default_bool_val);

    // --- Fuzzing tinyxml2::XMLNode::ChildElementCount(const char *) and ChildElementCount() ---
    // These functions currently have 0% runtime coverage.

    // Add a random number of child elements to the root.
    int num_children = fdp.ConsumeIntegralInRange(0, 10);
    std::string common_child_name = "common_child"; // Use a common name for some children
    for (int i = 0; i < num_children; ++i) {
        std::string child_name;
        if (fdp.ConsumeBool()) { // Randomly use common name or a unique name
            child_name = common_child_name;
        } else {
            child_name = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange(1, 20));
        }
        tinyxml2::XMLElement* child = doc->NewElement(child_name.c_str());
        if (child) {
            root->InsertEndChild(child);
        }
    }

    // Call ChildElementCount() to get the total number of child elements.
    root->ChildElementCount();
    // Call ChildElementCount(const char *) with a randomly generated name.
    std::string search_child_name = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange(1, 20));
    root->ChildElementCount(search_child_name.c_str());
    // Also call with the common name to ensure it finds elements.
    root->ChildElementCount(common_child_name.c_str());

    // --- Fuzzing tinyxml2::XMLPrinter::PushText(bool) and PushAttribute(const char*, bool) ---
    // These specific overloads currently have 0% runtime coverage.
    tinyxml2::XMLPrinter printer;
    // Push a boolean text value.
    printer.PushText(fdp.ConsumeBool());

    // Push a boolean attribute.
    std::string printer_attr_name = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange(1, 50));
    printer.PushAttribute(printer_attr_name.c_str(), fdp.ConsumeBool());

    // The XMLDocument and its associated nodes/attributes are automatically
    // deallocated when 'doc' goes out of scope due to std::unique_ptr.
    // The XMLPrinter's internal buffer is managed by its destructor.

    return 0;
}