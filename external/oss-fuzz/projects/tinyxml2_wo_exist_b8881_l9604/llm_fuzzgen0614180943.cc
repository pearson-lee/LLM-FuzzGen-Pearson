#include "/src/tinyxml2/tinyxml2.h" // Project-relative path for tinyxml2
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <memory>   // For std::unique_ptr
#include <cstddef>  // For size_t
#include <cstdint>  // For uint8_t

// Target APIs:
// 1. DW_TAG_enumeration_typeXMLError tinyxml2::XMLDocument::Parse(const char *, size_t)
// 2. XMLElement * tinyxml2::XMLDocument::NewElement(const char *)
// 3. void tinyxml2::XMLElement::SetAttribute(const char *, const char *)
// 4. void tinyxml2::XMLElement::SetText(const char *)
// 5. void tinyxml2::XMLDocument::Print(XMLPrinter *)

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // Use std::unique_ptr for automatic memory management of XMLDocument.
    // XMLDocument owns the nodes (XMLElement, XMLText, etc.) created via its
    // NewElement, NewText methods or parsed into it. Deleting the XMLDocument
    // will clean these up, preventing memory leaks.
    // Corrected to be C++11 compatible (instead of std::make_unique)
    std::unique_ptr<tinyxml2::XMLDocument> doc(new tinyxml2::XMLDocument());

    // 1. Attempt to parse an XML string from the fuzzer data using XMLDocument::Parse.
    // Consume up to half of the remaining data for parsing to leave data for other operations.
    size_t parse_string_size = fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes() / 2);
    std::string xml_to_parse = fdp.ConsumeBytesAsString(parse_string_size);
    doc->Parse(xml_to_parse.c_str(), xml_to_parse.length()); // size_t for length is correct

    // Get the root element if parsing was successful, or create one.
    tinyxml2::XMLElement *current_element = doc->RootElement();
    if (!current_element) {
        std::string root_name_str = fdp.ConsumeRandomLengthString(32);
        // NewElement requires a non-empty name.
        if (root_name_str.empty()) {
            root_name_str = "defaultRoot";
        }
        current_element = doc->NewElement(root_name_str.c_str());
        if (current_element) {
            doc->InsertFirstChild(current_element); // Add the new root to the document.
        }
    }

    // Proceed with further operations only if we have a valid element to work with.
    if (current_element) {
        // Perform a variable number of operations on the XML document.
        int num_operations = fdp.ConsumeIntegralInRange<int>(1, 20);
        for (int i = 0; i < num_operations; ++i) {
            if (!current_element) { // Safety check if current_element becomes null
                break;
            }

            // Choose an operation type.
            uint8_t op_type = fdp.ConsumeIntegralInRange<uint8_t>(0, 3);

            switch (op_type) {
                case 0: {
                    // 2. Test XMLDocument::NewElement by creating a new child element.
                    std::string child_name_str = fdp.ConsumeRandomLengthString(32);
                    // NewElement requires a non-empty name.
                    if (child_name_str.empty()) {
                        child_name_str = "defaultChild";
                    }
                    tinyxml2::XMLElement *new_child = doc->NewElement(child_name_str.c_str());
                    if (new_child) {
                        current_element->InsertEndChild(new_child);
                        // Optionally change context to the new child for subsequent operations.
                        if (fdp.ConsumeBool()) {
                            current_element = new_child;
                        }
                    }
                    break;
                }
                case 1: {
                    // 3. Test XMLElement::SetAttribute.
                    std::string attr_name_str = fdp.ConsumeRandomLengthString(32);
                    std::string attr_value_str = fdp.ConsumeRandomLengthString(64);
                    // SetAttribute handles empty names gracefully, but we can be explicit.
                    if (!attr_name_str.empty()) {
                        current_element->SetAttribute(attr_name_str.c_str(), attr_value_str.c_str());
                    }
                    break;
                }
                case 2: {
                    // 4. Test XMLElement::SetText.
                    std::string text_content_str = fdp.ConsumeRandomLengthString(128);
                    current_element->SetText(text_content_str.c_str());
                    break;
                }
                case 3: {
                    // Navigate the tree to apply operations to different elements.
                    if (fdp.ConsumeBool()) { // Try to go to parent
                        tinyxml2::XMLNode* parent_node = current_element->Parent();
                        if (parent_node) {
                            tinyxml2::XMLElement* parent_element = parent_node->ToElement();
                            if (parent_element) {
                                current_element = parent_element;
                            }
                        }
                    } else { // Try to go to first child element
                        tinyxml2::XMLElement* child_element = current_element->FirstChildElement();
                        if (child_element) {
                            current_element = child_element;
                        }
                    }
                    // If navigation fails, current_element remains the same.
                    break;
                }
            }
        }
    }

    // 5. Test XMLDocument::Print using XMLPrinter.
    // XMLPrinter can be default-constructed to use an internal buffer.
    // This is memory-safe as the printer is stack-allocated and manages its own buffer.
    tinyxml2::XMLPrinter printer;
    doc->Print(&printer);
    // The printed XML string can be accessed via printer.CStr() if needed for validation,
    // but for fuzzing, just exercising the Print logic is often sufficient.
    // const char* printed_xml = printer.CStr();

    // The XMLDocument 'doc' and all its created/parsed nodes (elements, text, attributes)
    // are automatically deallocated when 'doc' (the std::unique_ptr) goes out of scope.
    // This ensures no memory leaks from the XML structure itself.

    return 0;
}