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
// Added targets based on coverage analysis:
// 6. void tinyxml2::XMLElement::DeleteAttribute(const char *)
// 7. XMLError tinyxml2::XMLElement::Query<Type>Attribute(const char *, <Type>*) for various types
// 8. XMLError tinyxml2::XMLElement::Query<Type>Text(<Type>*) for various types
// 9. const char * tinyxml2::XMLElement::GetText()

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // Use std::unique_ptr for automatic memory management of XMLDocument.
    // XMLDocument owns the nodes (XMLElement, XMLText, etc.) created via its
    // NewElement, NewText methods or parsed into it. Deleting the XMLDocument
    // will clean these up, preventing memory leaks.
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

            // Choose an operation type. Range extended for new operations.
            uint8_t op_type = fdp.ConsumeIntegralInRange<uint8_t>(0, 6);

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
                case 4: { // Target XMLElement::DeleteAttribute
                    // Only attempt to delete if an attribute name is generated and attributes might exist.
                    std::string attr_name_to_delete = fdp.ConsumeRandomLengthString(32);
                    if (!attr_name_to_delete.empty() && current_element->FirstAttribute()) {
                        // Call DeleteAttribute. It's safe even if the attribute doesn't exist.
                        // This is added to cover XMLElement::DeleteAttribute based on coverage report.
                        current_element->DeleteAttribute(attr_name_to_delete.c_str());
                    }
                    break;
                }
                case 5: { // Target XMLElement::Query<Type>Attribute functions
                    std::string attr_name_str = fdp.ConsumeRandomLengthString(32);
                    // Only attempt to query if an attribute name is generated and attributes might exist.
                    if (!attr_name_str.empty() && current_element->FirstAttribute()) {
                        // Randomly select an attribute type to query.
                        // This helps cover various Query<Type>Attribute and XMLUtil::To<Type> functions,
                        // identified as uncovered in the coverage report.
                        // Query functions return an error code, but for fuzzing, calling them is the primary goal.
                        // The queried values are stack-allocated, ensuring memory safety.
                        switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 6)) {
                            case 0: { int val; current_element->QueryIntAttribute(attr_name_str.c_str(), &val); break; }
                            case 1: { unsigned val; current_element->QueryUnsignedAttribute(attr_name_str.c_str(), &val); break; }
                            case 2: { bool val; current_element->QueryBoolAttribute(attr_name_str.c_str(), &val); break; }
                            case 3: { double val; current_element->QueryDoubleAttribute(attr_name_str.c_str(), &val); break; }
                            case 4: { float val; current_element->QueryFloatAttribute(attr_name_str.c_str(), &val); break; }
                            case 5: { int64_t val; current_element->QueryInt64Attribute(attr_name_str.c_str(), &val); break; }
                            case 6: { uint64_t val; current_element->QueryUnsigned64Attribute(attr_name_str.c_str(), &val); break; }
                        }
                    }
                    break;
                }
                case 6: { // Target XMLElement::Query<Type>Text functions and XMLElement::GetText
                    // Call GetText() to cover this function, identified as uncovered.
                    // It's safe even if no text node exists (returns nullptr).
                    // The returned const char* is managed by the XMLDocument.
                    current_element->GetText();

                    // Only attempt to query text if a text node might exist.
                    if (current_element->FirstChild() && current_element->FirstChild()->ToText()) {
                        // Randomly select a text type to query.
                        // This helps cover various Query<Type>Text and XMLUtil::To<Type> functions,
                        // identified as uncovered in the coverage report.
                        // Query functions return an error code. Queried values are stack-allocated.
                        switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 6)) {
                            case 0: { int val; current_element->QueryIntText(&val); break; }
                            case 1: { unsigned val; current_element->QueryUnsignedText(&val); break; }
                            case 2: { bool val; current_element->QueryBoolText(&val); break; }
                            case 3: { double val; current_element->QueryDoubleText(&val); break; }
                            case 4: { float val; current_element->QueryFloatText(&val); break; }
                            case 5: { int64_t val; current_element->QueryInt64Text(&val); break; }
                            case 6: { uint64_t val; current_element->QueryUnsigned64Text(&val); break; }
                        }
                    }
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