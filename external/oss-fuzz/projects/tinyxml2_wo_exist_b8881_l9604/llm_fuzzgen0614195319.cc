#include "/src/tinyxml2/tinyxml2.h" // Project-relative path for tinyxml2
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <memory>   // For std::unique_ptr
#include <cstddef>  // For size_t
#include <cstdint>  // For uint8_t
#include <vector>   // For PickValueInArray

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
// New targets for this enhancement:
// 10. tinyxml2::XMLDocument constructor with Whitespace options (for StrPair::CollapseWhitespace)
// 11. tinyxml2::XMLUtil::SetBoolSerialization
// 12. XMLElement::SetAttribute for various numeric types (for XMLUtil::ToStr and typed setters)
// 13. XMLElement::SetText for various numeric types (for XMLUtil::ToStr and typed setters)
// 14. XMLElement::*Attribute (getters with default value) for various numeric types
// 15. XMLElement::*Text (getters with default value) for various numeric types
// 16. XMLPrinter constructor with compact option.

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    std::string true_str_val, false_str_val; // Keep strings in scope for SetBoolSerialization
    const char* true_cstr = nullptr;
    const char* false_cstr = nullptr;

    if (fdp.ConsumeBool()) { // Decide if we provide a custom true string
        true_str_val = fdp.ConsumeRandomLengthString(10);
        // Use "customTrue" if fdp gives empty and we want a non-empty string, to test actual custom values.
        if (true_str_val.empty() && fdp.ConsumeBool()) true_str_val = "customTrue";
        if (!true_str_val.empty()) true_cstr = true_str_val.c_str();
    }
    if (fdp.ConsumeBool()) { // Decide if we provide a custom false string
        false_str_val = fdp.ConsumeRandomLengthString(10);
        if (false_str_val.empty() && fdp.ConsumeBool()) false_str_val = "customFalse";
        if (!false_str_val.empty()) false_cstr = false_str_val.c_str();
    }
    // Call XMLUtil::SetBoolSerialization to cover this function and its branches by passing nullptr or valid C-strings.
    tinyxml2::XMLUtil::SetBoolSerialization(true_cstr, false_cstr);


    // Use std::unique_ptr for automatic memory management of XMLDocument.
    bool process_entities = fdp.ConsumeBool();
    tinyxml2::Whitespace whitespace_mode = fdp.PickValueInArray<tinyxml2::Whitespace>({tinyxml2::PRESERVE_WHITESPACE, tinyxml2::COLLAPSE_WHITESPACE});
    // Modified XMLDocument constructor to use fuzzed whitespace_mode and process_entities options.
    // This aims to cover StrPair::CollapseWhitespace (when COLLAPSE_WHITESPACE is used) and different parsing paths.
    std::unique_ptr<tinyxml2::XMLDocument> doc(new tinyxml2::XMLDocument(process_entities, whitespace_mode));

    // 1. Attempt to parse an XML string from the fuzzer data using XMLDocument::Parse.
    size_t parse_string_size = fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes() / 2);
    std::string xml_to_parse = fdp.ConsumeBytesAsString(parse_string_size);
    doc->Parse(xml_to_parse.c_str(), xml_to_parse.length());

    tinyxml2::XMLElement *current_element = doc->RootElement();
    if (!current_element) {
        std::string root_name_str = fdp.ConsumeRandomLengthString(32);
        if (root_name_str.empty()) {
            root_name_str = "defaultRoot";
        }
        current_element = doc->NewElement(root_name_str.c_str());
        if (current_element) {
            doc->InsertFirstChild(current_element);
        }
    }

    if (current_element) {
        int num_operations = fdp.ConsumeIntegralInRange<int>(1, 20);
        for (int i = 0; i < num_operations; ++i) {
            if (!current_element) {
                break;
            }

            // Choose an operation type. Range extended for new operations (0-8).
            uint8_t op_type = fdp.ConsumeIntegralInRange<uint8_t>(0, 8);

            switch (op_type) {
                case 0: {
                    std::string child_name_str = fdp.ConsumeRandomLengthString(32);
                    if (child_name_str.empty()) {
                        child_name_str = "defaultChild";
                    }
                    tinyxml2::XMLElement *new_child = doc->NewElement(child_name_str.c_str());
                    if (new_child) {
                        current_element->InsertEndChild(new_child);
                        if (fdp.ConsumeBool()) {
                            current_element = new_child;
                        }
                    }
                    break;
                }
                case 1: {
                    std::string attr_name_str = fdp.ConsumeRandomLengthString(32);
                    std::string attr_value_str = fdp.ConsumeRandomLengthString(64);
                    if (!attr_name_str.empty()) {
                        current_element->SetAttribute(attr_name_str.c_str(), attr_value_str.c_str());
                    }
                    break;
                }
                case 2: {
                    std::string text_content_str = fdp.ConsumeRandomLengthString(128);
                    current_element->SetText(text_content_str.c_str());
                    break;
                }
                case 3: {
                    if (fdp.ConsumeBool()) {
                        tinyxml2::XMLNode* parent_node = current_element->Parent();
                        if (parent_node) {
                            tinyxml2::XMLElement* parent_element = parent_node->ToElement();
                            if (parent_element) {
                                current_element = parent_element;
                            }
                        }
                    } else {
                        tinyxml2::XMLElement* child_element = current_element->FirstChildElement();
                        if (child_element) {
                            current_element = child_element;
                        }
                    }
                    break;
                }
                case 4: {
                    std::string attr_name_to_delete = fdp.ConsumeRandomLengthString(32);
                    if (!attr_name_to_delete.empty() && current_element->FirstAttribute()) {
                        current_element->DeleteAttribute(attr_name_to_delete.c_str());
                    }
                    break;
                }
                case 5: {
                    std::string attr_name_str = fdp.ConsumeRandomLengthString(32);
                    if (!attr_name_str.empty() && current_element->FirstAttribute()) {
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
                case 6: {
                    current_element->GetText();
                    if (current_element->FirstChild() && current_element->FirstChild()->ToText()) {
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
                case 7: { // Target XMLElement::SetAttribute(type), XMLElement::SetText(type) overloads, and indirectly XMLUtil::ToStr.
                    std::string name_str = fdp.ConsumeRandomLengthString(32);
                    if (name_str.empty() && fdp.ConsumeBool()) name_str = "defaultName"; // Ensure name for SetAttribute

                    uint8_t set_choice = fdp.ConsumeIntegralInRange<uint8_t>(0, 13); // 7 attribute types, 7 text types
                    if (!name_str.empty() && set_choice < 7) { // SetAttribute with typed value
                        switch (set_choice) {
                            case 0: current_element->SetAttribute(name_str.c_str(), fdp.ConsumeIntegral<int>()); break;
                            case 1: current_element->SetAttribute(name_str.c_str(), fdp.ConsumeIntegral<unsigned int>()); break;
                            case 2: current_element->SetAttribute(name_str.c_str(), fdp.ConsumeBool()); break;
                            case 3: current_element->SetAttribute(name_str.c_str(), fdp.ConsumeFloatingPoint<double>()); break;
                            case 4: current_element->SetAttribute(name_str.c_str(), fdp.ConsumeFloatingPoint<float>()); break;
                            case 5: current_element->SetAttribute(name_str.c_str(), fdp.ConsumeIntegral<int64_t>()); break;
                            case 6: current_element->SetAttribute(name_str.c_str(), fdp.ConsumeIntegral<uint64_t>()); break;
                        }
                    } else if (set_choice >= 7) { // SetText with typed value
                        switch (set_choice - 7) {
                            case 0: current_element->SetText(fdp.ConsumeIntegral<int>()); break;
                            case 1: current_element->SetText(fdp.ConsumeIntegral<unsigned int>()); break;
                            case 2: current_element->SetText(fdp.ConsumeBool()); break;
                            case 3: current_element->SetText(fdp.ConsumeFloatingPoint<double>()); break;
                            case 4: current_element->SetText(fdp.ConsumeFloatingPoint<float>()); break;
                            case 5: current_element->SetText(fdp.ConsumeIntegral<int64_t>()); break;
                            case 6: current_element->SetText(fdp.ConsumeIntegral<uint64_t>()); break;
                        }
                    }
                    break;
                }
                case 8: { // Target XMLElement::*Attribute(name, defaultVal) and XMLElement::*Text(defaultVal) getters.
                    std::string name_str = fdp.ConsumeRandomLengthString(32);
                     if (name_str.empty() && fdp.ConsumeBool()) name_str = "defaultName"; // Ensure name for *Attribute

                    uint8_t get_choice = fdp.ConsumeIntegralInRange<uint8_t>(0, 13); // 7 attribute types, 7 text types
                    if (!name_str.empty() && get_choice < 7) { // Get Attribute with default value
                        switch (get_choice) {
                            case 0: current_element->IntAttribute(name_str.c_str(), fdp.ConsumeIntegral<int>()); break;
                            case 1: current_element->UnsignedAttribute(name_str.c_str(), fdp.ConsumeIntegral<unsigned int>()); break;
                            case 2: current_element->BoolAttribute(name_str.c_str(), fdp.ConsumeBool()); break;
                            case 3: current_element->DoubleAttribute(name_str.c_str(), fdp.ConsumeFloatingPoint<double>()); break;
                            case 4: current_element->FloatAttribute(name_str.c_str(), fdp.ConsumeFloatingPoint<float>()); break;
                            case 5: current_element->Int64Attribute(name_str.c_str(), fdp.ConsumeIntegral<int64_t>()); break;
                            case 6: current_element->Unsigned64Attribute(name_str.c_str(), fdp.ConsumeIntegral<uint64_t>()); break;
                        }
                    } else if (get_choice >= 7) { // Get Text with default value
                        switch (get_choice - 7) {
                            case 0: current_element->IntText(fdp.ConsumeIntegral<int>()); break;
                            case 1: current_element->UnsignedText(fdp.ConsumeIntegral<unsigned int>()); break;
                            case 2: current_element->BoolText(fdp.ConsumeBool()); break;
                            case 3: current_element->DoubleText(fdp.ConsumeFloatingPoint<double>()); break;
                            case 4: current_element->FloatText(fdp.ConsumeFloatingPoint<float>()); break;
                            case 5: current_element->Int64Text(fdp.ConsumeIntegral<int64_t>()); break;
                            case 6: current_element->Unsigned64Text(fdp.ConsumeIntegral<uint64_t>()); break;
                        }
                    }
                    break;
                }
            }
        }
    }

    // Test XMLDocument::Print using XMLPrinter.
    // Using fdp.ConsumeBool() for 'compact' to exercise different printing paths and cover XMLPrinter constructor options.
    tinyxml2::XMLPrinter printer(nullptr, fdp.ConsumeBool());
    doc->Print(&printer);

    return 0;
}