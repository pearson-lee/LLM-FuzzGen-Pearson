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
// New targets for this enhancement iteration:
// 17. tinyxml2::XMLUtil::ConvertUTF32ToUTF8 (to cover its internal branches)
// 18. tinyxml2::XMLNode::DeepClone and tinyxml2::XMLDocument::DeepCopy (to cover cloning logic and ShallowClone overrides)
// 19. tinyxml2::XMLNode::ShallowEqual (and its overrides for various node types, to cover comparison logic)


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    std::string true_str_val, false_str_val; // Keep strings in scope for SetBoolSerialization
    const char* true_cstr = nullptr;
    const char* false_cstr = nullptr;

    if (fdp.ConsumeBool()) { 
        true_str_val = fdp.ConsumeRandomLengthString(10);
        if (true_str_val.empty() && fdp.ConsumeBool()) true_str_val = "customTrue";
        if (!true_str_val.empty()) true_cstr = true_str_val.c_str();
    }
    if (fdp.ConsumeBool()) { 
        false_str_val = fdp.ConsumeRandomLengthString(10);
        if (false_str_val.empty() && fdp.ConsumeBool()) false_str_val = "customFalse";
        if (!false_str_val.empty()) false_cstr = false_str_val.c_str();
    }
    tinyxml2::XMLUtil::SetBoolSerialization(true_cstr, false_cstr);


    bool process_entities = fdp.ConsumeBool();
    tinyxml2::Whitespace whitespace_mode = fdp.PickValueInArray<tinyxml2::Whitespace>({tinyxml2::PRESERVE_WHITESPACE, tinyxml2::COLLAPSE_WHITESPACE});
    std::unique_ptr<tinyxml2::XMLDocument> doc(new tinyxml2::XMLDocument(process_entities, whitespace_mode));

    size_t parse_string_size = fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes() / 3); // Adjusted size to leave data for other ops
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

    // Added call to XMLUtil::ConvertUTF32ToUTF8 to cover its branches.
    // This function is uncovered according to the coverage report.
    if (fdp.ConsumeBool()) {
        unsigned long utf32_val;
        uint8_t choice = fdp.ConsumeIntegralInRange<uint8_t>(0, 4);
        switch (choice) {
            case 0: utf32_val = fdp.ConsumeIntegralInRange<unsigned long>(0, 0x7F); break;
            case 1: utf32_val = fdp.ConsumeIntegralInRange<unsigned long>(0x80, 0x7FF); break;
            case 2: utf32_val = fdp.ConsumeIntegralInRange<unsigned long>(0x800, 0xFFFF); break;
            case 3: utf32_val = fdp.ConsumeIntegralInRange<unsigned long>(0x10000, 0x1FFFFF); break;
            case 4: utf32_val = fdp.ConsumeIntegralInRange<unsigned long>(0x200000, 0xFFFFFFFF); break; // Tests >4 byte case (error path)
            default: utf32_val = fdp.ConsumeIntegral<unsigned long>(); break;
        }
        char conversion_buffer[8]; // Max 4 bytes for UTF-8 from one UTF-32 char, plus buffer.
        int length = 0;
        tinyxml2::XMLUtil::ConvertUTF32ToUTF8(utf32_val, conversion_buffer, &length);
        // Memory safety: conversion_buffer is a stack-allocated array, no leaks.
    }


    if (current_element) {
        int num_operations = fdp.ConsumeIntegralInRange<int>(1, 20);
        for (int i = 0; i < num_operations; ++i) {
            if (!current_element) { // current_element might become null if root is deleted or changed
                 // Attempt to re-acquire a valid element if possible
                current_element = doc->RootElement();
                if (!current_element && doc->FirstChild()) current_element = doc->FirstChild()->ToElement();
                if (!current_element) break; 
            }

            // Choose an operation type. Range extended for new operations (0-9).
            uint8_t op_type = fdp.ConsumeIntegralInRange<uint8_t>(0, 9);

            switch (op_type) {
                case 0: { // Create and insert child
                    std::string child_name_str = fdp.ConsumeRandomLengthString(32);
                    if (child_name_str.empty()) child_name_str = "defaultChild";
                    tinyxml2::XMLElement *new_child = doc->NewElement(child_name_str.c_str());
                    if (new_child) {
                        current_element->InsertEndChild(new_child);
                        if (fdp.ConsumeBool()) current_element = new_child;
                    }
                    break;
                }
                case 1: { // Set attribute (string)
                    std::string attr_name_str = fdp.ConsumeRandomLengthString(32);
                    std::string attr_value_str = fdp.ConsumeRandomLengthString(64);
                    if (!attr_name_str.empty()) {
                        current_element->SetAttribute(attr_name_str.c_str(), attr_value_str.c_str());
                    }
                    break;
                }
                case 2: { // Set text (string)
                    std::string text_content_str = fdp.ConsumeRandomLengthString(128);
                    current_element->SetText(text_content_str.c_str());
                    break;
                }
                case 3: { // Navigate
                    if (fdp.ConsumeBool()) { // Go to parent
                        tinyxml2::XMLNode* parent_node = current_element->Parent();
                        if (parent_node && parent_node->ToElement()) {
                            current_element = parent_node->ToElement();
                        }
                    } else { // Go to first child element
                        tinyxml2::XMLElement* child_element = current_element->FirstChildElement();
                        if (child_element) {
                            current_element = child_element;
                        }
                    }
                    break;
                }
                case 4: { // Delete attribute
                    std::string attr_name_to_delete = fdp.ConsumeRandomLengthString(32);
                    if (!attr_name_to_delete.empty() && current_element->FirstAttribute()) {
                        current_element->DeleteAttribute(attr_name_to_delete.c_str());
                    }
                    break;
                }
                case 5: { // Query typed attribute
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
                case 6: { // GetText and Query typed text
                    current_element->GetText(); // Call original GetText
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
                case 7: { // Set typed attribute or text
                    std::string name_str = fdp.ConsumeRandomLengthString(32);
                    if (name_str.empty() && fdp.ConsumeBool()) name_str = "defaultName"; 
                    uint8_t set_choice = fdp.ConsumeIntegralInRange<uint8_t>(0, 13);
                    if (!name_str.empty() && set_choice < 7) {
                        switch (set_choice) {
                            case 0: current_element->SetAttribute(name_str.c_str(), fdp.ConsumeIntegral<int>()); break;
                            case 1: current_element->SetAttribute(name_str.c_str(), fdp.ConsumeIntegral<unsigned int>()); break;
                            case 2: current_element->SetAttribute(name_str.c_str(), fdp.ConsumeBool()); break;
                            case 3: current_element->SetAttribute(name_str.c_str(), fdp.ConsumeFloatingPoint<double>()); break;
                            case 4: current_element->SetAttribute(name_str.c_str(), fdp.ConsumeFloatingPoint<float>()); break;
                            case 5: current_element->SetAttribute(name_str.c_str(), fdp.ConsumeIntegral<int64_t>()); break;
                            case 6: current_element->SetAttribute(name_str.c_str(), fdp.ConsumeIntegral<uint64_t>()); break;
                        }
                    } else if (set_choice >= 7) {
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
                case 8: { // Get typed attribute or text with default value
                    std::string name_str = fdp.ConsumeRandomLengthString(32);
                    if (name_str.empty() && fdp.ConsumeBool()) name_str = "defaultName";
                    uint8_t get_choice = fdp.ConsumeIntegralInRange<uint8_t>(0, 13);
                    if (!name_str.empty() && get_choice < 7) {
                        switch (get_choice) {
                            case 0: current_element->IntAttribute(name_str.c_str(), fdp.ConsumeIntegral<int>()); break;
                            case 1: current_element->UnsignedAttribute(name_str.c_str(), fdp.ConsumeIntegral<unsigned int>()); break;
                            case 2: current_element->BoolAttribute(name_str.c_str(), fdp.ConsumeBool()); break;
                            case 3: current_element->DoubleAttribute(name_str.c_str(), fdp.ConsumeFloatingPoint<double>()); break;
                            case 4: current_element->FloatAttribute(name_str.c_str(), fdp.ConsumeFloatingPoint<float>()); break;
                            case 5: current_element->Int64Attribute(name_str.c_str(), fdp.ConsumeIntegral<int64_t>()); break;
                            case 6: current_element->Unsigned64Attribute(name_str.c_str(), fdp.ConsumeIntegral<uint64_t>()); break;
                        }
                    } else if (get_choice >= 7) {
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
                case 9: { // Target XMLNode::ShallowEqual and its overrides for various node types
                          // This case aims to cover the ShallowEqual methods which had 0% coverage.
                    uint8_t node_choice1 = fdp.ConsumeIntegralInRange<uint8_t>(0, 4); // 0:Elem, 1:Text, 2:Comment, 3:Decl, 4:Unknown
                    tinyxml2::XMLNode* node1 = nullptr;
                    tinyxml2::XMLNode* node2 = nullptr;

                    std::string s1_val = fdp.ConsumeRandomLengthString(20);
                    if (s1_val.empty() && node_choice1 == 0) s1_val = "node1elem"; // Element name must not be empty

                    switch (node_choice1) {
                        case 0: node1 = doc->NewElement(s1_val.c_str()); break;
                        case 1: node1 = doc->NewText(s1_val.c_str()); break;
                        case 2: node1 = doc->NewComment(s1_val.c_str()); break;
                        case 3: node1 = doc->NewDeclaration(s1_val.c_str()); break;
                        case 4: node1 = doc->NewUnknown(s1_val.c_str()); break;
                    }
                    if (!node1) break; 

                    uint8_t create_node2_strategy = fdp.ConsumeIntegralInRange<uint8_t>(0, 2);
                    std::string s2_val = fdp.ConsumeRandomLengthString(20);
                    
                    if (create_node2_strategy == 0) { // Same type as node1
                        s2_val = fdp.ConsumeBool() ? s1_val : s2_val;
                        if (s2_val.empty() && node_choice1 == 0) s2_val = "node2elem_st";
                        switch (node_choice1) {
                            case 0: node2 = doc->NewElement(s2_val.c_str()); break;
                            case 1: node2 = doc->NewText(s2_val.c_str()); break;
                            case 2: node2 = doc->NewComment(s2_val.c_str()); break;
                            case 3: node2 = doc->NewDeclaration(s2_val.c_str()); break;
                            case 4: node2 = doc->NewUnknown(s2_val.c_str()); break;
                        }
                    } else if (create_node2_strategy == 1 && node1) { // ShallowClone node1
                        node2 = node1->ShallowClone(doc.get());
                    } else { // Different type from node1
                        uint8_t node_choice2 = (node_choice1 + 1 + fdp.ConsumeIntegralInRange<uint8_t>(0,3)) % 5;
                        if (s2_val.empty() && node_choice2 == 0) s2_val = "node2elem_dt";
                        switch (node_choice2) {
                            case 0: node2 = doc->NewElement(s2_val.c_str()); break;
                            case 1: node2 = doc->NewText(s2_val.c_str()); break;
                            case 2: node2 = doc->NewComment(s2_val.c_str()); break;
                            case 3: node2 = doc->NewDeclaration(s2_val.c_str()); break;
                            case 4: node2 = doc->NewUnknown(s2_val.c_str()); break;
                        }
                    }

                    if (node2) {
                        node1->ShallowEqual(node2); 

                        tinyxml2::XMLElement* elem1 = node1->ToElement();
                        tinyxml2::XMLElement* elem2 = node2->ToElement();
                        if (elem1 && elem2) { // Fuzz attributes for XMLElement::ShallowEqual
                            int num_attrs_elem1 = fdp.ConsumeIntegralInRange<int>(0, 2);
                            for (int k=0; k < num_attrs_elem1; ++k) {
                                std::string attr_name = fdp.ConsumeRandomLengthString(10);
                                if (attr_name.empty()) attr_name = "attr" + std::to_string(k+1);
                                elem1->SetAttribute(attr_name.c_str(), fdp.ConsumeRandomLengthString(10).c_str());
                            }
                            if (fdp.ConsumeBool() && elem1->FirstAttribute()) {
                                 for(const tinyxml2::XMLAttribute* attr = elem1->FirstAttribute(); attr; attr = attr->Next()) {
                                    if (fdp.ConsumeBool()) {
                                        std::string val = fdp.ConsumeBool() ? attr->Value() : fdp.ConsumeRandomLengthString(10).c_str();
                                        elem2->SetAttribute(attr->Name(), val.c_str());
                                    }
                                 }
                            } else {
                                int num_attrs_elem2 = fdp.ConsumeIntegralInRange<int>(0, 2);
                                 for (int k=0; k < num_attrs_elem2; ++k) {
                                    std::string attr_name = fdp.ConsumeRandomLengthString(10);
                                    if (attr_name.empty()) attr_name = "attrB" + std::to_string(k+1);
                                    elem2->SetAttribute(attr_name.c_str(), fdp.ConsumeRandomLengthString(10).c_str());
                                }
                            }
                            elem1->ShallowEqual(elem2);
                        }
                        tinyxml2::XMLText* text1 = node1->ToText();
                        tinyxml2::XMLText* text2 = node2->ToText();
                        if (text1 && text2) { // Fuzz CData for XMLText::ShallowEqual
                            text1->SetCData(fdp.ConsumeBool());
                            text2->SetCData(fdp.ConsumeBool());
                            text1->ShallowEqual(text2);
                        }
                    }
                    // Memory safety: node1 and node2 are created via doc->New...() but not inserted into
                    // current_element's tree. They must be explicitly deleted using doc->DeleteNode().
                    doc->DeleteNode(node1); // node1 is guaranteed non-null if we reached here.
                    if (node2) doc->DeleteNode(node2);
                    break;
                }
            }
        }
    }

    // Added calls to DeepClone and DeepCopy to cover these 0% coverage functions
    // and their transitive calls to various ShallowClone methods.
    if (fdp.ConsumeBool()) {
        std::unique_ptr<tinyxml2::XMLDocument> doc2(new tinyxml2::XMLDocument());
        if (fdp.ConsumeBool() && doc->RootElement()) { // Test DeepClone on root
            tinyxml2::XMLNode* cloned_root = doc->RootElement()->DeepClone(doc2.get());
            if (cloned_root) {
                doc2->InsertEndChild(cloned_root); // doc2 takes ownership.
            }
        } else { // Test DeepCopy
            doc->DeepCopy(doc2.get());
        }
        // Memory safety: doc2 owns the deeply copied/cloned nodes.
        // Its unique_ptr will handle deallocation.
    }

    tinyxml2::XMLPrinter printer(nullptr, fdp.ConsumeBool());
    doc->Print(&printer);

    return 0;
}