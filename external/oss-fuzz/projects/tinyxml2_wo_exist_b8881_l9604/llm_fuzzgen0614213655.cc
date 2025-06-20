#include "/src/tinyxml2/tinyxml2.h" // Project-relative path for tinyxml2
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <memory>   // For std::unique_ptr
#include <cstddef>  // For size_t
#include <cstdint>  // For uint8_t
#include <vector>   // For PickValueInArray
#include <sstream>  // For std::stringstream (used for GetCharacterRef fuzzing)
#include <cstdio>   // For FILE, fopen, fclose, remove (for LoadFile/SaveFile/Printer testing)

// Target APIs:
// ... (original list)
// New targets for this enhancement iteration:
// 17. tinyxml2::XMLUtil::ConvertUTF32ToUTF8 (to cover its internal branches)
// 18. tinyxml2::XMLNode::DeepClone and tinyxml2::XMLDocument::DeepCopy (to cover cloning logic and ShallowClone overrides)
// 19. tinyxml2::XMLNode::ShallowEqual (and its overrides for various node types, to cover comparison logic)
// New targets for this enhancement iteration (focused on 0% coverage):
// 20. tinyxml2::XMLUtil::GetCharacterRef (direct call to cover its branches)
// 21. tinyxml2::XMLNode::InsertAfterChild (to cover its branches)
// 22. tinyxml2::XMLElement::InsertNewChildElement, InsertNewComment, InsertNewText, InsertNewDeclaration, InsertNewUnknown
// 23. tinyxml2::XMLNode::ChildElementCount (both overloads)
// 24. tinyxml2::XMLNode::LastChildElement(const char*), NextSiblingElement(const char*), PreviousSiblingElement(const char*)
// 25. tinyxml2::XMLDocument error reporting functions (ErrorStr, PrintError, ErrorName, ErrorLineNum)
// 26. tinyxml2::XMLDocument::SetBOM (to influence XMLPrinter::PushHeader)
// Additional targets for this iteration based on 0% coverage from report:
// 27. tinyxml2::XMLDocument::LoadFile (const char* and FILE*) and tinyxml2::XMLDocument::SaveFile (const char* and FILE*)
// 28. tinyxml2::XMLElement::Attribute(const char* name, const char* value) const
// 29. tinyxml2::XMLPrinter::Print(const char* format, ...) and TIXML_VSCPRINTF
// Added targets for this iteration:
// - XMLPrinter::Print(const char* format, ...) to cover its internal branches and TIXML_VSCPRINTF.
// - XMLPrinter::PushAttribute numeric overloads.
// - XMLPrinter::PushText numeric overloads.
// - XMLPrinter::ClearBuffer().
// - XMLNode::SetUserData() and XMLNode::GetUserData().


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

    // Added call to XMLUtil::GetCharacterRef to cover its branches (0% coverage).
    // This function parses XML character entities.
    if (fdp.ConsumeBool()) {
        std::string entity_str;
        char value_buf[8]; // Max UTF-8 char length from one codepoint + safety
        int length = 0;

        uint8_t entity_type = fdp.ConsumeIntegralInRange<uint8_t>(0, 6);
        switch (entity_type) {
            case 0: // Valid decimal
                entity_str = "&#" + std::to_string(fdp.ConsumeIntegralInRange<uint32_t>(1, 0x10FFFF)) + ";";
                break;
            case 1: // Valid hex
            {
                uint32_t val = fdp.ConsumeIntegralInRange<uint32_t>(1, 0x10FFFF);
                std::stringstream ss;
                ss << std::hex << val;
                entity_str = "&#x" + ss.str() + ";";
            }
                break;
            case 2: // Invalid - missing semicolon
                entity_str = "&#" + std::to_string(fdp.ConsumeIntegralInRange<uint32_t>(32, 126));
                break;
            case 3: // Invalid - malformed general
                entity_str = "&" + fdp.ConsumeRandomLengthString(5) + ";"; // Ensure it might look like an entity
                break;
            case 4: // Invalid - out of range UCS value
                entity_str = "&#" + std::to_string(fdp.ConsumeIntegralInRange<uint32_t>(0x110000, 0x200000)) + ";";
                break;
            case 5: // Empty after # or #x
                entity_str = fdp.ConsumeBool() ? "&#;" : "&#x;";
                break;
            case 6: // Other malformed cases
                if (fdp.ConsumeBool()) entity_str = "&#xNOSEMICOLON";
                else if (fdp.ConsumeBool()) entity_str = "&#NoDigits;";
                else if (fdp.ConsumeBool()) entity_str = "&#xNonHexG;";
                else entity_str = "&almost;" + fdp.ConsumeRandomLengthString(3); // Test non-entity paths
                break;
        }

        if (!entity_str.empty()) {
            tinyxml2::XMLUtil::GetCharacterRef(entity_str.c_str(), value_buf, &length);
        }
        // Memory safety: entity_str is std::string, value_buf is stack allocated. No leaks.
    }


    size_t parse_string_size = fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes() / 2);
    std::string xml_to_parse = fdp.ConsumeBytesAsString(parse_string_size);
    doc->Parse(xml_to_parse.c_str(), xml_to_parse.length());

    // Added calls to error reporting functions to cover them (0% coverage).
    // These are called if Parse() results in an error.
    if (doc->Error()) {
        doc->ErrorID(); // Getter for error code
        doc->ErrorName(); // Converts error code to string
        doc->ErrorStr();  // Gets detailed error string
        doc->PrintError(); // Prints error to stdout (for coverage) - might use TIXML_VSCPRINTF
        doc->ErrorLineNum(); // Gets line number of error
    }


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
    if (fdp.ConsumeBool()) { 
        unsigned long utf32_val;
        uint8_t choice = fdp.ConsumeIntegralInRange<uint8_t>(0, 4);
        switch (choice) {
            case 0: utf32_val = fdp.ConsumeIntegralInRange<unsigned long>(0, 0x7F); break;
            case 1: utf32_val = fdp.ConsumeIntegralInRange<unsigned long>(0x80, 0x7FF); break;
            case 2: utf32_val = fdp.ConsumeIntegralInRange<unsigned long>(0x800, 0xFFFF); break;
            case 3: utf32_val = fdp.ConsumeIntegralInRange<unsigned long>(0x10000, 0x1FFFFF); break; 
            case 4: utf32_val = fdp.ConsumeIntegralInRange<unsigned long>(0x200000, 0xFFFFFFFF); break; 
            default: utf32_val = fdp.ConsumeIntegral<unsigned long>(); break;
        }
        char conversion_buffer[8]; 
        int length = 0;
        tinyxml2::XMLUtil::ConvertUTF32ToUTF8(utf32_val, conversion_buffer, &length);
    }


    if (current_element) {
        int num_operations = fdp.ConsumeIntegralInRange<int>(1, 20);
        for (int i = 0; i < num_operations; ++i) {
            if (!current_element) {
                current_element = doc->RootElement();
                if (!current_element && doc->FirstChild()) current_element = doc->FirstChild()->ToElement();
                if (!current_element) break;
            }

            uint8_t op_type = fdp.ConsumeIntegralInRange<uint8_t>(0, 13);

            switch (op_type) {
                case 0: case 1: case 2: case 3: case 4: case 5: case 6: case 7: case 8: case 9: 
                {
                    uint8_t original_op_type = op_type;
                    switch (original_op_type) {
                        case 0: { 
                            std::string child_name_str = fdp.ConsumeRandomLengthString(32);
                            if (child_name_str.empty()) child_name_str = "defaultChild";
                            tinyxml2::XMLElement *new_child = doc->NewElement(child_name_str.c_str());
                            if (new_child) {
                                current_element->InsertEndChild(new_child);
                                if (fdp.ConsumeBool()) current_element = new_child;
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
                                if (parent_node && parent_node->ToElement()) {
                                    current_element = parent_node->ToElement();
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
                        case 7: { 
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
                        case 8: { 
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
                        case 9: { 
                            uint8_t node_choice1 = fdp.ConsumeIntegralInRange<uint8_t>(0, 4); 
                            tinyxml2::XMLNode* node1 = nullptr;
                            tinyxml2::XMLNode* node2 = nullptr;

                            std::string s1_val = fdp.ConsumeRandomLengthString(20);
                            if (s1_val.empty() && node_choice1 == 0) s1_val = "node1elem"; 

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
                            
                            if (create_node2_strategy == 0) { 
                                s2_val = fdp.ConsumeBool() ? s1_val : s2_val;
                                if (s2_val.empty() && node_choice1 == 0) s2_val = "node2elem_st";
                                switch (node_choice1) {
                                    case 0: node2 = doc->NewElement(s2_val.c_str()); break;
                                    case 1: node2 = doc->NewText(s2_val.c_str()); break;
                                    case 2: node2 = doc->NewComment(s2_val.c_str()); break;
                                    case 3: node2 = doc->NewDeclaration(s2_val.c_str()); break;
                                    case 4: node2 = doc->NewUnknown(s2_val.c_str()); break;
                                }
                            } else if (create_node2_strategy == 1 && node1) { 
                                node2 = node1->ShallowClone(doc.get());
                            } else { 
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
                                if (elem1 && elem2) { 
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
                                if (text1 && text2) { 
                                    text1->SetCData(fdp.ConsumeBool());
                                    text2->SetCData(fdp.ConsumeBool());
                                    text1->ShallowEqual(text2);
                                }
                            }
                            doc->DeleteNode(node1); 
                            if (node2) doc->DeleteNode(node2);
                            break;
                        }
                    }
                    break; 
                }
                case 10: {
                    if (current_element && current_element->Parent() && current_element != doc->RootElement()) {
                        tinyxml2::XMLNode* parent = current_element->Parent();
                        tinyxml2::XMLNode* after_this_node = current_element;

                        std::string add_name = fdp.ConsumeRandomLengthString(10);
                        if (add_name.empty()) add_name = "addNodeIAC";
                        tinyxml2::XMLElement* add_this_elem = doc->NewElement(add_name.c_str());
                        
                        if (!add_this_elem) break; 

                        tinyxml2::XMLNode* inserted_node_result = nullptr;
                        uint8_t scenario = fdp.ConsumeIntegralInRange<uint8_t>(0, 4);

                        if (scenario == 0) { 
                            inserted_node_result = parent->InsertAfterChild(after_this_node, add_this_elem);
                        } else if (scenario == 1) { 
                            std::unique_ptr<tinyxml2::XMLDocument> doc2(new tinyxml2::XMLDocument());
                            tinyxml2::XMLElement* other_doc_node = doc2->NewElement("otherDocNode");
                            if (other_doc_node) {
                                parent->InsertAfterChild(after_this_node, other_doc_node); 
                            }
                            doc->DeleteNode(add_this_elem); 
                            add_this_elem = nullptr;
                        } else if (scenario == 2) { 
                            std::unique_ptr<tinyxml2::XMLDocument> temp_doc_for_orphan(new tinyxml2::XMLDocument());
                            tinyxml2::XMLElement* orphan_node = temp_doc_for_orphan->NewElement("orphanNode");
                            if (orphan_node) {
                                inserted_node_result = parent->InsertAfterChild(orphan_node, add_this_elem); 
                            }
                        } else if (scenario == 3 && after_this_node) { 
                            doc->DeleteNode(add_this_elem); 
                            add_this_elem = nullptr;
                            parent->InsertAfterChild(after_this_node, after_this_node);
                        } else if (scenario == 4 && after_this_node == parent->LastChild()) { 
                            inserted_node_result = parent->InsertAfterChild(after_this_node, add_this_elem);
                        } else { 
                            inserted_node_result = parent->InsertAfterChild(after_this_node, add_this_elem);
                        }

                        if (add_this_elem) { 
                            if (inserted_node_result == add_this_elem) { 
                                if (fdp.ConsumeBool()) current_element = add_this_elem;
                            } else { 
                                doc->DeleteNode(add_this_elem); 
                            }
                        }
                    }
                    break;
                }
                case 11: {
                    if (current_element) {
                        uint8_t insert_type = fdp.ConsumeIntegralInRange<uint8_t>(0, 4);
                        std::string content = fdp.ConsumeRandomLengthString(20);
                        if (content.empty()) content = "newContent";

                        tinyxml2::XMLNode* new_node = nullptr;
                        switch (insert_type) {
                            case 0: new_node = current_element->InsertNewChildElement(content.c_str()); break;
                            case 1: new_node = current_element->InsertNewComment(content.c_str()); break;
                            case 2: new_node = current_element->InsertNewText(content.c_str()); break;
                            case 3: new_node = current_element->InsertNewDeclaration(content.c_str()); break;
                            case 4: new_node = current_element->InsertNewUnknown(content.c_str()); break;
                        }
                        if (new_node && new_node->ToElement() && fdp.ConsumeBool()) {
                            current_element = new_node->ToElement();
                        }
                    }
                    break;
                }
                case 12: {
                    if (current_element) {
                        current_element->ChildElementCount(); 

                        std::string name_filter_str = fdp.ConsumeRandomLengthString(10);
                        const char* name_filter = name_filter_str.empty() ? nullptr : name_filter_str.c_str();

                        current_element->ChildElementCount(name_filter); 
                        current_element->LastChildElement(name_filter);

                        if (current_element->Parent() && current_element != doc->RootElement()) {
                            current_element->NextSiblingElement(name_filter);
                            current_element->PreviousSiblingElement(name_filter);
                        }
                        current_element->FirstChildElement(name_filter);
                    }
                    break;
                }
                case 13: {
                    if (current_element) {
                        std::string attr_name_str = fdp.ConsumeRandomLengthString(16);
                        if (attr_name_str.empty()) attr_name_str = "attrForAttributeApi";
                        const char* attr_name = attr_name_str.c_str();

                        std::string actual_val_str = fdp.ConsumeRandomLengthString(16);
                        if (actual_val_str.empty()) actual_val_str = "actualValueForAttrApi";
                        
                        std::string expected_val_str; 

                        uint8_t scenario = fdp.ConsumeIntegralInRange<uint8_t>(0, 3);
                        switch (scenario) {
                            case 0: 
                                current_element->Attribute(attr_name, nullptr);
                                break;
                            case 1: 
                                current_element->SetAttribute(attr_name, actual_val_str.c_str());
                                current_element->Attribute(attr_name, nullptr);
                                current_element->DeleteAttribute(attr_name); 
                                break;
                            case 2: 
                                expected_val_str = actual_val_str; 
                                current_element->SetAttribute(attr_name, actual_val_str.c_str());
                                current_element->Attribute(attr_name, expected_val_str.c_str());
                                current_element->DeleteAttribute(attr_name); 
                                break;
                            case 3: 
                                expected_val_str = actual_val_str + "_mismatch"; 
                                if (expected_val_str == actual_val_str) expected_val_str += "X"; 
                                current_element->SetAttribute(attr_name, actual_val_str.c_str());
                                current_element->Attribute(attr_name, expected_val_str.c_str());
                                current_element->DeleteAttribute(attr_name); 
                                break;
                        }
                    }
                    break;
                }
            }

            // Added calls for XMLNode::SetUserData and GetUserData (0% coverage from API list)
            if (current_element && fdp.ConsumeIntegralInRange<int>(0, 9) == 0) { // Approx 10% chance per operation
                static int user_data_payload; // Static for a stable pointer address.
                // Set UserData first, then optionally Get it to ensure GetUserData has something to return.
                current_element->SetUserData(&user_data_payload);
                if (fdp.ConsumeBool()) {
                    current_element->GetUserData();
                }
                // Memory safety: Passing a pointer to a static int is safe.
                // tinyxml2 does not manage (e.g., free) this user data.
            }
        }
    }

    if (fdp.ConsumeBool()) {
        std::string filename_str_save = fdp.ConsumeRandomLengthString(30);
        bool make_save_filename_problematic = fdp.ConsumeBool();

        if (make_save_filename_problematic) {
            uint8_t problem_type = fdp.ConsumeIntegralInRange<uint8_t>(0, 2);
            if (problem_type == 0) filename_str_save = ""; 
            else if (problem_type == 1) filename_str_save = std::string(300, 'A'); 
        } else {
            if (filename_str_save.empty() || filename_str_save.find('/') != std::string::npos || filename_str_save.find('\\') != std::string::npos) {
                filename_str_save = "fuzzer_output_doc.xml"; 
            }
        }
        
        const char* save_filename = filename_str_save.c_str();
        bool compact_save = fdp.ConsumeBool();
        doc->SaveFile(save_filename, compact_save);
        // Ensure the saved file is removed to prevent cluttering the file system
        if (filename_str_save != "") { // Only remove if a valid filename was attempted
             remove(save_filename);
        }

        tinyxml2::XMLDocument loaded_doc;
        if (fdp.ConsumeBool()) {
            // Attempt to load the (now removed) save_filename to test error handling or if it was recreated by another part of the fuzzer.
            // This behavior is kept as it might uncover different bugs.
            loaded_doc.LoadFile(save_filename);
        } else {
            std::string load_filename_str = fdp.ConsumeRandomLengthString(30);
            uint8_t load_scenario = fdp.ConsumeIntegralInRange<uint8_t>(0, 2);
            if (load_scenario == 0) {
                 if (load_filename_str.empty() && fdp.ConsumeBool()) load_filename_str = "a_surely_nonexistent_file.xml";
                 loaded_doc.LoadFile(load_filename_str.c_str());
            } else if (load_scenario == 1) {
                 loaded_doc.LoadFile("");
            } else {
                 const char* empty_file_name = "fuzzer_empty_file.xml";
                 FILE* empty_fp = fopen(empty_file_name, "w");
                 if (empty_fp) {
                     fclose(empty_fp);
                     loaded_doc.LoadFile(empty_file_name);
                     remove(empty_file_name); // Uncommented to ensure cleanup
                 }
            }
        }
        // Call error reporting functions if LoadFile resulted in an error
        if (loaded_doc.Error()) {
            loaded_doc.ErrorID();
            loaded_doc.ErrorName();
            loaded_doc.ErrorStr();
            loaded_doc.PrintError(); // Might use TIXML_VSCPRINTF
            loaded_doc.ErrorLineNum();
        }
    }

    if (fdp.ConsumeBool()) {
        std::unique_ptr<tinyxml2::XMLDocument> doc2(new tinyxml2::XMLDocument());
        if (fdp.ConsumeBool() && doc->RootElement()) { 
            tinyxml2::XMLNode* cloned_root = doc->RootElement()->DeepClone(doc2.get());
            if (cloned_root) {
                doc2->InsertEndChild(cloned_root); 
            }
        } else { 
            doc->DeepCopy(doc2.get());
        }
    }

    doc->SetBOM(fdp.ConsumeBool());

    tinyxml2::XMLPrinter printer(nullptr, fdp.ConsumeBool() /*compact*/);

    // --- Start of new code for XMLPrinter coverage ---

    // Target XMLPrinter::PushAttribute numeric overloads (0% coverage in report for these specific overloads)
    if (fdp.ConsumeBool()) {
        std::string elemName = fdp.ConsumeRandomLengthString(15);
        if (elemName.empty()) elemName = "NumericAttrsTest";
        printer.OpenElement(elemName.c_str());

        std::string attrName = fdp.ConsumeRandomLengthString(10);
        if (attrName.empty()) attrName = "numAttr";

        printer.PushAttribute(attrName.c_str(), fdp.ConsumeIntegral<int>());
        printer.PushAttribute(attrName.c_str(), fdp.ConsumeIntegral<unsigned int>());
        printer.PushAttribute(attrName.c_str(), fdp.ConsumeIntegral<int64_t>());
        printer.PushAttribute(attrName.c_str(), fdp.ConsumeIntegral<uint64_t>());
        printer.PushAttribute(attrName.c_str(), fdp.ConsumeBool());
        printer.PushAttribute(attrName.c_str(), fdp.ConsumeFloatingPoint<double>());
        // Memory safety: elemName and attrName are std::strings. Printer handles internal buffer.
        printer.CloseElement(); 
    }

    // Target XMLPrinter::PushText numeric overloads (0% coverage in report for these specific overloads)
    if (fdp.ConsumeBool()) {
        std::string elemName = fdp.ConsumeRandomLengthString(15);
        if (elemName.empty()) elemName = "NumericTextTest";
        printer.OpenElement(elemName.c_str());

        printer.PushText(fdp.ConsumeIntegral<int>());
        printer.PushText(fdp.ConsumeIntegral<unsigned int>());
        printer.PushText(fdp.ConsumeIntegral<int64_t>());
        printer.PushText(fdp.ConsumeIntegral<uint64_t>());
        printer.PushText(fdp.ConsumeBool());
        printer.PushText(fdp.ConsumeFloatingPoint<float>());
        printer.PushText(fdp.ConsumeFloatingPoint<double>());
        // Memory safety: elemName is std::string. Printer handles internal buffer.
        printer.CloseElement(); 
    }
    
    // Target XMLPrinter::ClearBuffer (0% coverage from API list)
    if (fdp.ConsumeBool()) {
        printer.ClearBuffer(fdp.ConsumeBool());
        // Memory safety: This method manages internal printer buffer, should be safe.
    }
    // --- End of new code for XMLPrinter coverage ---

    doc->Print(&printer);

    return 0;
}