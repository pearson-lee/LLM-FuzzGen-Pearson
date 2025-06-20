#include "/src/tinyxml2/tinyxml2.h" // Project-relative path for tinyxml2
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <memory>   // For std::unique_ptr
#include <cstddef>  // For size_t
#include <cstdint>  // For uint8_t
#include <vector>   // For PickValueInArray
#include <sstream>  // For std::stringstream (used for GetCharacterRef fuzzing)

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
    if (doc->Error()) {
        doc->ErrorID(); // Getter for error code
        doc->ErrorName(); // Converts error code to string
        doc->ErrorStr();  // Gets detailed error string
        doc->PrintError(); // Prints error to stdout (for coverage)
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
    if (fdp.ConsumeBool()) { // This was already present, keeping it.
        unsigned long utf32_val;
        uint8_t choice = fdp.ConsumeIntegralInRange<uint8_t>(0, 4);
        switch (choice) {
            case 0: utf32_val = fdp.ConsumeIntegralInRange<unsigned long>(0, 0x7F); break;
            case 1: utf32_val = fdp.ConsumeIntegralInRange<unsigned long>(0x80, 0x7FF); break;
            case 2: utf32_val = fdp.ConsumeIntegralInRange<unsigned long>(0x800, 0xFFFF); break;
            case 3: utf32_val = fdp.ConsumeIntegralInRange<unsigned long>(0x10000, 0x1FFFFF); break; // Max valid is 0x10FFFF
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

            // Extended op_type range for new operations (0-12).
            uint8_t op_type = fdp.ConsumeIntegralInRange<uint8_t>(0, 12);

            switch (op_type) {
                case 0: case 1: case 2: case 3: case 4: case 5: case 6: case 7: case 8: case 9: // Existing operations
                {
                    // Re-map to avoid large empty case blocks, keep original logic for 0-9
                    uint8_t original_op_type = op_type;
                    // ... (original cases 0-9 from the input fuzz target) ...
                    // This is a placeholder. The actual original cases 0-9 should be here.
                    // For brevity in this example, I'm showing the structure.
                    // In a real scenario, copy-paste the original cases 0-9 here.
                    // START OF ORIGINAL CASES 0-9 (Copied and adapted)
                    switch (original_op_type) {
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
                        case 9: { // Target XMLNode::ShallowEqual and its overrides
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
                    // END OF ORIGINAL CASES 0-9
                    break; // Break from the outer switch case for 0-9
                }
                // Added case 10: Target XMLNode::InsertAfterChild to cover its branches (0% coverage).
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

                        if (scenario == 0) { // Normal valid insertion
                            inserted_node_result = parent->InsertAfterChild(after_this_node, add_this_elem);
                        } else if (scenario == 1) { // addThis from another document
                            std::unique_ptr<tinyxml2::XMLDocument> doc2(new tinyxml2::XMLDocument());
                            tinyxml2::XMLElement* other_doc_node = doc2->NewElement("otherDocNode");
                            if (other_doc_node) {
                                parent->InsertAfterChild(after_this_node, other_doc_node); // Should return 0
                                // Memory safety: other_doc_node is owned by doc2 and will be cleaned up.
                            }
                            doc->DeleteNode(add_this_elem); // Original add_this_elem not used.
                            add_this_elem = nullptr;
                        } else if (scenario == 2) { // afterThis not a child of parent
                            std::unique_ptr<tinyxml2::XMLDocument> temp_doc_for_orphan(new tinyxml2::XMLDocument());
                            tinyxml2::XMLElement* orphan_node = temp_doc_for_orphan->NewElement("orphanNode");
                            if (orphan_node) {
                                inserted_node_result = parent->InsertAfterChild(orphan_node, add_this_elem); // Should return 0
                                // Memory safety: orphan_node is owned by temp_doc_for_orphan.
                            }
                        } else if (scenario == 3 && after_this_node) { // afterThis == addThis
                            doc->DeleteNode(add_this_elem); // Original add_this_elem not used.
                            add_this_elem = nullptr;
                            // Try to insert after_this_node after itself. This should hit the (afterThis == addThis) check.
                            parent->InsertAfterChild(after_this_node, after_this_node);
                        } else if (scenario == 4 && after_this_node == parent->LastChild()) { // afterThis is last child
                            inserted_node_result = parent->InsertAfterChild(after_this_node, add_this_elem);
                        } else { // Fallback or other valid cases
                            inserted_node_result = parent->InsertAfterChild(after_this_node, add_this_elem);
                        }

                        if (add_this_elem) { // If original add_this_elem is still valid (not nulled)
                            if (inserted_node_result == add_this_elem) { // And it was successfully inserted
                                if (fdp.ConsumeBool()) current_element = add_this_elem;
                            } else { // Not inserted or a different node was involved
                                doc->DeleteNode(add_this_elem); // Delete it
                            }
                        }
                    }
                    break;
                }
                // Added case 11: Target XMLElement::InsertNew... functions (0% coverage).
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
                        // Memory safety: Returned node is owned by the document if insertion is successful.
                        if (new_node && new_node->ToElement() && fdp.ConsumeBool()) {
                            current_element = new_node->ToElement();
                        }
                    }
                    break;
                }
                // Added case 12: Target XMLNode::ChildElementCount and named Sibling/ChildElement functions (0% coverage).
                case 12: {
                    if (current_element) {
                        current_element->ChildElementCount(); // Unnamed overload

                        std::string name_filter_str = fdp.ConsumeRandomLengthString(10);
                        // Use nullptr if string is empty, otherwise c_str().
                        const char* name_filter = name_filter_str.empty() ? nullptr : name_filter_str.c_str();

                        current_element->ChildElementCount(name_filter); // Named overload
                        current_element->LastChildElement(name_filter);

                        if (current_element->Parent() && current_element != doc->RootElement()) {
                            current_element->NextSiblingElement(name_filter);
                            current_element->PreviousSiblingElement(name_filter);
                        }
                         // Also cover FirstChildElement(name) as it's similar and might have specific paths.
                        current_element->FirstChildElement(name_filter);
                    }
                    break;
                }
            }
        }
    }

    // Added calls to DeepClone and DeepCopy (already present, keeping them).
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

    // Added SetBOM to influence XMLPrinter behavior for PushHeader coverage.
    doc->SetBOM(fdp.ConsumeBool());

    tinyxml2::XMLPrinter printer(nullptr, fdp.ConsumeBool());
    doc->Print(&printer);

    return 0;
}