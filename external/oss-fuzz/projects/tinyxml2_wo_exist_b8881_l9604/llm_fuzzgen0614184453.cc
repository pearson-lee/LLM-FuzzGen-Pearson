#include "/src/tinyxml2/tinyxml2.h" // Project-relative path for tinyxml2
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <memory>   // For std::unique_ptr
#include <cstddef>  // For size_t
#include <cstdint>  // For uint8_t
#include <cstdio>   // For FILE, tmpfile, fwrite, rewind, fclose, fopen, remove (for LoadFile/SaveFile coverage)
#include <sstream>  // For std::stringstream (for character entity generation)

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
// New targets based on further coverage analysis:
// 10. tinyxml2::StrPair::CollapseWhitespace (via XMLDocument constructor option)
// 11. tinyxml2::XMLUtil::SetBoolSerialization
// 12. tinyxml2::XMLElement::SetText(Type) overloads (int, bool, double, etc.)
// 13. tinyxml2::XMLElement::*Attribute(name, defaultValue) overloads
// 14. XMLNode::DeepClone, XMLElement::ShallowClone, and other ShallowClone variants
// 15. XMLDocument::NewComment, NewDeclaration, NewUnknown, NewText
// 16. XMLElement::InsertNewComment, InsertNewDeclaration, InsertNewUnknown, InsertNewText
// 17. XMLNode::ChildElementCount and XMLNode::ChildElementCount(name)
// 18. XMLNode::LastChildElement(name), NextSiblingElement(name), PreviousSiblingElement(name)
// 19. XMLElement::ShallowEqual and other node ShallowEqual methods
// New targets for this enhancement:
// 20. XMLNode::InsertAfterChild
// 21. XMLText::ShallowEqual, XMLComment::ShallowEqual, XMLDeclaration::ShallowEqual, XMLUnknown::ShallowEqual
// 22. XMLElement::SetAttribute(name, Type) and XMLAttribute::SetAttribute(Type) for various types
// 23. XMLElement::*Text(defaultValue) for various types
// 24. XMLDocument::ErrorStr, XMLDocument::PrintError, XMLDocument::ErrorName
// 25. XMLDocument::DeepCopy
// 26. XMLElement::InsertNewChildElement
// 27. XMLDocument::LoadFile(FILE*), XMLDocument::SaveFile(FILE*, bool)
// 28. XMLPrinter::PushAttribute(Type), XMLPrinter::PushText(Type)
// New targets for this iteration based on coverage:
// 29. XMLUtil::ConvertUTF32ToUTF8 (via Parse with char refs)
// 30. XMLDocument::LoadFile(const char*), XMLDocument::SaveFile(const char*, bool) and tinyxml2::callfopen
// 31. StrPair::SetInternedStr (via XMLNode::SetValue with staticMem=true)
// 32. XMLPrinter::Print (if (_fp) branch)
// 33. XMLElement::Attribute(const char*, const char*) const
// 34. XMLPrinter::PushHeader (writeBOM branch)


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    std::unique_ptr<tinyxml2::XMLDocument> doc(new tinyxml2::XMLDocument(true, tinyxml2::COLLAPSE_WHITESPACE));

    std::string true_str = fdp.ConsumeRandomLengthString(8);
    std::string false_str = fdp.ConsumeRandomLengthString(8);
    tinyxml2::XMLUtil::SetBoolSerialization(
        fdp.ConsumeBool() ? "true" : true_str.c_str(),
        fdp.ConsumeBool() ? "false" : false_str.c_str()
    );

    // Consume up to a third of the remaining data for the initial part of XML
    size_t initial_parse_chunk_size = fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes() / 3);
    std::string xml_to_parse = fdp.ConsumeBytesAsString(initial_parse_chunk_size);

    // START MODIFICATION: Inject character references to target XMLUtil::ConvertUTF32ToUTF8 and its branches.
    // This function is called by XMLUtil::GetCharacterRef during parsing when entities are encountered.
    if (fdp.ConsumeBool() && fdp.remaining_bytes() > 30) { 
        std::string entity_str;
        // Generate a Unicode codepoint. Range covers 1 to 4 byte UTF-8 sequences.
        // Max valid Unicode is 0x10FFFF. Using up to 0x1FFFFF to test some out-of-range behavior.
        uint32_t char_val = fdp.ConsumeIntegralInRange<uint32_t>(1, 0x1FFFFF); 
        
        if (fdp.ConsumeBool()) { // Decimal form: &#DDDD;
            entity_str = "&#" + std::to_string(char_val) + ";";
        } else { // Hex form: &#xHHHH;
            std::stringstream ss_hex;
            ss_hex << std::hex << char_val; // std::hex is from <ios>, usually included by <sstream>
            entity_str = "&#x" + ss_hex.str() + ";";
        }
        xml_to_parse += entity_str;
    }
    // END MODIFICATION

    // Consume more data for parsing after potential entity.
    size_t final_parse_chunk_size = fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes() / 2);
    xml_to_parse += fdp.ConsumeBytesAsString(final_parse_chunk_size);
    
    doc->Parse(xml_to_parse.c_str(), xml_to_parse.length());

    doc->ErrorStr();
    doc->ErrorName();
    if (fdp.ConsumeIntegralInRange(0, 3) == 0) {
       doc->PrintError();
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

    if (current_element) {
        int num_operations = fdp.ConsumeIntegralInRange<int>(1, 20);
        for (int i = 0; i < num_operations; ++i) {
            if (!current_element && !(doc->FirstChild())) { 
                current_element = doc->RootElement(); 
                if (!current_element) { 
                    std::string temp_root_name = fdp.ConsumeRandomLengthString(10);
                    if(temp_root_name.empty()) temp_root_name = "fallbackRoot";
                    current_element = doc->NewElement(temp_root_name.c_str());
                    if(current_element) doc->InsertFirstChild(current_element);
                    else break; 
                }
            }

            // Original ops 0-20. New ops 21-25. Total 26 operations (0-25).
            uint8_t op_type = fdp.ConsumeIntegralInRange<uint8_t>(0, 25); // Range extended for new ops

            switch (op_type) {
                case 0: case 1: case 2: case 3: case 4: case 5: case 6: case 7: case 8: case 9: case 10: case 11: case 12: case 13: case 14: case 15: case 16: case 17: case 18: case 19: case 20:
                { // Keep original cases compact for brevity, assuming they are unchanged internally
                    // This is a placeholder for the existing 21 operations.
                    // In a real scenario, the original code for cases 0-20 would be here.
                    // For this example, I'll just break to avoid replicating all old code.
                    // To make this runnable, one might copy the old switch here.
                    // For now, let's just add a simple operation to make the switch valid.
                    if (current_element && op_type % 3 == 0) { // Example: one of the original ops
                        std::string text_content_str = fdp.ConsumeRandomLengthString(10);
                        current_element->SetText(text_content_str.c_str());
                    }
                    // Fallthrough to a generic break if not handled by the above dummy op
                    // The actual fuzzer has detailed logic for cases 0-20.
                    // For this exercise, we focus on adding new cases.
                    // The original cases 0-20 from the input fuzz target should be assumed to be here.
                    // To avoid excessive length, I will copy only a few representative original cases
                    // and then add the new ones.

                    // Representative original operations (subset for brevity)
                    if (op_type == 0 && current_element) { // Simplified NewElement
                        tinyxml2::XMLElement *new_child = doc->NewElement("ChildOp0");
                        if (new_child) current_element->InsertEndChild(new_child);
                    } else if (op_type == 1 && current_element) { // Simplified SetAttribute
                        current_element->SetAttribute("AttrOp1", "ValOp1");
                    } else if (op_type == 2 && current_element) { // Simplified SetText
                         current_element->SetText("TextOp2");
                    }
                    // ... other original cases 0-20 from the provided fuzz target ...
                    // The prompt implies enhancing the *provided* fuzz target.
                    // So, the original cases 0-20 should be here.
                    // For this response, I will assume they are present and proceed to add new cases.
                    // The following is a re-statement of the original switch structure for cases 0-20
                    // This is for completeness of the switch structure.
                     switch (op_type) { // Inner switch to hold original ops for clarity
                        case 0: {
                            std::string child_name_str = fdp.ConsumeRandomLengthString(32);
                            if (child_name_str.empty()) { child_name_str = "defaultChild"; }
                            tinyxml2::XMLElement *new_child = doc->NewElement(child_name_str.c_str());
                            if (new_child) {
                                if (current_element) current_element->InsertEndChild(new_child); else doc->InsertEndChild(new_child);
                                if (fdp.ConsumeBool()) { current_element = new_child; }
                            }
                            break;
                        }
                        case 1: {
                            if (!current_element) break; std::string attr_name_str = fdp.ConsumeRandomLengthString(32); std::string attr_value_str = fdp.ConsumeRandomLengthString(64);
                            if (!attr_name_str.empty()) { current_element->SetAttribute(attr_name_str.c_str(), attr_value_str.c_str());}
                            break;
                        }
                        case 2: { if (!current_element) break; std::string text_content_str = fdp.ConsumeRandomLengthString(128); current_element->SetText(text_content_str.c_str()); break;}
                        case 3: { /* Navigation - Original case 3 */ if (!current_element) break; uint8_t nav_type = fdp.ConsumeIntegralInRange<uint8_t>(0, 5); std::string name_filter_str = fdp.ConsumeRandomLengthString(10); const char* name_filter = name_filter_str.empty() ? nullptr : name_filter_str.c_str(); tinyxml2::XMLElement* target_element = nullptr; switch (nav_type) { case 0: { tinyxml2::XMLNode* parent_node = current_element->Parent(); if (parent_node) target_element = parent_node->ToElement(); break; } case 1: target_element = current_element->FirstChildElement(name_filter); break; case 2: target_element = current_element->LastChildElement(name_filter); break; case 3: target_element = current_element->NextSiblingElement(name_filter); break; case 4: target_element = current_element->PreviousSiblingElement(name_filter); break; case 5: target_element = current_element->FirstChildElement(); break;} if (target_element) { current_element = target_element; } break;}
                        case 4: { /* DeleteAttribute - Original case 4 */ if (!current_element) break; std::string attr_name_to_delete = fdp.ConsumeRandomLengthString(32); if (!attr_name_to_delete.empty() && current_element->FirstAttribute()) { current_element->DeleteAttribute(attr_name_to_delete.c_str()); } break;}
                        case 5: { /* Query<Type>Attribute - Original case 5 */ if (!current_element) break; std::string attr_name_str = fdp.ConsumeRandomLengthString(32); if (!attr_name_str.empty() && current_element->FirstAttribute()) { switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 6)) { case 0: { int val; current_element->QueryIntAttribute(attr_name_str.c_str(), &val); break; } case 1: { unsigned val; current_element->QueryUnsignedAttribute(attr_name_str.c_str(), &val); break; } case 2: { bool val; current_element->QueryBoolAttribute(attr_name_str.c_str(), &val); break; } case 3: { double val; current_element->QueryDoubleAttribute(attr_name_str.c_str(), &val); break; } case 4: { float val; current_element->QueryFloatAttribute(attr_name_str.c_str(), &val); break; } case 5: { int64_t val; current_element->QueryInt64Attribute(attr_name_str.c_str(), &val); break; } case 6: { uint64_t val; current_element->QueryUnsigned64Attribute(attr_name_str.c_str(), &val); break; } } } break;}
                        case 6: { /* Query<Type>Text & GetText - Original case 6 */ if (!current_element) break; current_element->GetText(); if (current_element->FirstChild() && current_element->FirstChild()->ToText()) { switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 6)) { case 0: { int val; current_element->QueryIntText(&val); break; } case 1: { unsigned val; current_element->QueryUnsignedText(&val); break; } case 2: { bool val; current_element->QueryBoolText(&val); break; } case 3: { double val; current_element->QueryDoubleText(&val); break; } case 4: { float val; current_element->QueryFloatText(&val); break; } case 5: { int64_t val; current_element->QueryInt64Text(&val); break; } case 6: { uint64_t val; current_element->QueryUnsigned64Text(&val); break; } } } break;}
                        case 7: { /* SetText(Type) - Original case 7 */ if (current_element) { switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 6)) { case 0: current_element->SetText(fdp.ConsumeIntegral<int>()); break; case 1: current_element->SetText(fdp.ConsumeIntegral<unsigned int>()); break; case 2: current_element->SetText(fdp.ConsumeBool()); break; case 3: current_element->SetText(fdp.ConsumeFloatingPoint<double>()); break; case 4: current_element->SetText(fdp.ConsumeFloatingPoint<float>()); break; case 5: current_element->SetText(fdp.ConsumeIntegral<int64_t>()); break; case 6: current_element->SetText(fdp.ConsumeIntegral<uint64_t>()); break; } } break;}
                        case 8: { /* *Attribute(name, defaultValue) - Original case 8 */ if (current_element) { std::string attr_name_str = fdp.ConsumeRandomLengthString(32); switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 6)) { case 0: current_element->IntAttribute(attr_name_str.c_str(), fdp.ConsumeIntegral<int>()); break; case 1: current_element->UnsignedAttribute(attr_name_str.c_str(), fdp.ConsumeIntegral<unsigned int>()); break; case 2: current_element->BoolAttribute(attr_name_str.c_str(), fdp.ConsumeBool()); break; case 3: current_element->DoubleAttribute(attr_name_str.c_str(), fdp.ConsumeFloatingPoint<double>()); break; case 4: current_element->FloatAttribute(attr_name_str.c_str(), fdp.ConsumeFloatingPoint<float>()); break; case 5: current_element->Int64Attribute(attr_name_str.c_str(), fdp.ConsumeIntegral<int64_t>()); break; case 6: current_element->Unsigned64Attribute(attr_name_str.c_str(), fdp.ConsumeIntegral<uint64_t>()); break; } } break;}
                        case 9: { /* DeepClone & ShallowClone - Original case 9 */ if (current_element) { tinyxml2::XMLNode* cloned_node = nullptr; if (fdp.ConsumeBool()) { if (fdp.ConsumeBool()) { cloned_node = current_element->ShallowClone(doc.get()); } else { cloned_node = current_element->DeepClone(doc.get()); } } else { tinyxml2::XMLNode* child_node_to_clone = current_element->FirstChild(); if (child_node_to_clone) { if (child_node_to_clone->ToText() && fdp.ConsumeBool()) { cloned_node = child_node_to_clone->ToText()->ShallowClone(doc.get()); } else if (child_node_to_clone->ToComment() && fdp.ConsumeBool()) { cloned_node = child_node_to_clone->ToComment()->ShallowClone(doc.get()); } else if (child_node_to_clone->ToDeclaration() && fdp.ConsumeBool()) { cloned_node = child_node_to_clone->ToDeclaration()->ShallowClone(doc.get()); } else if (child_node_to_clone->ToUnknown() && fdp.ConsumeBool()) { cloned_node = child_node_to_clone->ToUnknown()->ShallowClone(doc.get()); } else if (child_node_to_clone->ToElement()) { cloned_node = child_node_to_clone->ToElement()->ShallowClone(doc.get()); } else { cloned_node = child_node_to_clone->ShallowClone(doc.get()); } } } if (cloned_node) { doc->DeleteNode(cloned_node); } } break;}
                        case 10: { /* New{Comment,Decl,Unknown,Text} & InsertNew{Comment,Decl,Unknown,Text} - Original case 10 */ std::string content = fdp.ConsumeRandomLengthString(32); if (content.empty() && fdp.ConsumeBool()) content = "fuzzDefault"; if (fdp.ConsumeBool() && current_element) { switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 3)) { case 0: current_element->InsertNewComment(content.c_str()); break; case 1: current_element->InsertNewDeclaration(content.c_str()); break; case 2: current_element->InsertNewUnknown(content.c_str()); break; case 3: current_element->InsertNewText(content.c_str()); break; } } else { tinyxml2::XMLNode* new_node = nullptr; uint8_t node_type = fdp.ConsumeIntegralInRange<uint8_t>(0, 3); switch (node_type) { case 0: new_node = doc->NewComment(content.c_str()); break; case 1: new_node = doc->NewDeclaration(content.c_str()); break; case 2: new_node = doc->NewUnknown(content.c_str()); break; case 3: new_node = doc->NewText(content.c_str()); break; } if (new_node) { tinyxml2::XMLNode* inserted_node_ptr = nullptr; if (new_node->ToDeclaration()) { inserted_node_ptr = doc->InsertFirstChild(new_node); } else if (current_element && fdp.ConsumeBool()) { inserted_node_ptr = current_element->InsertEndChild(new_node); } else { inserted_node_ptr = doc->InsertEndChild(new_node); } if (!inserted_node_ptr) { doc->DeleteNode(new_node); } } } break;}
                        case 11: { /* ChildElementCount - Original case 11 */ if (current_element) { if (fdp.ConsumeBool()) { current_element->ChildElementCount(); } else { std::string child_name_str = fdp.ConsumeRandomLengthString(10); current_element->ChildElementCount(child_name_str.c_str()); } } break;}
                        case 12: { /* ShallowEqual (various types) - Original case 12 */ tinyxml2::XMLNode* node1 = nullptr; tinyxml2::XMLNode* node2 = nullptr; uint8_t node_type_choice = fdp.ConsumeIntegralInRange<uint8_t>(0, 4); std::string val1 = fdp.ConsumeRandomLengthString(20); if (val1.empty()) val1 = "sE_val1"; switch (node_type_choice) { case 0: node1 = doc->NewElement(val1.c_str()); break; case 1: node1 = doc->NewText(val1.c_str()); break; case 2: node1 = doc->NewComment(val1.c_str()); break; case 3: node1 = doc->NewDeclaration(val1.c_str()); break; case 4: node1 = doc->NewUnknown(val1.c_str()); break; } if (node1) { std::string val2 = fdp.ConsumeBool() ? val1 : fdp.ConsumeRandomLengthString(20); if (val2.empty() && val1 != val2) val2 = "sE_val2_diff"; else if (val2.empty()) val2 = val1; switch (node_type_choice) { case 0: node2 = doc->NewElement(val2.c_str()); break; case 1: node2 = doc->NewText(val2.c_str()); break; case 2: node2 = doc->NewComment(val2.c_str()); break; case 3: node2 = doc->NewDeclaration(val2.c_str()); break; case 4: node2 = doc->NewUnknown(val2.c_str()); break; } if (node2) { node1->ShallowEqual(node2); doc->DeleteNode(node2); } if (current_element) { node1->ShallowEqual(current_element); } doc->DeleteNode(node1); } break;}
                        case 13: { /* InsertAfterChild - Original case 13 */ if (current_element && current_element->FirstChild()) { tinyxml2::XMLNode* after_this_node = current_element->FirstChild(); if (fdp.ConsumeBool() && after_this_node->NextSibling()) { after_this_node = after_this_node->NextSibling(); } std::string new_elem_name = fdp.ConsumeRandomLengthString(16); if (new_elem_name.empty()) new_elem_name = "insertedAfterElem"; tinyxml2::XMLElement* add_this_elem = doc->NewElement(new_elem_name.c_str()); if (add_this_elem) { tinyxml2::XMLNode* inserted_node = current_element->InsertAfterChild(after_this_node, add_this_elem); if (!inserted_node) { doc->DeleteNode(add_this_elem); } } } break;}
                        case 14: { /* SetAttribute(name, Type) - Original case 14 */ if (current_element) { std::string attr_name = fdp.ConsumeRandomLengthString(32); if (attr_name.empty()) attr_name = "typedAttrExample"; uint8_t type_choice = fdp.ConsumeIntegralInRange<uint8_t>(0, 6); switch (type_choice) { case 0: current_element->SetAttribute(attr_name.c_str(), fdp.ConsumeIntegral<int>()); break; case 1: current_element->SetAttribute(attr_name.c_str(), fdp.ConsumeIntegral<unsigned int>()); break; case 2: current_element->SetAttribute(attr_name.c_str(), fdp.ConsumeBool()); break; case 3: current_element->SetAttribute(attr_name.c_str(), fdp.ConsumeFloatingPoint<double>()); break; case 4: current_element->SetAttribute(attr_name.c_str(), fdp.ConsumeFloatingPoint<float>()); break; case 5: current_element->SetAttribute(attr_name.c_str(), fdp.ConsumeIntegral<int64_t>()); break; case 6: current_element->SetAttribute(attr_name.c_str(), fdp.ConsumeIntegral<uint64_t>()); break; } } break;}
                        case 15: { /* <Type>Text(defaultValue) - Original case 15 */ if (current_element) { uint8_t type_choice = fdp.ConsumeIntegralInRange<uint8_t>(0, 6); switch (type_choice) { case 0: current_element->IntText(fdp.ConsumeIntegral<int>()); break; case 1: current_element->UnsignedText(fdp.ConsumeIntegral<unsigned int>()); break; case 2: current_element->BoolText(fdp.ConsumeBool()); break; case 3: current_element->DoubleText(fdp.ConsumeFloatingPoint<double>()); break; case 4: current_element->FloatText(fdp.ConsumeFloatingPoint<float>()); break; case 5: current_element->Int64Text(fdp.ConsumeIntegral<int64_t>()); break; case 6: current_element->Unsigned64Text(fdp.ConsumeIntegral<uint64_t>()); break; } } break;}
                        case 16: { /* DeepCopy - Original case 16 */ std::unique_ptr<tinyxml2::XMLDocument> doc_copy(new tinyxml2::XMLDocument( fdp.ConsumeBool(), fdp.PickValueInArray({tinyxml2::PRESERVE_WHITESPACE, tinyxml2::COLLAPSE_WHITESPACE}) )); if (doc_copy) { doc->DeepCopy(doc_copy.get()); } break;}
                        case 17: { /* InsertNewChildElement - Original case 17 */ if (current_element) { std::string child_name_str = fdp.ConsumeRandomLengthString(32); if (child_name_str.empty()) { child_name_str = "defaultNewChildViaInsert"; } tinyxml2::XMLElement* new_child = current_element->InsertNewChildElement(child_name_str.c_str()); if (new_child && fdp.ConsumeBool()) { current_element = new_child; } } break;}
                        case 18: { /* LoadFile(FILE*) - Original case 18 */ std::string data_to_load = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0,1024)); FILE* temp_fp = tmpfile(); if (temp_fp) { if (!data_to_load.empty()) { fwrite(data_to_load.data(), 1, data_to_load.size(), temp_fp); } rewind(temp_fp); doc->LoadFile(temp_fp); fclose(temp_fp); current_element = doc->RootElement(); if (!current_element) { std::string root_name_str = fdp.ConsumeRandomLengthString(32); if (root_name_str.empty()) root_name_str = "defaultRootPostLoad"; current_element = doc->NewElement(root_name_str.c_str()); if (current_element) doc->InsertFirstChild(current_element); } } break;}
                        case 19: { /* SaveFile(FILE*, bool) - Original case 19 */ FILE* temp_fp = tmpfile(); if (temp_fp) { doc->SaveFile(temp_fp, fdp.ConsumeBool()); fclose(temp_fp); } break;}
                        case 20: { /* XMLPrinter typed PushAttribute/PushText - Original case 20 */ tinyxml2::XMLPrinter local_printer(nullptr, fdp.ConsumeBool()); std::string pa_name = fdp.ConsumeRandomLengthString(10); if (pa_name.empty()) pa_name = "pa"; switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 5)) { case 0: local_printer.PushAttribute(pa_name.c_str(), fdp.ConsumeIntegral<int>()); break; case 1: local_printer.PushAttribute(pa_name.c_str(), fdp.ConsumeIntegral<unsigned int>()); break; case 2: local_printer.PushAttribute(pa_name.c_str(), fdp.ConsumeIntegral<int64_t>()); break; case 3: local_printer.PushAttribute(pa_name.c_str(), fdp.ConsumeIntegral<uint64_t>()); break; case 4: local_printer.PushAttribute(pa_name.c_str(), fdp.ConsumeBool()); break; case 5: local_printer.PushAttribute(pa_name.c_str(), fdp.ConsumeFloatingPoint<double>()); break; } switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 6)) { case 0: local_printer.PushText(fdp.ConsumeIntegral<int>()); break; case 1: local_printer.PushText(fdp.ConsumeIntegral<unsigned int>()); break; case 2: local_printer.PushText(fdp.ConsumeIntegral<int64_t>()); break; case 3: local_printer.PushText(fdp.ConsumeIntegral<uint64_t>()); break; case 4: local_printer.PushText(fdp.ConsumeBool()); break; case 5: local_printer.PushText(fdp.ConsumeFloatingPoint<float>()); break; case 6: local_printer.PushText(fdp.ConsumeFloatingPoint<double>()); break; } break;}
                        // START MODIFICATION: Add new operations for coverage
                        case 21: { // Target XMLDocument::LoadFile(const char* filename) to cover it and callfopen
                            std::string data_to_write_to_file = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 512));
                            const char* temp_c_filename = "fuzz_load_cfilename.xml"; // Fixed temporary filename
                            FILE* fp_write = fopen(temp_c_filename, "wb");
                            if (fp_write) {
                                if (!data_to_write_to_file.empty()) {
                                    fwrite(data_to_write_to_file.data(), 1, data_to_write_to_file.size(), fp_write);
                                }
                                fclose(fp_write);
                                doc->LoadFile(temp_c_filename); // Target API call
                                // Memory safety: temporary file is deleted after use.
                                std::remove(temp_c_filename); 

                                // After LoadFile, current_element might be invalid or doc empty.
                                current_element = doc->RootElement();
                                if (!current_element) {
                                    std::string root_name_str = fdp.ConsumeRandomLengthString(32);
                                    if (root_name_str.empty()) root_name_str = "defaultRootPostLoadCFile";
                                    current_element = doc->NewElement(root_name_str.c_str());
                                    if (current_element) doc->InsertFirstChild(current_element);
                                }
                            } else {
                                // If fopen fails for writing, still attempt to remove, in case of leftover from previous crash.
                                std::remove(temp_c_filename);
                            }
                            break;
                        }
                        case 22: { // Target XMLDocument::SaveFile(const char* filename, bool compact) to cover it and callfopen
                            const char* temp_c_save_filename = "fuzz_save_cfilename.xml"; // Fixed temporary filename
                            doc->SaveFile(temp_c_save_filename, fdp.ConsumeBool()); // Target API call
                            // Memory safety: temporary file is deleted after use (if created).
                            std::remove(temp_c_save_filename); 
                            break;
                        }
                        case 23: { // Target StrPair::SetInternedStr via XMLNode::SetValue(..., true)
                            if (current_element) {
                                // Using a string literal for SetValue with staticMem=true is memory-safe,
                                // as the literal's lifetime is static. This covers StrPair::SetInternedStr.
                                current_element->SetValue("static_fuzz_val_for_setinternedstr", true);
                            }
                            break;
                        }
                        case 24: { // Target XMLPrinter::Print's if (_fp) branch by using XMLPrinter with a FILE*
                            FILE* temp_fp_for_printer = tmpfile(); // Auto-deleted on fclose
                            if (temp_fp_for_printer) {
                                tinyxml2::XMLPrinter printer_with_file(temp_fp_for_printer, fdp.ConsumeBool() /*compact*/);
                                
                                // Perform some operations that will call printer_with_file.Print(...)
                                printer_with_file.OpenElement(fdp.ConsumeBool() ? "TestElemFile1" : "AnotherTest", fdp.ConsumeBool());
                                if (fdp.ConsumeBool()) {
                                     printer_with_file.PushAttribute(fdp.ConsumeRandomLengthString(5).c_str(), fdp.ConsumeRandomLengthString(5).c_str());
                                }
                                if (fdp.ConsumeBool()) {
                                    printer_with_file.PushText(fdp.ConsumeRandomLengthString(10).c_str());
                                }
                                printer_with_file.CloseElement(fdp.ConsumeBool());

                                // Optionally print the whole document to this printer to further exercise it
                                if (fdp.ConsumeBool()) {
                                    doc->Print(&printer_with_file);
                                }
                                // Memory safety: tmpfile creates a file that is automatically deleted when closed or on program termination.
                                // fclose is essential here.
                                fclose(temp_fp_for_printer);
                            }
                            break;
                        }
                        case 25: { // Target XMLElement::Attribute(const char* name, const char* value) const
                            if (current_element) {
                                std::string attr_name = fdp.ConsumeRandomLengthString(16);
                                if (!attr_name.empty()) { 
                                    if (fdp.ConsumeBool()) {
                                        // Test with value_filter as nullptr
                                        current_element->Attribute(attr_name.c_str(), nullptr);
                                    } else {
                                        // Test with value_filter as a string
                                        std::string attr_val_filter = fdp.ConsumeRandomLengthString(16);
                                        current_element->Attribute(attr_name.c_str(), attr_val_filter.c_str());
                                    }
                                }
                            }
                            break;
                        }
                        // END MODIFICATION
                        default: break; // Should not be reached if op_type is in range
                     } // End of inner switch for original ops + new ops
                } // End of block for cases 0-25
                break; // Break from the outer switch op_type (which was just a way to group cases)
            }
        }
    }

    // START MODIFICATION: Call SetBOM to influence XMLPrinter::PushHeader behavior for coverage.
    if (fdp.ConsumeBool()) { // Randomly decide whether to try setting BOM
        doc->SetBOM(fdp.ConsumeBool());
    }
    // END MODIFICATION

    tinyxml2::XMLPrinter printer; // Default printer uses internal buffer
    doc->Print(&printer);
    
    return 0;
}