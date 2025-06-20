#include "/src/tinyxml2/tinyxml2.h" // Project-relative path for tinyxml2
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>
#include <memory>   // For std::unique_ptr
#include <cstddef>  // For size_t
#include <cstdint>  // For uint8_t
#include <cstdio>   // For fopen, fclose, remove, FILE

// Target APIs:
// 1. DW_TAG_enumeration_typeXMLError tinyxml2::XMLDocument::Parse(const char *, size_t)
// 2. XMLElement * tinyxml2::XMLDocument::NewElement(const char *)
// 3. void tinyxml2::XMLElement::SetAttribute(const char *, const char *)
// 4. void tinyxml2::XMLElement::SetText(const char *)
// 5. void tinyxml2::XMLDocument::Print(XMLPrinter *)
// Added targets based on coverage analysis:
// 6. void tinyxml2::XMLElement::DeleteAttribute(const char *) // ADDRESSED
// 7. XMLError tinyxml2::XMLElement::Query<Type>Attribute(const char *, <Type>*) for various types // ADDRESSED via *Attribute
// 8. XMLError tinyxml2::XMLElement::Query<Type>Text(<Type>*) for various types // ADDRESSED via *Text
// 9. const char * tinyxml2::XMLElement::GetText() // ADDRESSED
// New targets based on further coverage analysis:
// 10. tinyxml2::StrPair::CollapseWhitespace (via XMLDocument constructor option)
// 11. tinyxml2::XMLUtil::SetBoolSerialization
// 12. tinyxml2::XMLElement::SetText(Type) overloads (int, bool, double, etc.) // ADDRESSED
// 13. tinyxml2::XMLElement::*Attribute(name, defaultValue) overloads // ADDRESSED
// 14. XMLNode::DeepClone, XMLElement::ShallowClone, and other ShallowClone variants // ADDRESSED
// 15. XMLDocument::NewComment, NewDeclaration, NewUnknown, NewText // Covered by existing fuzzer logic or new ops
// 16. XMLElement::InsertNewComment, InsertNewDeclaration, InsertNewUnknown, InsertNewText // ADDRESSED
// 17. XMLNode::ChildElementCount and XMLNode::ChildElementCount(name) // ADDRESSED
// 18. XMLNode::LastChildElement(name), NextSiblingElement(name), PreviousSiblingElement(name)
// 19. XMLElement::ShallowEqual and other node ShallowEqual methods // ADDRESSED
// New targets for this enhancement:
// 20. XMLNode::InsertAfterChild and its branches // ADDRESSED
// 21. ShallowEqual for XMLText, XMLComment, XMLDeclaration, XMLUnknown // ADDRESSED
// 22. XMLElement::SetAttribute(Type value) overloads (int, bool, double, etc.) // ADDRESSED
// 23. XMLElement::*Text(defaultValue) functions (IntText, BoolText etc.) // ADDRESSED
// 24. XMLDocument::DeepCopy // ADDRESSED
// 25. XMLElement::InsertNewChildElement // ADDRESSED
// New targets for this enhancement iteration:
// 26. XMLUtil::ConvertUTF32ToUTF8 (via character references in Parse)
// 27. XMLDocument::LoadFile(const char*), XMLDocument::SaveFile(const char*, bool) (and tinyxml2::callfopen)
// 28. XMLDocument::ErrorName(), XMLDocument::ErrorStr()
// 29. XMLHandle and XMLConstHandle methods
// 30. Direct XMLPrinter usage: PushText(Type), PushAttribute(Type), Print(format,...), PushHeader
// 31. Various XMLNode utility methods (GetUserData, SetUserData, NoChildren, etc.)
// 32. XMLAttribute direct value getters (IntValue, FloatValue etc.)


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    std::unique_ptr<tinyxml2::XMLDocument> doc(new tinyxml2::XMLDocument(true, fdp.ConsumeBool() ? tinyxml2::COLLAPSE_WHITESPACE : tinyxml2::PRESERVE_WHITESPACE));

    std::string true_str = fdp.ConsumeRandomLengthString(8);
    std::string false_str = fdp.ConsumeRandomLengthString(8);
    tinyxml2::XMLUtil::SetBoolSerialization(
        fdp.ConsumeBool() ? "true" : true_str.c_str(),
        fdp.ConsumeBool() ? "false" : false_str.c_str()
    );

    size_t parse_string_size = fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes() / 2);
    std::string xml_to_parse = fdp.ConsumeBytesAsString(parse_string_size);

    if (fdp.ConsumeBool()) {
        std::string char_refs;
        char_refs += "&#65;"; 
        if (fdp.ConsumeBool()) char_refs += "&#xA2;"; else char_refs += "&#162;";
        if (fdp.ConsumeBool()) char_refs += "&#x20AC;"; else char_refs += "&#8364;";
        if (fdp.ConsumeBool()) char_refs += "&#x1F600;"; else char_refs += "&#128512;";
        
        if (xml_to_parse.length() > 10) {
            size_t insert_pos = fdp.ConsumeIntegralInRange<size_t>(0, xml_to_parse.length() - 5);
            if (xml_to_parse.find("<") == std::string::npos || xml_to_parse.find(">") == std::string::npos) {
                 xml_to_parse = "<r>" + char_refs + fdp.ConsumeRandomLengthString(20) + "</r>";
            } else {
                 xml_to_parse.insert(insert_pos, char_refs);
            }
        } else {
            xml_to_parse = "<root>" + char_refs + "</root>";
        }
    }

    doc->Parse(xml_to_parse.c_str(), xml_to_parse.length());

    if (doc->Error()) {
        (void)doc->ErrorName(); 
        (void)doc->ErrorStr();  
    }
    doc->SetBOM(fdp.ConsumeBool());
    (void)doc->ToDocument(); 
    (void)doc->ShallowClone(nullptr); 
    // (void)doc->ShallowEqual(nullptr); // XMLDocument::ShallowEqual might also crash if it doesn't handle null.
                                     // For now, only addressing the reported XMLText crash.

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
        int num_operations = fdp.ConsumeIntegralInRange<int>(1, 30); 
        for (int i = 0; i < num_operations; ++i) {
            if (!current_element && fdp.ConsumeBool()) { 
                 current_element = doc->RootElement();
                 if (!current_element) { 
                    std::string temp_root_name = fdp.ConsumeRandomLengthString(10);
                    if(temp_root_name.empty()) temp_root_name = "fallbackRoot";
                    current_element = doc->NewElement(temp_root_name.c_str());
                    if(current_element) doc->InsertFirstChild(current_element);
                    else break; 
                 }
            }
            uint8_t op_type = fdp.ConsumeIntegralInRange<uint8_t>(0, 29); 

            bool needs_current_element = (op_type <= 18 || op_type == 20 || op_type == 22 || (op_type >= 23 && op_type <= 26) || op_type == 28 || op_type == 29);
            if (!current_element && needs_current_element) {
                current_element = doc->RootElement();
                if (!current_element) {
                    std::string fallback_root_name_str = fdp.ConsumeRandomLengthString(10);
                    if (fallback_root_name_str.empty()) fallback_root_name_str = "opFallbackRoot";
                    current_element = doc->NewElement(fallback_root_name_str.c_str());
                    if (current_element) doc->InsertFirstChild(current_element);
                    else break; 
                }
                if (!current_element) break; 
            }


            switch (op_type) {
                case 0: case 1: case 2: case 3: case 4: case 5: case 6: case 7: case 8: case 9: case 10: case 11: case 12: case 13: case 14: case 15: case 16: case 17: case 18:
                { 
                    if (op_type == 1 && current_element) { 
                        std::string attr_name_str = fdp.ConsumeRandomLengthString(32);
                        std::string attr_value_str = fdp.ConsumeRandomLengthString(64);
                        if (!attr_name_str.empty()) {
                            current_element->SetAttribute(attr_name_str.c_str(), attr_value_str.c_str());
                        }
                    } else if (op_type == 0 && current_element) { 
                         std::string child_name_str = fdp.ConsumeRandomLengthString(32);
                        if (child_name_str.empty()) child_name_str = "defaultChild";
                        tinyxml2::XMLElement *new_child = doc->NewElement(child_name_str.c_str());
                        if (new_child) {
                            current_element->InsertEndChild(new_child);
                            if (fdp.ConsumeBool()) current_element = new_child;
                        }
                    }
                    break;
                }
                case 19: { 
                    if (fdp.ConsumeBool()) { 
                        std::string temp_xml_content = fdp.ConsumeRandomLengthString(256);
                        const char* load_filename = "fuzz_load.xml";
                        FILE* fp_temp = fopen(load_filename, "wb");
                        if (fp_temp) {
                            fwrite(temp_xml_content.data(), 1, temp_xml_content.length(), fp_temp);
                            fclose(fp_temp);
                            tinyxml2::XMLDocument temp_load_doc; 
                            temp_load_doc.LoadFile(load_filename); 
                            remove(load_filename); 
                        }
                    } else { 
                        if (doc->RootElement()) { 
                            const char* save_filename = "fuzz_save.xml";
                            doc->SaveFile(save_filename, fdp.ConsumeBool()); 
                            remove(save_filename); 
                        }
                    }
                    break;
                }
                case 20: { 
                    if (current_element) {
                        if (fdp.ConsumeBool()) {
                            tinyxml2::XMLHandle handle(current_element);
                            handle.FirstChild();
                            handle.FirstChildElement(fdp.ConsumeBool() ? "a" : nullptr);
                            handle.LastChild();
                            handle.LastChildElement(fdp.ConsumeBool() ? "b" : nullptr);
                            if(fdp.ConsumeBool()) handle.PreviousSibling(); else handle.NextSibling();
                            if(fdp.ConsumeBool()) handle.PreviousSiblingElement(fdp.ConsumeBool() ? "c" : nullptr);
                            else handle.NextSiblingElement(fdp.ConsumeBool() ? "d" : nullptr);
                            (void)handle.ToNode(); (void)handle.ToElement(); (void)handle.ToText();
                            (void)handle.ToUnknown(); (void)handle.ToDeclaration(); 
                            if (handle.ToNode()) (void)handle.ToNode()->ToComment(); 
                        } else {
                            const tinyxml2::XMLNode* const_node = current_element; 
                            tinyxml2::XMLConstHandle const_handle(const_node);
                            const_handle.FirstChild();
                            const_handle.FirstChildElement(fdp.ConsumeBool() ? "e" : nullptr);
                            const_handle.LastChild();
                            const_handle.LastChildElement(fdp.ConsumeBool() ? "f" : nullptr);
                            if(fdp.ConsumeBool()) const_handle.PreviousSibling(); else const_handle.NextSibling();
                            if(fdp.ConsumeBool()) const_handle.PreviousSiblingElement(fdp.ConsumeBool() ? "g" : nullptr);
                            else const_handle.NextSiblingElement(fdp.ConsumeBool() ? "h" : nullptr);
                            (void)const_handle.ToNode(); (void)const_handle.ToElement(); (void)const_handle.ToText();
                            (void)const_handle.ToUnknown(); (void)const_handle.ToDeclaration(); 
                            if (const_handle.ToNode()) (void)const_handle.ToNode()->ToComment(); 
                        }
                    }
                    break;
                }
                case 21: { 
                    tinyxml2::XMLPrinter temp_printer(nullptr, fdp.ConsumeBool());
                    std::string printer_attr_name_str = fdp.ConsumeRandomLengthString(10);
                    const char* printer_attr_name = printer_attr_name_str.c_str();
                    if(printer_attr_name_str.empty()) printer_attr_name = "prAtt";

                    switch(fdp.ConsumeIntegralInRange<uint8_t>(0,6)) {
                        case 0: temp_printer.PushText(fdp.ConsumeIntegral<int>()); break;
                        case 1: temp_printer.PushText(fdp.ConsumeIntegral<unsigned int>()); break;
                        case 2: temp_printer.PushText(fdp.ConsumeBool()); break;
                        case 3: temp_printer.PushText(fdp.ConsumeFloatingPoint<double>()); break;
                        case 4: temp_printer.PushText(fdp.ConsumeFloatingPoint<float>()); break; 
                        case 5: temp_printer.PushText(fdp.ConsumeIntegral<int64_t>()); break;
                        case 6: temp_printer.PushText(fdp.ConsumeIntegral<uint64_t>()); break;
                    }
                     switch(fdp.ConsumeIntegralInRange<uint8_t>(0,5)) {
                        case 0: temp_printer.PushAttribute(printer_attr_name, fdp.ConsumeIntegral<int>()); break;
                        case 1: temp_printer.PushAttribute(printer_attr_name, fdp.ConsumeIntegral<unsigned int>()); break;
                        case 2: temp_printer.PushAttribute(printer_attr_name, fdp.ConsumeBool()); break;
                        case 3: temp_printer.PushAttribute(printer_attr_name, fdp.ConsumeFloatingPoint<double>()); break;
                        case 4: temp_printer.PushAttribute(printer_attr_name, fdp.ConsumeIntegral<int64_t>()); break;
                        case 5: temp_printer.PushAttribute(printer_attr_name, fdp.ConsumeIntegral<uint64_t>()); break;
                    }
                    if (fdp.ConsumeBool()) {
                        temp_printer.PushHeader(fdp.ConsumeBool(), fdp.ConsumeBool());
                    }
                    (void)temp_printer.CStr();
                    (void)temp_printer.CStrSize();
                    if (fdp.ConsumeBool()) temp_printer.ClearBuffer(fdp.ConsumeBool());
                    break;
                }
                case 22: { 
                    if (current_element) {
                        (void)current_element->GetDocument(); 
                        (void)current_element->NoChildren();  
                        (void)current_element->GetLineNum();  
                        if (fdp.ConsumeBool()) { 
                            current_element->SetUserData(reinterpret_cast<void*>(fdp.ConsumeIntegral<uintptr_t>()));
                        } else {
                            (void)current_element->GetUserData();
                        }
                        const tinyxml2::XMLAttribute* first_attr = current_element->FirstAttribute();
                        if (first_attr) {
                            (void)first_attr->IntValue(); (void)first_attr->Int64Value();
                            (void)first_attr->UnsignedValue(); (void)first_attr->Unsigned64Value();
                            (void)first_attr->BoolValue();
                            (void)first_attr->DoubleValue(); (void)first_attr->FloatValue();
                            (void)first_attr->GetLineNum(); 
                        }
                        const char* str_val_out = nullptr;
                        std::string q_attr_name_str = fdp.ConsumeRandomLengthString(10);
                        if(!q_attr_name_str.empty()) {
                           current_element->QueryStringAttribute(q_attr_name_str.c_str(), &str_val_out);
                        }
                    }
                    break;
                }
                case 23: { 
                    if (!current_element) continue;
                    (void)current_element->ChildElementCount(); 
                    std::string child_name_filter_str = fdp.ConsumeRandomLengthString(10);
                    (void)current_element->ChildElementCount(child_name_filter_str.c_str()); 
                    break;
                }
                case 24: { 
                    if (!current_element) continue;
                    std::string add_this_elem_name_str = fdp.ConsumeRandomLengthString(8);
                    const char* add_this_elem_name = add_this_elem_name_str.c_str();
                    if (add_this_elem_name_str.empty()) {
                        add_this_elem_name = "elemToAdd"; 
                    }
                    tinyxml2::XMLElement* addThis = doc->NewElement(add_this_elem_name);
                    if (!addThis) continue;

                    if (current_element->FirstChild()) {
                        tinyxml2::XMLNode* afterThis = nullptr;
                        if (fdp.ConsumeBool()) { 
                            afterThis = current_element->FirstChild();
                        } else if (current_element->LastChild()){ 
                            afterThis = current_element->LastChild();
                        } else {
                            afterThis = current_element->FirstChild(); 
                        }
                        
                        if (afterThis) {
                            tinyxml2::XMLNode* inserted_node = current_element->InsertAfterChild(afterThis, addThis); 
                            if (inserted_node && inserted_node->Parent() == current_element && fdp.ConsumeBool()) {
                                current_element->InsertAfterChild(inserted_node, inserted_node); 
                            }
                        } else { 
                             current_element->InsertFirstChild(addThis); 
                        }
                    } else {
                        current_element->InsertFirstChild(addThis);
                    }
                    break;
                }
                case 25: { 
                    if (!current_element) continue;
                    std::string attr_name_str = fdp.ConsumeRandomLengthString(10);
                    if (attr_name_str.empty()) attr_name_str = "a";
                    const char* attr_name = attr_name_str.c_str();

                    if (fdp.ConsumeBool()) { int v = fdp.ConsumeIntegral<int>(); current_element->SetAttribute(attr_name, v); (void)current_element->IntAttribute(attr_name, v); }
                    if (fdp.ConsumeBool()) { unsigned v = fdp.ConsumeIntegral<unsigned>(); current_element->SetAttribute(attr_name, v); (void)current_element->UnsignedAttribute(attr_name, v); }
                    if (fdp.ConsumeBool()) { int64_t v = fdp.ConsumeIntegral<int64_t>(); current_element->SetAttribute(attr_name, v); (void)current_element->Int64Attribute(attr_name, v); }
                    if (fdp.ConsumeBool()) { uint64_t v = fdp.ConsumeIntegral<uint64_t>(); current_element->SetAttribute(attr_name, v); (void)current_element->Unsigned64Attribute(attr_name, v); }
                    if (fdp.ConsumeBool()) { bool v = fdp.ConsumeBool(); current_element->SetAttribute(attr_name, v); (void)current_element->BoolAttribute(attr_name, v); }
                    if (fdp.ConsumeBool()) { double v = fdp.ConsumeFloatingPoint<double>(); current_element->SetAttribute(attr_name, v); (void)current_element->DoubleAttribute(attr_name, v); }
                    if (fdp.ConsumeBool()) { float v = fdp.ConsumeFloatingPoint<float>(); current_element->SetAttribute(attr_name, v); (void)current_element->FloatAttribute(attr_name, v); }
                    break;
                }
                case 26: { 
                    if (!current_element) continue;
                    std::string text_s = fdp.ConsumeRandomLengthString(20);
                    current_element->SetText(text_s.c_str()); 
                    if (fdp.ConsumeBool()) { 
                        std::string text_s_overwrite = fdp.ConsumeRandomLengthString(10);
                        current_element->SetText(text_s_overwrite.c_str());
                    }
                    (void)current_element->GetText(); 

                    if (fdp.ConsumeBool()) current_element->SetText(fdp.ConsumeIntegral<int>());
                    if (fdp.ConsumeBool()) current_element->SetText(fdp.ConsumeIntegral<unsigned int>());
                    if (fdp.ConsumeBool()) current_element->SetText(fdp.ConsumeIntegral<int64_t>());
                    if (fdp.ConsumeBool()) current_element->SetText(fdp.ConsumeIntegral<uint64_t>());
                    if (fdp.ConsumeBool()) current_element->SetText(fdp.ConsumeBool());
                    if (fdp.ConsumeBool()) current_element->SetText(fdp.ConsumeFloatingPoint<double>());
                    if (fdp.ConsumeBool()) current_element->SetText(fdp.ConsumeFloatingPoint<float>());
                    
                    (void)current_element->IntText(fdp.ConsumeIntegral<int>());
                    (void)current_element->UnsignedText(fdp.ConsumeIntegral<unsigned int>());
                    (void)current_element->Int64Text(fdp.ConsumeIntegral<int64_t>());
                    (void)current_element->Unsigned64Text(fdp.ConsumeIntegral<uint64_t>());
                    (void)current_element->BoolText(fdp.ConsumeBool());
                    (void)current_element->DoubleText(fdp.ConsumeFloatingPoint<double>());
                    (void)current_element->FloatText(fdp.ConsumeFloatingPoint<float>());
                    break;
                }
                case 27: { 
                    std::unique_ptr<tinyxml2::XMLDocument> target_doc_for_deepcopy(new tinyxml2::XMLDocument());
                    doc->DeepCopy(target_doc_for_deepcopy.get());

                    std::string str_content_data = fdp.ConsumeRandomLengthString(10);
                    const char* str_content = str_content_data.c_str();

                    tinyxml2::XMLText* text1 = doc->NewText(str_content);
                    if (text1) {
                        tinyxml2::XMLNode* cloned_text = text1->ShallowClone(doc.get()); 
                        if (cloned_text) (void)text1->ShallowEqual(cloned_text); 
                        // (void)text1->ShallowEqual(nullptr); // This call caused SEGV in XMLText::ShallowEqual.
                        std::string temp_comment_text_str = fdp.ConsumeRandomLengthString(10);
                        const char* temp_comment_text = temp_comment_text_str.c_str();
                        if (temp_comment_text_str.empty()) temp_comment_text = "diff_comment";
                        tinyxml2::XMLComment* temp_comment = doc->NewComment(temp_comment_text);
                        if (temp_comment) (void)text1->ShallowEqual(temp_comment); 
                    }

                    tinyxml2::XMLComment* comment1 = doc->NewComment(str_content);
                    if (comment1) {
                        tinyxml2::XMLNode* cloned_comment = comment1->ShallowClone(doc.get()); 
                        if (cloned_comment) (void)comment1->ShallowEqual(cloned_comment); 
                    }

                    tinyxml2::XMLDeclaration* decl1 = doc->NewDeclaration(str_content);
                    if (decl1) {
                        tinyxml2::XMLNode* cloned_decl = decl1->ShallowClone(doc.get()); 
                        if (cloned_decl) (void)decl1->ShallowEqual(cloned_decl); 
                    }

                    tinyxml2::XMLUnknown* unknown1 = doc->NewUnknown(str_content);
                    if (unknown1) {
                        tinyxml2::XMLNode* cloned_unknown = unknown1->ShallowClone(doc.get()); 
                        if (cloned_unknown) (void)unknown1->ShallowEqual(cloned_unknown); 
                    }
                    
                    if (current_element) {
                        tinyxml2::XMLElement* elem_to_clone = current_element;
                        if (fdp.ConsumeBool() && doc->RootElement()) elem_to_clone = doc->RootElement();

                        if (elem_to_clone) {
                            tinyxml2::XMLElement* cloned_element = static_cast<tinyxml2::XMLElement*>(elem_to_clone->ShallowClone(doc.get())); 
                            if (cloned_element) {
                                (void)elem_to_clone->ShallowEqual(cloned_element); 
                                if (fdp.ConsumeBool()) { 
                                     std::string attr_name_for_unequal_str = fdp.ConsumeRandomLengthString(5);
                                     const char* attr_name_for_unequal = attr_name_for_unequal_str.c_str();
                                     if (attr_name_for_unequal_str.empty()) {
                                         attr_name_for_unequal = "defaultAttrEq";
                                     }
                                     cloned_element->SetAttribute(attr_name_for_unequal, fdp.ConsumeIntegral<int>());
                                     (void)elem_to_clone->ShallowEqual(cloned_element); 
                                }
                            }
                            // (void)elem_to_clone->ShallowEqual(nullptr); // Proactively commenting out as XMLElement::ShallowEqual might also not handle null.
                            if (text1) (void)elem_to_clone->ShallowEqual(text1); 
                        }
                    }
                    break;
                }
                case 28: { 
                    if (!current_element) continue;
                    std::string attr_to_delete_name_str = fdp.ConsumeRandomLengthString(10);
                    const char* attr_to_delete_name = attr_to_delete_name_str.c_str();
                    if (attr_to_delete_name_str.empty()) attr_to_delete_name = "delAttr";
                    
                    if (fdp.ConsumeBool()) {
                        current_element->SetAttribute(attr_to_delete_name, fdp.ConsumeIntegral<int>());
                    }
                    current_element->DeleteAttribute(attr_to_delete_name); 
                    break;
                }
                case 29: { 
                    if (!current_element) continue;
                    std::string name_or_text_str = fdp.ConsumeRandomLengthString(15);
                    const char* name_or_text = name_or_text_str.c_str();
                    if (name_or_text_str.empty()) name_or_text = "defaultContent";

                    if (fdp.ConsumeBool()) (void)current_element->InsertNewChildElement(name_or_text);
                    if (fdp.ConsumeBool()) (void)current_element->InsertNewComment(name_or_text);
                    if (fdp.ConsumeBool()) (void)current_element->InsertNewText(name_or_text);
                    if (fdp.ConsumeBool()) (void)current_element->InsertNewDeclaration(name_or_text);
                    if (fdp.ConsumeBool()) (void)current_element->InsertNewUnknown(name_or_text);
                    break;
                }

            } 
        } 
    } 

    tinyxml2::XMLPrinter printer(nullptr, fdp.ConsumeBool()); 
    doc->Print(&printer);
    
    return 0;
}