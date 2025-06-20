#include "/src/tinyxml2/tinyxml2.h" // Project-relative path as per requirement
#include <fuzzer/FuzzedDataProvider.h>

#include <string>
#include <vector>
#include <cstdio>   // For FILE*, fopen, fclose, fwrite, remove
#include <cstring>  // For memset
#include <cctype>   // Not used in final version, but often useful

// Use fixed temporary filenames to avoid issues with tmpnam or platform differences
const char* FUZZ_LOAD_FILENAME = "fuzz_load_temp.xml";
const char* FUZZ_SAVE_FILENAME = "fuzz_save_temp.xml";

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    tinyxml2::XMLDocument* doc = nullptr; // Must be deleted
    tinyxml2::XMLPrinter* printer = nullptr; // Must be deleted

    // Coverage: tinyxml2::StrPair::GetStr() for NEEDS_WHITESPACE_COLLAPSING
    // Modify XMLDocument constructor to sometimes use COLLAPSE_WHITESPACE or PEDANTIC_WHITESPACE
    int whitespace_choice = fdp.ConsumeIntegralInRange<int>(0, 2);
    tinyxml2::Whitespace ws_mode = tinyxml2::PRESERVE_WHITESPACE;
    if (whitespace_choice == 1) {
        ws_mode = tinyxml2::COLLAPSE_WHITESPACE;
    } else if (whitespace_choice == 2) {
        // Coverage for XMLDocument::Identify PEDANTIC_WHITESPACE path (lines 757-760 in tinyxml2.cpp)
        ws_mode = tinyxml2::PEDANTIC_WHITESPACE;
    }

    // Coverage for XMLPrinter::PrintString else branch (line 2714 in tinyxml2.cpp) by controlling doc->_processEntities
    bool process_entities_for_doc = fdp.ConsumeBool();
    doc = new tinyxml2::XMLDocument(process_entities_for_doc, ws_mode);
    // Memory: doc is deleted at the end.

    // --- Stage 1: Target API: tinyxml2::XMLDocument::LoadFile(FILE *) ---
    if (fdp.ConsumeBool()) {
        std::string xml_to_load_content = fdp.ConsumeRandomLengthString(1024);
        std::string xml_to_load_full;

        // Coverage for XMLPrinter::VisitEnter(XMLDocument) for HasBOM() path (line 2964 in tinyxml2.cpp)
        // and XMLUtil::ReadBOM (line 409 in tinyxml2.cpp) by sometimes adding a BOM.
        if (fdp.ConsumeBool()) {
            xml_to_load_full = "\xEF\xBB\xBF"; // UTF-8 BOM
        }
        xml_to_load_full += xml_to_load_content;

        FILE* fp_load = fopen(FUZZ_LOAD_FILENAME, "wb");
        if (fp_load) {
            fwrite(xml_to_load_full.data(), 1, xml_to_load_full.size(), fp_load);
            fclose(fp_load);

            fp_load = fopen(FUZZ_LOAD_FILENAME, "rb");
            if (fp_load) {
                doc->LoadFile(fp_load); // This will call Parse(), which calls ReadBOM()
                fclose(fp_load);       // doc->_writeBOM should be set if BOM was present
            }
            std::remove(FUZZ_LOAD_FILENAME);
        }
    }

    // Coverage for XMLDocument::Identify PEDANTIC_WHITESPACE path (lines 757-760 in tinyxml2.cpp)
    // This requires parsing a string with leading whitespace before a closing tag, when the document is in PEDANTIC_WHITESPACE mode.
    if (fdp.ConsumeBool() && doc->WhitespaceMode() == tinyxml2::PEDANTIC_WHITESPACE) {
        // Ensure the document is empty or this parse might be affected by prior state or cause errors unrelated to this test.
        if (doc->NoChildren()) {
             std::string pedantic_test_str = "   </close_unexpected>"; // Whitespace before a closing tag
             doc->Parse(pedantic_test_str.c_str()); // This parse attempt targets the specific path in Identify
        }
    }


    if (fdp.ConsumeBool() && doc->NoChildren()) {
        if (fdp.ConsumeBool()) { // Chance to test specific entities for GetCharacterRef coverage
            std::string entity_str;
            // Coverage for XMLUtil::GetCharacterRef hex paths (lines 490-495, 519-524)
            // Coverage for XMLUtil::GetCharacterRef line 551 (return 0 if ConvertUTF32ToUTF8 sets length to 0)
            int entity_type = fdp.ConsumeIntegralInRange(0, 5);
            switch (entity_type) {
                case 0: entity_str = "<doc>&#x41;</doc>"; break;           // Valid hex 'A'
                case 1: entity_str = "<doc>&#xabcdef;</doc>"; break;       // Valid hex lower
                case 2: entity_str = "<doc>&#x10FFFF;</doc>"; break;       // Max valid UCS
                // Modified case 3 to target GetCharacterRef line 551: ucs >= 0x200000 causes ConvertUTF32ToUTF8 to set length = 0.
                case 3: entity_str = "<doc>&#x200000;</doc>"; break;      // Invalid UCS (>=0x200000) -> ConvertUTF32ToUTF8 len 0 -> GetCharacterRef line 551
                case 4: entity_str = "<doc>&#xInvalid;</doc>"; break;      // Invalid hex digits in ref
                case 5: entity_str = "<doc>&custom;</doc>"; break;         // Test non-standard entity if not processed
            }
            doc->Parse(entity_str.c_str()); // Use Parse overload that calculates length
        } else {
            std::string direct_parse_xml = fdp.ConsumeRandomLengthString(512);
            if (!direct_parse_xml.empty()) {
                if (fdp.ConsumeBool()) {
                    doc->Parse(direct_parse_xml.c_str(), direct_parse_xml.length());
                } else {
                    // Coverage for XMLDocument::Parse using default length (nBytes = -1) (lines 2456-2457 in tinyxml2.cpp)
                    doc->Parse(direct_parse_xml.c_str());
                }
            }
        }
    }

    // --- Stage 1.5: Node Creation for Destructor Coverage ---
    if (doc && fdp.ConsumeBool()) { // Only if doc exists
        if (fdp.ConsumeBool()) {
            (void)doc->NewText(fdp.ConsumeRandomLengthString(20).c_str());
        }
        if (fdp.ConsumeBool()) {
            (void)doc->NewComment(fdp.ConsumeRandomLengthString(20).c_str());
        }
        if (fdp.ConsumeBool()) {
            (void)doc->NewDeclaration(fdp.ConsumeRandomLengthString(20).c_str());
        }
        if (fdp.ConsumeBool()) {
            (void)doc->NewUnknown(fdp.ConsumeRandomLengthString(20).c_str());
        }
    }


    // --- Stage 2: Target API: (indirectly) void tinyxml2::XMLPrinter::Print(const char *, ...) ---
    if (fdp.ConsumeBool()) {
        printer = new tinyxml2::XMLPrinter(nullptr, fdp.ConsumeBool() /* compact mode */);
        // Memory: printer is deleted at the end.

        // Test XMLPrinter's programmatic construction of elements and attributes
        if (fdp.ConsumeBool()) {
            printer->OpenElement("TestPrint", fdp.ConsumeBool());
            printer->PushAttribute("formatStr", "string_val");
            printer->PushAttribute("valueInt", fdp.ConsumeIntegral<int>());
            printer->CloseElement(fdp.ConsumeBool());
        }

        if (doc && fdp.ConsumeBool()) {
            if (fdp.ConsumeBool()) {
                tinyxml2::XMLElement* root_elem_for_attr = doc->RootElement();
                if (!root_elem_for_attr && doc->NoChildren() && fdp.ConsumeBool()) {
                    std::string r_name = fdp.ConsumeRandomLengthString(10);
                    if(r_name.empty()) r_name = "RootForAttr";
                    root_elem_for_attr = doc->NewElement(r_name.c_str());
                    doc->InsertFirstChild(root_elem_for_attr);
                }
                if (root_elem_for_attr) {
                    std::string attr_n = fdp.ConsumeRandomLengthString(10);
                    if(attr_n.empty()) attr_n = "fuzzPrintAttr";
                    if (!attr_n.empty()) {
                        root_elem_for_attr->SetAttribute(attr_n.c_str(), fdp.ConsumeRandomLengthString(10).c_str());
                    }
                }
            }
            doc->Accept(printer);
        }
        else {
            int operation_choice = fdp.ConsumeIntegralInRange<int>(0, 6);
            std::string text_arg = fdp.ConsumeRandomLengthString(50);
            std::string name_arg = fdp.ConsumeRandomLengthString(20);
            if (name_arg.empty()) name_arg = "fuzzDefaultName";

            switch (operation_choice) {
                case 0:
                    printer->PushText(text_arg.c_str(), fdp.ConsumeBool() /* cdata */);
                    break;
                case 1:
                    printer->PushText(fdp.ConsumeIntegral<int>());
                    break;
                case 2:
                    printer->PushText(fdp.ConsumeFloatingPoint<double>());
                    break;
                case 3:
                    printer->OpenElement(name_arg.c_str(), fdp.ConsumeBool());
                    {
                        std::string attr_name = fdp.ConsumeRandomLengthString(15);
                        if(attr_name.empty()) attr_name = "fuzzAttr";
                        if (!attr_name.empty()) {
                           if (fdp.ConsumeBool()) {
                                std::string attr_val_str = fdp.ConsumeRandomLengthString(20);
                                printer->PushAttribute(attr_name.c_str(), attr_val_str.c_str());
                            } else {
                                printer->PushAttribute(attr_name.c_str(), fdp.ConsumeIntegral<int>());
                            }
                        }
                    }
                    printer->CloseElement(fdp.ConsumeBool());
                    break;
                case 4:
                    printer->PushComment(text_arg.c_str());
                    break;
                case 5:
                    printer->PushDeclaration(text_arg.c_str());
                    break;
                case 6:
                    printer->PushUnknown(text_arg.c_str());
                    break;
            }
        }
        (void)printer->CStr();
    }


    // --- Stage 3: Target API: tinyxml2::XMLDocument::SaveFile(const char *, bool) ---
    if (doc && fdp.ConsumeBool()) {
        bool compact_mode_save = fdp.ConsumeBool();
        doc->SaveFile(FUZZ_SAVE_FILENAME, compact_mode_save);
        std::remove(FUZZ_SAVE_FILENAME);
    }
    // Coverage for XMLDocument::Print(nullptr) (lines 2483-2486 in tinyxml2.cpp)
    if (doc && fdp.ConsumeBool()) {
        doc->Print(nullptr); // Prints to stdout, covering the else branch in XMLDocument::Print
    }
    // Coverage for XMLDocument::SaveFile(nullptr, bool) path (line 2420 in tinyxml2.cpp)
    if (doc && fdp.ConsumeBool()) {
        // Explicitly cast nullptr to const char* to resolve ambiguity
        doc->SaveFile(static_cast<const char*>(nullptr), fdp.ConsumeBool()); // Pass nullptr for filename
    }


    // --- Stage 3.5: XMLNode::Unlink coverage for non-first child ---
    if (doc && fdp.ConsumeBool()) {
        tinyxml2::XMLElement* parent_for_unlink = doc->RootElement();
        if ((!parent_for_unlink || fdp.ConsumeBool()) && doc->NoChildren()) {
            std::string p_name = fdp.ConsumeRandomLengthString(10);
            if(p_name.empty()) p_name = "UnlinkParent";
            parent_for_unlink = doc->NewElement(p_name.c_str());
            doc->InsertFirstChild(parent_for_unlink);
        }

        if (parent_for_unlink && parent_for_unlink->NoChildren() && fdp.ConsumeBool()) {
            std::string c1_name_str = fdp.ConsumeRandomLengthString(10);
            if (c1_name_str.empty()) c1_name_str = "child1ToUnlink";
            tinyxml2::XMLElement* child1 = doc->NewElement(c1_name_str.c_str());

            std::string c2_name_str = fdp.ConsumeRandomLengthString(10);
            if (c2_name_str.empty()) c2_name_str = "child2ToUnlink";
            tinyxml2::XMLElement* child2 = doc->NewElement(c2_name_str.c_str());

            parent_for_unlink->InsertEndChild(child1);
            parent_for_unlink->InsertEndChild(child2);

            parent_for_unlink->DeleteChild(child2); // child2 is managed by parent_for_unlink, then deleted.
        }
    }


    // --- Stage 4: Target API: XMLElement::DeleteAttribute, XMLElement::Attribute ---
    if (doc && fdp.ConsumeBool()) {
        tinyxml2::XMLElement* target_element = doc->RootElement();

        if (!target_element && fdp.ConsumeBool()) {
            std::string root_name = fdp.ConsumeRandomLengthString(10);
            if (root_name.empty()) root_name = "FuzzRootForAttrs";
            target_element = doc->NewElement(root_name.c_str());
            doc->InsertFirstChild(target_element);
        }

        if (target_element) {
            std::string attr_name1 = fdp.ConsumeRandomLengthString(15);
            if (attr_name1.empty()) attr_name1 = "fuzzAttrOne";
            std::string attr_val1 = fdp.ConsumeRandomLengthString(20);

            std::string attr_name2 = fdp.ConsumeRandomLengthString(15);
            if (attr_name2.empty()) attr_name2 = "fuzzAttrTwo";
            if (attr_name1 == attr_name2 && !attr_name1.empty()) attr_name2 += "_2";
            else if (attr_name1 == attr_name2 && attr_name1.empty()) attr_name2 = "fuzzAttrTwo_def";

            std::string attr_val2 = fdp.ConsumeRandomLengthString(20);


            if (!attr_name1.empty()) target_element->SetAttribute(attr_name1.c_str(), attr_val1.c_str());
            if (!attr_name2.empty()) target_element->SetAttribute(attr_name2.c_str(), attr_val2.c_str());

            if (fdp.ConsumeBool() && !attr_name2.empty()) {
                target_element->DeleteAttribute(attr_name2.c_str());
            } else if (!attr_name1.empty()) {
                target_element->DeleteAttribute(attr_name1.c_str());
            }

            if (!attr_name1.empty()) {
                target_element->SetAttribute(attr_name1.c_str(), "actual_value");
                target_element->Attribute(attr_name1.c_str(), "a_value_that_does_not_match");
            }

            std::string attr_name_to_delete_orig = fdp.ConsumeRandomLengthString(15);
            if (attr_name_to_delete_orig.empty()) {
                const tinyxml2::XMLAttribute* first_attr = target_element->FirstAttribute();
                if (first_attr && first_attr->Name() && fdp.ConsumeBool()) {
                     attr_name_to_delete_orig = first_attr->Name();
                } else {
                     attr_name_to_delete_orig = "fuzz_attr_default_orig";
                }
            }

            if (fdp.ConsumeBool() && !target_element->FindAttribute(attr_name_to_delete_orig.c_str()) && !attr_name_to_delete_orig.empty()) {
                std::string attr_value = fdp.ConsumeRandomLengthString(20);
                target_element->SetAttribute(attr_name_to_delete_orig.c_str(), attr_value.c_str());
            }

            if (!attr_name_to_delete_orig.empty()) {
                target_element->DeleteAttribute(attr_name_to_delete_orig.c_str());
            }
        }
    }

    // --- Stage 5: Target API: void tinyxml2::XMLUtil::ConvertUTF32ToUTF8(unsigned long, char *, int *) ---
    if (fdp.ConsumeBool()) {
        unsigned long utf32_char;
        if (fdp.ConsumeBool()) {
            utf32_char = fdp.ConsumeIntegralInRange<unsigned long>(0x200000, 0x400000);
        } else {
            do {
                utf32_char = fdp.ConsumeIntegralInRange<unsigned long>(0, 0x10FFFF);
            } while (utf32_char >= 0xD800 && utf32_char <= 0xDFFF);
        }

        char utf8_buffer[5];
        int output_length = 0;
        memset(utf8_buffer, 0, sizeof(utf8_buffer));
        tinyxml2::XMLUtil::ConvertUTF32ToUTF8(utf32_char, utf8_buffer, &output_length);
    }

    // --- Stage 6: Target XML_ELEMENT_DEPTH_EXCEEDED (lines 2570-2571 in tinyxml2.cpp) ---
    if (doc && fdp.ConsumeBool()) {
        std::string deep_xml = "";
        // TINYXML2_MAX_ELEMENT_DEPTH is 100 by default in tinyxml2.h.
        // Create slightly more to be sure, e.g., 102 levels.
        const int depth_to_trigger = 102;
        for (int i = 0; i < depth_to_trigger; ++i) {
            deep_xml += "<d>"; // Use a short name for efficiency
        }
        for (int i = 0; i < depth_to_trigger; ++i) {
            deep_xml += "</d>";
        }

        // It's important to clear the document before parsing a potentially problematic string
        // that might lead to errors or large memory use, to avoid compounding issues.
        doc->Clear();
        doc->Parse(deep_xml.c_str()); // This should trigger XML_ELEMENT_DEPTH_EXCEEDED
                                      // Memory for deep_xml is managed by std::string.
                                      // Memory for parsed nodes is managed by doc.
    }

    // --- Stage 7: Additional Coverage Targets ---

    // Coverage for StrPair::TransferTo self-assignment (line 161 in tinyxml2.cpp)
    if (fdp.ConsumeBool()) {
        tinyxml2::StrPair sp; // Stack allocated, memory safe.
        // Call TransferTo on itself. Asserts in TransferTo for other->_flags etc.
        // should pass as 'sp' is default-initialized (flags/start/end are 0).
        sp.TransferTo(&sp);
    }

    // Coverage for XMLNode::InsertChildPreamble reparenting path (lines 1209-1210 in tinyxml2.cpp)
    if (doc && fdp.ConsumeBool()) {
        tinyxml2::XMLElement* p1 = doc->NewElement("p1_reparent");
        tinyxml2::XMLElement* p2 = doc->NewElement("p2_reparent");
        tinyxml2::XMLElement* c1_reparent = doc->NewElement("c1_reparent");

        if (p1 && p2 && c1_reparent) { // Nodes are initially unlinked, managed by doc.
            doc->InsertEndChild(p1); // Link p1 to doc.
            doc->InsertEndChild(p2); // Link p2 to doc.

            p1->InsertEndChild(c1_reparent); // c1_reparent becomes child of p1.

            // Try to insert c1_reparent into p2. This triggers reparenting.
            // c1_reparent->_parent is p1, so p1->Unlink(c1_reparent) is called.
            p2->InsertEndChild(c1_reparent); // c1_reparent is now child of p2.
            // All nodes (p1, p2, c1_reparent) are managed within 'doc' tree. Memory safe.
        }
    }

    // Coverage for XMLNode::ToElementWithName matching name (line 1226 in tinyxml2.cpp)
    if (doc && fdp.ConsumeBool()) {
        std::string parent_name = fdp.ConsumeRandomLengthString(10);
        if (parent_name.empty()) parent_name = "ParentForToElement";
        tinyxml2::XMLElement* parent = doc->NewElement(parent_name.c_str());

        if (parent) { // Initially unlinked, managed by doc.
            doc->InsertFirstChild(parent); // Link parent to doc.
            std::string child_name_str = fdp.ConsumeRandomLengthString(10);
            if (child_name_str.empty()) child_name_str = "TargetChildName";
            tinyxml2::XMLElement* child = doc->NewElement(child_name_str.c_str());

            if (child) { // Initially unlinked, managed by doc.
                parent->InsertEndChild(child); // Link child to parent.
                // Call FirstChildElement with the actual name of the child.
                // This should make node->ToElementWithName("TargetChildName") be called
                // where node is 'child' and name is "TargetChildName", hitting line 1226.
                parent->FirstChildElement(child_name_str.c_str());
                // Nodes are managed within 'doc' tree. Memory safe.
            }
        }
    }

    // Coverage for XMLNode::InsertEndChild and XMLNode::InsertFirstChild with node from different document
    // (lines 929-931 for InsertEndChild, lines 959-961 for InsertFirstChild in tinyxml2.cpp)
    if (doc && fdp.ConsumeBool()) {
        tinyxml2::XMLDocument doc2; // RAII for doc2, memory safe.
        std::string elem_name_other_doc = fdp.ConsumeRandomLengthString(10);
        if (elem_name_other_doc.empty()) elem_name_other_doc = "elemFromOtherDoc";
        tinyxml2::XMLElement* elemFromDoc2 = doc2.NewElement(elem_name_other_doc.c_str());

        if (elemFromDoc2) { // elemFromDoc2 is owned by doc2.
            if (fdp.ConsumeBool()) {
                doc->InsertEndChild(elemFromDoc2); // Attempt to insert, error case.
            } else {
                doc->InsertFirstChild(elemFromDoc2); // Attempt to insert, error case.
            }
            // elemFromDoc2 is NOT adopted by 'doc'. It remains owned by 'doc2' and is cleaned up
            // when 'doc2' goes out of scope. Memory safe.
        }
    }


    // --- Cleanup ---
    delete printer;
    delete doc;

    return 0;
}