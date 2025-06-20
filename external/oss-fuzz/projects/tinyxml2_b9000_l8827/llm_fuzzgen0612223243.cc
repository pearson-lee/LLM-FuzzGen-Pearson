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
    // Modify XMLDocument constructor to sometimes use COLLAPSE_WHITESPACE
    bool collapse_whitespace = fdp.ConsumeBool();
    doc = new tinyxml2::XMLDocument(true, collapse_whitespace ? tinyxml2::COLLAPSE_WHITESPACE : tinyxml2::PRESERVE_WHITESPACE);
    // Memory: doc is deleted at the end.

    // --- Stage 1: Target API: tinyxml2::XMLDocument::LoadFile(FILE *) ---
    if (fdp.ConsumeBool()) {
        std::string xml_to_load = fdp.ConsumeRandomLengthString(1024);

        FILE* fp_load = fopen(FUZZ_LOAD_FILENAME, "wb");
        if (fp_load) {
            fwrite(xml_to_load.data(), 1, xml_to_load.size(), fp_load);
            fclose(fp_load);

            fp_load = fopen(FUZZ_LOAD_FILENAME, "rb");
            if (fp_load) {
                doc->LoadFile(fp_load);
                fclose(fp_load);
            }
            std::remove(FUZZ_LOAD_FILENAME);
        }
    }

    if (fdp.ConsumeBool() && doc->NoChildren()) {
        std::string direct_parse_xml = fdp.ConsumeRandomLengthString(512);
        if (!direct_parse_xml.empty()) {
            doc->Parse(direct_parse_xml.c_str(), direct_parse_xml.length());
        }
    }

    // --- Stage 1.5: Node Creation for Destructor Coverage ---
    if (doc && fdp.ConsumeBool()) { // Only if doc exists
        // Coverage: XMLText::~XMLText()
        // NewText creates an unlinked node. XMLDocument's destructor will clean it up from _unlinked.
        if (fdp.ConsumeBool()) {
            (void)doc->NewText(fdp.ConsumeRandomLengthString(20).c_str());
            // Memory: Node is in _unlinked list if not parented, cleaned by ~XMLDocument.
        }
        // Coverage: XMLComment::~XMLComment()
        // NewComment creates an unlinked node. XMLDocument's destructor will clean it up from _unlinked.
        if (fdp.ConsumeBool()) {
            (void)doc->NewComment(fdp.ConsumeRandomLengthString(20).c_str());
            // Memory: Node is in _unlinked list if not parented, cleaned by ~XMLDocument.
        }
        // Coverage: XMLDeclaration::~XMLDeclaration()
        // NewDeclaration creates an unlinked node. XMLDocument's destructor will clean it up from _unlinked.
        if (fdp.ConsumeBool()) {
            (void)doc->NewDeclaration(fdp.ConsumeRandomLengthString(20).c_str());
            // Memory: Node is in _unlinked list, cleaned by ~XMLDocument.
        }
        // Coverage: XMLUnknown::~XMLUnknown()
        // NewUnknown creates an unlinked node. XMLDocument's destructor will clean it up from _unlinked.
        if (fdp.ConsumeBool()) {
            (void)doc->NewUnknown(fdp.ConsumeRandomLengthString(20).c_str());
            // Memory: Node is in _unlinked list, cleaned by ~XMLDocument.
        }
    }


    // --- Stage 2: Target API: (indirectly) void tinyxml2::XMLPrinter::Print(const char *, ...) ---
    if (fdp.ConsumeBool()) {
        printer = new tinyxml2::XMLPrinter(nullptr, fdp.ConsumeBool() /* compact mode */);
        // Memory: printer is deleted at the end.

        if (doc && fdp.ConsumeBool()) {
            // Coverage: XMLPrinter::VisitEnter for elements with attributes
            if (fdp.ConsumeBool()) {
                tinyxml2::XMLElement* root_elem_for_attr = doc->RootElement();
                if (!root_elem_for_attr && doc->NoChildren() && fdp.ConsumeBool()) {
                    std::string r_name = fdp.ConsumeRandomLengthString(10);
                    if(r_name.empty()) r_name = "RootForAttr";
                    root_elem_for_attr = doc->NewElement(r_name.c_str());
                    doc->InsertFirstChild(root_elem_for_attr);
                     // Memory: root_elem_for_attr owned by doc.
                }
                if (root_elem_for_attr) {
                    std::string attr_n = fdp.ConsumeRandomLengthString(10);
                    if(attr_n.empty()) attr_n = "fuzzPrintAttr";
                    // Ensure attribute name is valid if not empty
                    if (!attr_n.empty()) {
                        root_elem_for_attr->SetAttribute(attr_n.c_str(), fdp.ConsumeRandomLengthString(10).c_str());
                    }
                    // Memory: Attribute is owned by element/document.
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
                    printer->OpenElement(name_arg.c_str());
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
                    printer->CloseElement();
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

    // --- Stage 3.5: XMLNode::Unlink coverage for non-first child ---
    if (doc && fdp.ConsumeBool()) {
        tinyxml2::XMLElement* parent_for_unlink = doc->RootElement();
        // Create a new root if current one is null or if we want to test on a fresh parent sometimes
        if ((!parent_for_unlink || fdp.ConsumeBool()) && doc->NoChildren()) { // Prioritize NoChildren to avoid messing up existing complex docs too much
            std::string p_name = fdp.ConsumeRandomLengthString(10);
            if(p_name.empty()) p_name = "UnlinkParent";
            parent_for_unlink = doc->NewElement(p_name.c_str());
            doc->InsertFirstChild(parent_for_unlink);
            // Memory: parent_for_unlink is owned by doc.
        }

        if (parent_for_unlink && parent_for_unlink->NoChildren() && fdp.ConsumeBool()) {
            std::string c1_name_str = fdp.ConsumeRandomLengthString(10);
            if (c1_name_str.empty()) c1_name_str = "child1ToUnlink";
            tinyxml2::XMLElement* child1 = doc->NewElement(c1_name_str.c_str());

            std::string c2_name_str = fdp.ConsumeRandomLengthString(10);
            if (c2_name_str.empty()) c2_name_str = "child2ToUnlink";
            tinyxml2::XMLElement* child2 = doc->NewElement(c2_name_str.c_str());
            
            parent_for_unlink->InsertEndChild(child1); // child1 is owned by parent_for_unlink
            parent_for_unlink->InsertEndChild(child2); // child2 is owned by parent_for_unlink

            // Deleting child2 will call Unlink(child2), where child2->_prev (child1) is non-null.
            // This covers line 901 in XMLNode::Unlink.
            parent_for_unlink->DeleteChild(child2);
            // Memory: child1 remains, child2 is deleted. All managed by doc/parent.
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
            // Memory: target_element is owned by doc.
        }
        
        if (target_element) {
            std::string attr_name1 = fdp.ConsumeRandomLengthString(15);
            if (attr_name1.empty()) attr_name1 = "fuzzAttrOne";
            std::string attr_val1 = fdp.ConsumeRandomLengthString(20);

            std::string attr_name2 = fdp.ConsumeRandomLengthString(15);
            if (attr_name2.empty()) attr_name2 = "fuzzAttrTwo";
            if (attr_name1 == attr_name2 && !attr_name1.empty()) attr_name2 += "_2"; // Ensure different names if not empty
            else if (attr_name1 == attr_name2 && attr_name1.empty()) attr_name2 = "fuzzAttrTwo_def";
            
            std::string attr_val2 = fdp.ConsumeRandomLengthString(20); // FIX: Added declaration for attr_val2


            // Coverage for XMLElement::DeleteAttribute (deleting a non-first attribute, line 1946)
            if (!attr_name1.empty()) target_element->SetAttribute(attr_name1.c_str(), attr_val1.c_str());
            if (!attr_name2.empty()) target_element->SetAttribute(attr_name2.c_str(), attr_val2.c_str());
            // Memory: Attributes are owned by the element/document.
            
            if (fdp.ConsumeBool() && !attr_name2.empty()) {
                target_element->DeleteAttribute(attr_name2.c_str()); // prev can be attr_name1
            } else if (!attr_name1.empty()) {
                target_element->DeleteAttribute(attr_name1.c_str()); // prev is null
            }
            
            // Coverage for XMLElement::Attribute (non-matching value, line 1636)
            if (!attr_name1.empty()) { // Ensure attr_name1 is valid
                target_element->SetAttribute(attr_name1.c_str(), "actual_value"); 
                // Memory: SetAttribute handles memory if attr_name1 was deleted.
                target_element->Attribute(attr_name1.c_str(), "a_value_that_does_not_match");
            }


            // Original DeleteAttribute logic, slightly modified to help cover line 134
            std::string attr_name_to_delete_orig = fdp.ConsumeRandomLengthString(15);
            if (attr_name_to_delete_orig.empty()) {
                const tinyxml2::XMLAttribute* first_attr = target_element->FirstAttribute();
                // Coverage for line 134: (first_attr && first_attr->Name())
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
        // Coverage: XMLUtil::ConvertUTF32ToUTF8 for input >= 0x200000 (lines 435-438)
        // and default case in switch (lines 464-465)
        if (fdp.ConsumeBool()) {
            utf32_char = fdp.ConsumeIntegralInRange<unsigned long>(0x200000, 0x400000); 
        } else {
            do { // Original logic for valid range
                utf32_char = fdp.ConsumeIntegralInRange<unsigned long>(0, 0x10FFFF);
            } while (utf32_char >= 0xD800 && utf32_char <= 0xDFFF); // Exclude surrogates
        }

        char utf8_buffer[5];
        int output_length = 0;
        memset(utf8_buffer, 0, sizeof(utf8_buffer));
        tinyxml2::XMLUtil::ConvertUTF32ToUTF8(utf32_char, utf8_buffer, &output_length);
        // Memory: Stack buffer, no leaks.
    }

    // --- Cleanup ---
    delete printer;
    delete doc;

    return 0;
}