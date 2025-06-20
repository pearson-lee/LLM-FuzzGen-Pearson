#include "/src/tinyxml2/tinyxml2.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <cstdio> // For FILE operations (fopen, fclose, fwrite, remove)
#include <list>   // For std::list

// Define a temporary filename for file operations.
const char* FUZZ_XML_FILENAME = "fuzz_input.xml";
const char* FUZZ_SAVE_FILENAME = "fuzz_output.xml";

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // --- Enhanced XMLDocument options ---
    bool process_entities_fuzz = fdp.ConsumeBool();
    // Coverage: XMLDocument::Identify PEDANTIC_WHITESPACE branch. Max value 2 for PEDANTIC_WHITESPACE.
    tinyxml2::Whitespace ws_mode_fuzz = static_cast<tinyxml2::Whitespace>(fdp.ConsumeIntegralInRange<int>(0, 2));
    tinyxml2::XMLDocument doc(process_entities_fuzz, ws_mode_fuzz);

    // --- API 1: tinyxml2::XMLDocument::LoadFile(const char *) ---
    std::string xml_content_for_load;

    // --- Target PEDANTIC_WHITESPACE in XMLDocument::Identify ---
    // Coverage: XMLDocument::Identify lines 757-761 for PEDANTIC_WHITESPACE
    // Requires: PEDANTIC_WHITESPACE mode, 'first' node, leading whitespace, and '</' pattern.
    if (ws_mode_fuzz == tinyxml2::PEDANTIC_WHITESPACE && fdp.ConsumeBool()) {
        xml_content_for_load = " < /pedantic_test_element>";
    } else {
        xml_content_for_load = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, Size / 3));
        if (fdp.ConsumeBool()) {
            xml_content_for_load += "<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>";
        }
        if (fdp.ConsumeBool()) {
            xml_content_for_load += "<!-- This is a fuzzed comment -->";
        }
        xml_content_for_load += "<fuzz_outer_root>";
        if (fdp.ConsumeBool()) {
            xml_content_for_load += "<child_text_fuzz>Text with entities: &amp; &lt; &gt; &#xABCD; &#12345; &#xaf00; &#xBAD;</child_text_fuzz>";
        }

        if (fdp.ConsumeBool()) {
            xml_content_for_load += "<utf_four_byte>&#x10FFFF;</utf_four_byte>";
        }
        if (fdp.ConsumeBool()) {
            xml_content_for_load += "<utf_invalid_codepoint>&#x200000;</utf_invalid_codepoint>";
        }

        // Coverage: XMLUtil::GetCharacterRef error paths for premature end / no semicolon
        if (fdp.ConsumeBool()) {
            xml_content_for_load += "<char_ref_premature_end1>&#</char_ref_premature_end1>";
        }
        if (fdp.ConsumeBool()) {
            xml_content_for_load += "<char_ref_premature_end2>&#x</char_ref_premature_end2>";
        }
        if (fdp.ConsumeBool()) {
            xml_content_for_load += "<char_ref_no_semicolon1>&#123</char_ref_no_semicolon1>";
        }
        if (fdp.ConsumeBool()) {
            xml_content_for_load += "<char_ref_no_semicolon2>&#xabc</char_ref_no_semicolon2>";
        }

        if (fdp.ConsumeBool()) {
            xml_content_for_load += "<![CDATA[Some CDATA fuzzed content & more < > symbols]]>";
        }
        xml_content_for_load += "</fuzz_outer_root>";
        if (fdp.ConsumeBool()) {
            xml_content_for_load += "<!UNKNOWN_FUZZ_TAG some unknown fuzzed stuff>";
        }
    }

    FILE* fp_write_fuzz = fopen(FUZZ_XML_FILENAME, "wb");
    if (fp_write_fuzz) {
        fwrite(xml_content_for_load.data(), 1, xml_content_for_load.size(), fp_write_fuzz);
        fclose(fp_write_fuzz);
        doc.LoadFile(FUZZ_XML_FILENAME);
    }

    if (fdp.ConsumeBool()) {
        doc.LoadFile(static_cast<const char*>(nullptr));
    }

    // --- DOM Manipulation APIs (if document has a root) ---
    tinyxml2::XMLElement* rootElement = doc.RootElement();
    if (rootElement) {
        std::string attr_name_for_root = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(1, 32));
        if (!attr_name_for_root.empty()) {
            if (fdp.ConsumeBool()) {
                std::string attr_value_for_root = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 64));
                rootElement->SetAttribute(attr_name_for_root.c_str(), attr_value_for_root.c_str());

                if (fdp.ConsumeBool()) {
                     std::string updated_attr_value = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 64));
                     rootElement->SetAttribute(attr_name_for_root.c_str(), updated_attr_value.c_str());
                }
            }
            if (fdp.ConsumeBool()) {
                (void)rootElement->Attribute(attr_name_for_root.c_str(), "non_matching_fuzz_value");
            }
            if (fdp.ConsumeBool()) {
                rootElement->DeleteAttribute(attr_name_for_root.c_str());
            }

            // Coverage: XMLElement::DeleteAttribute where prev is not null
            if (fdp.ConsumeBool()) {
                std::string attr1_name = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(1,10));
                std::string attr2_name = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(1,10));
                // Ensure names are non-empty and different to avoid deleting the same attribute or an empty one
                if (!attr1_name.empty() && !attr2_name.empty() && attr1_name != attr2_name) {
                    rootElement->SetAttribute(attr1_name.c_str(), "val1_del_attr_fuzz");
                    rootElement->SetAttribute(attr2_name.c_str(), "val2_del_attr_fuzz");
                    // Deleting the second attribute should make 'prev' non-null in DeleteAttribute
                    rootElement->DeleteAttribute(attr2_name.c_str());
                }
            }
        }

        std::string new_element_name_str = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(1, 32));
        if (!new_element_name_str.empty()) {
            tinyxml2::XMLElement* newElement = doc.NewElement(new_element_name_str.c_str());
            if (newElement) {
                rootElement->InsertEndChild(newElement);
                if (fdp.ConsumeBool()) {
                    newElement->SetName("StaticNameFromFuzzer", true);
                }

                std::string child_attr_name_str = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(1, 32));
                if (!child_attr_name_str.empty()) {
                    if (fdp.ConsumeBool()) {
                         std::string child_attr_val_str = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 64));
                         newElement->SetAttribute(child_attr_name_str.c_str(), child_attr_val_str.c_str());
                    }
                    if (fdp.ConsumeBool()) {
                        newElement->DeleteAttribute(child_attr_name_str.c_str());
                    }
                }
            }
        }
        if (fdp.ConsumeBool()) {
            tinyxml2::XMLElement* child1 = doc.NewElement("Child1ForDeleteFuzz");
            tinyxml2::XMLElement* child2 = doc.NewElement("Child2ForDeleteFuzz");
            if (child1 && child2) {
                rootElement->InsertEndChild(child1);
                rootElement->InsertEndChild(child2);
                rootElement->DeleteChild(child2);
            }
        }

        if (fdp.ConsumeBool()) {
            tinyxml2::XMLDocument doc2;
            std::string elem_name_doc2_str = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(1,10));
            if (!elem_name_doc2_str.empty()) {
                tinyxml2::XMLElement* elemFromDoc2 = doc2.NewElement(elem_name_doc2_str.c_str());
                if (elemFromDoc2) {
                    (void)rootElement->InsertEndChild(elemFromDoc2);
                }
            }
        }

        // Coverage: XMLNode::InsertChildPreamble for reparenting a node
        if (fdp.ConsumeBool()) {
            tinyxml2::XMLElement* p1 = doc.NewElement("reparent_P1");
            tinyxml2::XMLElement* c1 = doc.NewElement("reparent_C1");
            tinyxml2::XMLElement* p2 = doc.NewElement("reparent_P2");
            if (p1 && c1 && p2) {
                rootElement->InsertEndChild(p1);
                rootElement->InsertEndChild(p2);
                p1->InsertEndChild(c1); // c1 is child of p1
                if (fdp.ConsumeBool()) {
                    // Re-parent c1 to p2. This will call Unlink(c1) from p1.
                    p2->InsertEndChild(c1);
                }
            }
        }
    }

    if (fdp.ConsumeBool()) {
        tinyxml2::XMLElement* unlinked_el = doc.NewElement("UnlinkedElementFuzz");
        (void)unlinked_el;
    }

    bool compact_print_fuzz = fdp.ConsumeBool();
    if (fdp.ConsumeBool()) {
        doc.SaveFile(static_cast<const char*>(nullptr), compact_print_fuzz);
    }
    doc.SaveFile(FUZZ_SAVE_FILENAME, compact_print_fuzz);

    if (fdp.ConsumeBool()) {
        doc.Print(nullptr);
    }

    if (fdp.ConsumeBool()) {
        (void)doc.Value();
    }

    tinyxml2::XMLPrinter printer;
    int open_elements_count = 0;
    std::list<std::string> active_element_names;

    if (fdp.ConsumeBool()) {
        doc.Print(&printer);
        open_elements_count = 0;
        active_element_names.clear();
    }

    if (fdp.ConsumeBool()) {
        if (fdp.ConsumeBool()) {
             printer.ClearBuffer();
             open_elements_count = 0;
             active_element_names.clear();
        }

        int num_printer_ops = fdp.ConsumeIntegralInRange<int>(0, 10);
        bool element_just_opened_for_attribute = false;

        for (int i = 0; i < num_printer_ops; ++i) {
            uint8_t op_choice = fdp.ConsumeIntegralInRange<uint8_t>(0, 6);
            std::string temp_name_str;
            std::string temp_val_str;
            bool current_op_opened_element = false;

            switch (op_choice) {
                case 0: // OpenElement
                    {
                        std::string name_for_open = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(1, 20));
                        if (!name_for_open.empty()) {
                            active_element_names.push_back(name_for_open);
                            printer.OpenElement(active_element_names.back().c_str(), fdp.ConsumeBool());
                            open_elements_count++;
                            current_op_opened_element = true;
                        }
                    }
                    break;
                case 1: // PushAttribute
                    if (element_just_opened_for_attribute && open_elements_count > 0) {
                        temp_name_str = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(1, 20));
                        if (!temp_name_str.empty()) {
                            uint8_t attr_type_choice = fdp.ConsumeIntegralInRange<uint8_t>(0, 6);
                            switch (attr_type_choice) {
                                case 0:
                                    temp_val_str = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 30));
                                    printer.PushAttribute(temp_name_str.c_str(), temp_val_str.c_str());
                                    break;
                                case 1:
                                    printer.PushAttribute(temp_name_str.c_str(), fdp.ConsumeIntegral<int>());
                                    break;
                                case 2:
                                    printer.PushAttribute(temp_name_str.c_str(), fdp.ConsumeIntegral<unsigned>());
                                    break;
                                case 3:
                                    printer.PushAttribute(temp_name_str.c_str(), fdp.ConsumeBool());
                                    break;
                                case 4:
                                    printer.PushAttribute(temp_name_str.c_str(), fdp.ConsumeFloatingPoint<double>());
                                    break;
                                case 5:
                                    printer.PushAttribute(temp_name_str.c_str(), fdp.ConsumeIntegral<int64_t>());
                                    break;
                                case 6:
                                    printer.PushAttribute(temp_name_str.c_str(), fdp.ConsumeIntegral<uint64_t>());
                                    break;
                            }
                        }
                    }
                    break;
                case 2: // PushText
                    if (open_elements_count > 0) {
                        uint8_t text_type_choice = fdp.ConsumeIntegralInRange<uint8_t>(0, 6);
                        switch (text_type_choice) {
                            case 0:
                                temp_val_str = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 30));
                                printer.PushText(temp_val_str.c_str(), fdp.ConsumeBool());
                                break;
                            case 1:
                                printer.PushText(fdp.ConsumeIntegral<int>());
                                break;
                            case 2:
                                printer.PushText(fdp.ConsumeIntegral<unsigned>());
                                break;
                            case 3:
                                printer.PushText(fdp.ConsumeBool());
                                break;
                            case 4:
                                printer.PushText(fdp.ConsumeFloatingPoint<double>());
                                break;
                            case 5:
                                printer.PushText(fdp.ConsumeIntegral<int64_t>());
                                break;
                            case 6:
                                printer.PushText(fdp.ConsumeIntegral<uint64_t>());
                                break;
                        }
                    }
                    break;
                case 3: // CloseElement
                    if (open_elements_count > 0) {
                        printer.CloseElement(fdp.ConsumeBool());
                        open_elements_count--;
                        if (!active_element_names.empty()) {
                            active_element_names.pop_back();
                        }
                    }
                    break;
                case 4: // PushComment
                    temp_val_str = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 30));
                    printer.PushComment(temp_val_str.c_str());
                    break;
                case 5: // PushDeclaration
                    temp_val_str = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 30));
                    printer.PushDeclaration(temp_val_str.c_str());
                    break;
                case 6: // PushUnknown
                    temp_val_str = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 30));
                    printer.PushUnknown(temp_val_str.c_str());
                    break;
            }
            element_just_opened_for_attribute = current_op_opened_element;
        }
    }

    while(open_elements_count > 0) {
        printer.CloseElement(false);
        open_elements_count--;
        if (!active_element_names.empty()) {
            active_element_names.pop_back();
        }
    }

    // --- Coverage for specific node destructors ---
    // Create and link various node types to ensure their destructors are called when 'doc' is cleared/destroyed.
    // These are created after LoadFile and other operations to ensure they are present during doc's final cleanup.
    // Memory is managed by the XMLDocument's pools.
    if (fdp.ConsumeBool()) {
        // Coverage: XMLDeclaration::~XMLDeclaration
        // Create a declaration node. It will be added to doc's unlinked list.
        // If InsertFirstChild is called, it's linked. Either way, doc's destructor will clean it up.
        tinyxml2::XMLDeclaration* decl_node = doc.NewDeclaration(fdp.ConsumeRandomLengthString(25).c_str());
        if (decl_node) {
             // Declarations are typically top-level. Inserting it ensures it's managed if not already.
            doc.InsertFirstChild(decl_node);
        }
    }
    if (fdp.ConsumeBool()) {
        // Coverage: XMLComment::~XMLComment
        tinyxml2::XMLComment* comment_node = doc.NewComment(fdp.ConsumeRandomLengthString(25).c_str());
        if (comment_node) {
            // Link to root or doc to ensure it's part of the managed tree/list.
            if (doc.RootElement()) doc.RootElement()->InsertEndChild(comment_node);
            else doc.InsertEndChild(comment_node);
        }
    }
    if (fdp.ConsumeBool()) {
        // Coverage: XMLUnknown::~XMLUnknown
        tinyxml2::XMLUnknown* unknown_node = doc.NewUnknown(fdp.ConsumeRandomLengthString(25).c_str());
        if (unknown_node) {
            if (doc.RootElement()) doc.RootElement()->InsertEndChild(unknown_node);
            else doc.InsertEndChild(unknown_node);
        }
    }
    if (fdp.ConsumeBool()) {
        // Coverage: XMLText::~XMLText
        // XMLText needs an element parent.
        tinyxml2::XMLElement* text_parent_for_dtor = doc.RootElement();
        bool temp_parent_created = false;
        if (!text_parent_for_dtor) {
            text_parent_for_dtor = doc.NewElement("TextParentForDtorFuzz");
            if (text_parent_for_dtor) {
                doc.InsertEndChild(text_parent_for_dtor);
                temp_parent_created = true; // Mark that we created it
            }
        }
        if (text_parent_for_dtor) {
            tinyxml2::XMLText* text_node = doc.NewText(fdp.ConsumeRandomLengthString(25).c_str());
            if (text_node) {
                text_parent_for_dtor->InsertEndChild(text_node);
            }
        }
        // If we created a temporary parent just for this text node, and it has no other children,
        // it might be good to remove it to not significantly alter doc structure for other tests,
        // but its own dtor will be tested regardless. For simplicity, leave it.
        // The text node's dtor is the primary target here.
    }


    remove(FUZZ_XML_FILENAME);
    remove(FUZZ_SAVE_FILENAME);

    return 0;
}