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
    // Rationale: Cover XMLPrinter::PrintString with _processEntities = false (lines 2713-2715 of coverage)
    // Rationale: Cover XMLText::ParseDeep with COLLAPSE_WHITESPACE (lines 1245-1246 of coverage)
    bool process_entities_fuzz = fdp.ConsumeBool();
    tinyxml2::Whitespace ws_mode_fuzz = fdp.ConsumeBool() ? tinyxml2::COLLAPSE_WHITESPACE : tinyxml2::PRESERVE_WHITESPACE;
    tinyxml2::XMLDocument doc(process_entities_fuzz, ws_mode_fuzz);

    // --- API 1: tinyxml2::XMLDocument::LoadFile(const char *) ---
    std::string xml_content_for_load = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, Size / 2));

    // Rationale: Enrich input to cover XMLUtil::ConvertUTF32ToUTF8, XMLUtil::GetCharacterRef (various entities),
    // and destructors for XMLDeclaration, XMLComment, XMLText, XMLUnknown by ensuring their creation and deletion.
    if (fdp.ConsumeBool()) {
        xml_content_for_load += "<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>";
    }
    if (fdp.ConsumeBool()) {
        xml_content_for_load += "<!-- This is a fuzzed comment -->";
    }
    // Add some structured elements to ensure basic parsability and include specific test cases
    xml_content_for_load += "<fuzz_outer_root>";
    if (fdp.ConsumeBool()) {
        xml_content_for_load += "<child_text_fuzz>Text with entities: &amp; &lt; &gt; &#xABCD; &#12345; &#xaf00; &#xBAD;</child_text_fuzz>";
    }
    if (fdp.ConsumeBool()) {
        xml_content_for_load += "<![CDATA[Some CDATA fuzzed content & more < > symbols]]>";
    }
    xml_content_for_load += "</fuzz_outer_root>";
    if (fdp.ConsumeBool()) {
        xml_content_for_load += "<!UNKNOWN_FUZZ_TAG some unknown fuzzed stuff>";
    }

    FILE* fp_write_fuzz = fopen(FUZZ_XML_FILENAME, "wb");
    if (fp_write_fuzz) {
        fwrite(xml_content_for_load.data(), 1, xml_content_for_load.size(), fp_write_fuzz);
        fclose(fp_write_fuzz);
        // doc.Clear() is called by LoadFile, potentially cleaning unlinked nodes from previous ops if any.
        doc.LoadFile(FUZZ_XML_FILENAME);
    }

    // Rationale: Cover XMLDocument::LoadFile(nullptr) error case (lines 2347-2350 of coverage)
    if (fdp.ConsumeBool()) {
        doc.LoadFile(static_cast<const char*>(nullptr));
    }

    // --- DOM Manipulation APIs (if document has a root) ---
    tinyxml2::XMLElement* rootElement = doc.RootElement();
    if (rootElement) {
        std::string attr_name_for_root = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(1, 32)); // Ensure non-empty
        if (!attr_name_for_root.empty()) {
            if (fdp.ConsumeBool()) {
                std::string attr_value_for_root = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 64));
                rootElement->SetAttribute(attr_name_for_root.c_str(), attr_value_for_root.c_str());

                // Rationale: Cover XMLElement::FindOrCreateAttribute's "find existing attribute" branch (lines 1920-1921 of coverage)
                if (fdp.ConsumeBool()) {
                     std::string updated_attr_value = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 64));
                     rootElement->SetAttribute(attr_name_for_root.c_str(), updated_attr_value.c_str());
                }
            }
            // Rationale: Cover XMLElement::Attribute's branch for non-matching value (line 1636 of coverage)
            if (fdp.ConsumeBool()) {
                (void)rootElement->Attribute(attr_name_for_root.c_str(), "non_matching_fuzz_value");
            }
            if (fdp.ConsumeBool()) {
                rootElement->DeleteAttribute(attr_name_for_root.c_str());
            }
        }

        std::string new_element_name_str = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(1, 32)); // Ensure non-empty
        if (!new_element_name_str.empty()) {
            tinyxml2::XMLElement* newElement = doc.NewElement(new_element_name_str.c_str());
            if (newElement) {
                rootElement->InsertEndChild(newElement);
                // Rationale: Cover XMLNode::SetValue with staticMem = true (lines 858-859 of coverage) via XMLElement::SetName
                if (fdp.ConsumeBool()) {
                    newElement->SetName("StaticNameFromFuzzer", true); // SetName calls SetValue with staticMem flag
                }

                std::string child_attr_name_str = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(1, 32)); // Ensure non-empty
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
        // Rationale: Cover XMLNode::Unlink for a non-first child (lines 901-902 of coverage)
        if (fdp.ConsumeBool()) {
            tinyxml2::XMLElement* child1 = doc.NewElement("Child1ForDeleteFuzz");
            tinyxml2::XMLElement* child2 = doc.NewElement("Child2ForDeleteFuzz");
            if (child1 && child2) {
                rootElement->InsertEndChild(child1);
                rootElement->InsertEndChild(child2); // child2 is not the first child, so child2->_prev is child1
                // Deleting child2 calls Unlink(child2). Inside Unlink, child2->_prev will be non-null.
                // This is memory safe as DeleteChild handles the full deletion of child2.
                rootElement->DeleteChild(child2);
            }
        }
    }

    // Rationale: Cover XMLDocument::Clear() with unlinked nodes (lines 2228-2229 of coverage).
    // NewElement adds node to _unlinked list. doc.Clear() (e.g. in ~XMLDocument) will delete it.
    if (fdp.ConsumeBool()) {
        tinyxml2::XMLElement* unlinked_el = doc.NewElement("UnlinkedElementFuzz");
        // This is memory safe: unlinked_el is owned by doc's _unlinked list and cleaned by XMLDocument::Clear().
        (void)unlinked_el; // Suppress unused variable warning if any
    }

    bool compact_print_fuzz = fdp.ConsumeBool();
    // Rationale: Cover XMLDocument::SaveFile(nullptr, ...) error case (lines 2420-2423 of coverage)
    if (fdp.ConsumeBool()) {
        doc.SaveFile(static_cast<const char*>(nullptr), compact_print_fuzz);
    }
    doc.SaveFile(FUZZ_SAVE_FILENAME, compact_print_fuzz);

    // Rationale: Cover XMLDocument::Print(nullptr) to use stdoutStreamer (lines 2484-2486 of coverage)
    if (fdp.ConsumeBool()) {
        doc.Print(nullptr);
    }

    // Rationale: Cover XMLNode::Value() on an XMLDocument (line 851 of coverage)
    if (fdp.ConsumeBool()) {
        (void)doc.Value(); // Returns nullptr for XMLDocument, exercises the ToDocument() check.
    }

    tinyxml2::XMLPrinter printer; // Default constructor uses no FILE*, buffers internally.
    int open_elements_count = 0;
    std::list<std::string> active_element_names; // Use std::list for pointer stability for c_str()

    if (fdp.ConsumeBool()) {
        doc.Print(&printer); // printer._processEntities is set by doc.ProcessEntities() here.
        open_elements_count = 0; // Reset counter as printer buffer is now based on doc
        active_element_names.clear(); // Clear names as well
    }

    // XMLPrinter specific operations
    if (fdp.ConsumeBool()) {
        if (fdp.ConsumeBool()) {
             printer.ClearBuffer();
             open_elements_count = 0; // Buffer cleared, so no open elements in printer's context
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
                        temp_val_str = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 30));
                        if (!temp_name_str.empty()) {
                            if (fdp.ConsumeBool()) printer.PushAttribute(temp_name_str.c_str(), temp_val_str.c_str());
                            else printer.PushAttribute(temp_name_str.c_str(), fdp.ConsumeIntegral<int>());
                        }
                    }
                    break;
                case 2: // PushText
                    if (open_elements_count > 0) { // Text can only be pushed inside an open element
                        temp_val_str = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 30));
                        printer.PushText(temp_val_str.c_str(), fdp.ConsumeBool()); // bool is for cdata
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
        printer.CloseElement(false); // Use default (not compact) for closing remaining
        open_elements_count--;
        if (!active_element_names.empty()) {
            active_element_names.pop_back();
        }
    }

    // Rationale: Ensure FUZZ_XML_FILENAME is removed even if fopen for write failed.
    // remove() is safe to call even if the file doesn't exist.
    remove(FUZZ_XML_FILENAME);
    remove(FUZZ_SAVE_FILENAME);

    return 0;
}