#include "/src/tinyxml2/tinyxml2.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <cstdio> // For FILE operations (fopen, fclose, fwrite, remove)
#include <vector> 
#include <list>   // For std::list

// Define a temporary filename for file operations.
const char* FUZZ_XML_FILENAME = "fuzz_input.xml";
const char* FUZZ_SAVE_FILENAME = "fuzz_output.xml";

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    tinyxml2::XMLDocument doc;

    // --- API 1: tinyxml2::XMLDocument::LoadFile(const char *) ---
    std::string xml_content_for_load = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, Size / 2));
    FILE* fp_write = fopen(FUZZ_XML_FILENAME, "wb");
    if (fp_write) {
        fwrite(xml_content_for_load.data(), 1, xml_content_for_load.size(), fp_write);
        fclose(fp_write);

        doc.LoadFile(FUZZ_XML_FILENAME);
    }

    // --- DOM Manipulation APIs (if document has a root) ---
    tinyxml2::XMLElement* rootElement = doc.RootElement();
    if (rootElement) {
        std::string attr_name_for_root = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 32));
        if (!attr_name_for_root.empty()) {
            if (fdp.ConsumeBool()) {
                std::string attr_value_for_root = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 64));
                rootElement->SetAttribute(attr_name_for_root.c_str(), attr_value_for_root.c_str());
            }
            if (fdp.ConsumeBool()) {
                rootElement->DeleteAttribute(attr_name_for_root.c_str());
            }
        }

        std::string new_element_name_str = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 32));
        if (!new_element_name_str.empty()) {
            tinyxml2::XMLElement* newElement = doc.NewElement(new_element_name_str.c_str());
            if (newElement) {
                rootElement->InsertEndChild(newElement);
                std::string child_attr_name_str = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 32));
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
    }

    bool compact_print = fdp.ConsumeBool();
    doc.SaveFile(FUZZ_SAVE_FILENAME, compact_print);

    tinyxml2::XMLPrinter printer;
    int open_elements_count = 0; 
    std::list<std::string> active_element_names; // Use std::list for pointer stability

    if (fdp.ConsumeBool()) {
        doc.Print(&printer);
        open_elements_count = 0; 
        active_element_names.clear();
    }

    if (fdp.ConsumeBool()) { 
        if (fdp.ConsumeBool()) { 
             printer.ClearBuffer();
        }
        
        int num_printer_ops = fdp.ConsumeIntegralInRange<int>(0, 10);
        bool element_just_opened_for_attribute = false;

        for (int i = 0; i < num_printer_ops; ++i) {
            uint8_t op_choice = fdp.ConsumeIntegralInRange<uint8_t>(0, 6);
            
            std::string temp_name_str; // For attributes, etc.
            std::string temp_val_str;  // For attributes, text, etc.
            
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
                    if (open_elements_count > 0) { 
                        temp_val_str = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 30));
                        printer.PushText(temp_val_str.c_str(), fdp.ConsumeBool());
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

    if (fp_write) { 
      remove(FUZZ_XML_FILENAME);
    }
    remove(FUZZ_SAVE_FILENAME);

    return 0;
}