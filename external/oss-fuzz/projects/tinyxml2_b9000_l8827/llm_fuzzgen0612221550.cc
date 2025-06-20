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

    // --- Stage 1: Target API: tinyxml2::XMLDocument::LoadFile(FILE *) ---
    doc = new tinyxml2::XMLDocument(); 

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

    // --- Stage 2: Target API: (indirectly) void tinyxml2::XMLPrinter::Print(const char *, ...) ---
    // We aim to exercise XMLPrinter's internal formatting by calling its public methods,
    // which in turn may call the protected Print method.
    if (fdp.ConsumeBool()) { // Randomly decide whether to test XMLPrinter
        printer = new tinyxml2::XMLPrinter(nullptr, fdp.ConsumeBool() /* compact mode */); 
        
        // Option 1: If a document exists, print it. This uses the visitor pattern.
        if (doc && fdp.ConsumeBool()) {
            doc->Accept(printer);
        } 
        // Option 2: Use various Push methods to exercise formatting and internal Print calls.
        // This is useful even if 'doc' is null or empty, or to specifically target Push methods.
        else { 
            int operation_choice = fdp.ConsumeIntegralInRange<int>(0, 6);
            std::string text_arg = fdp.ConsumeRandomLengthString(50);
            // Ensure element/attribute names are not empty if used.
            std::string name_arg = fdp.ConsumeRandomLengthString(20);
            if (name_arg.empty()) name_arg = "fuzzDefaultName"; 

            switch (operation_choice) {
                case 0: // Push text (string)
                    printer->PushText(text_arg.c_str(), fdp.ConsumeBool() /* cdata */);
                    break;
                case 1: // Push text (integer)
                    printer->PushText(fdp.ConsumeIntegral<int>());
                    break;
                case 2: // Push text (double)
                    printer->PushText(fdp.ConsumeFloatingPoint<double>());
                    break;
                case 3: // Push element and attribute (string or int value)
                    printer->OpenElement(name_arg.c_str());
                    {
                        std::string attr_name = fdp.ConsumeRandomLengthString(15);
                        if(attr_name.empty()) attr_name = "fuzzAttr"; // Ensure valid attribute name
                        
                        // Ensure attribute name is valid if not empty
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
                case 4: // Push comment
                    printer->PushComment(text_arg.c_str());
                    break;
                case 5: // Push declaration
                    printer->PushDeclaration(text_arg.c_str());
                    break;
                case 6: // Push unknown
                    printer->PushUnknown(text_arg.c_str());
                    break;
            }
        }
        // Access the printer's output string to ensure the Print logic is fully executed.
        (void)printer->CStr(); 
    }


    // --- Stage 3: Target API: tinyxml2::XMLDocument::SaveFile(const char *, bool) ---
    if (doc && fdp.ConsumeBool()) { 
        bool compact_mode = fdp.ConsumeBool(); 
        doc->SaveFile(FUZZ_SAVE_FILENAME, compact_mode);
        std::remove(FUZZ_SAVE_FILENAME);
    }

    // --- Stage 4: Target API: (indirectly) void tinyxml2::XMLElement::DeleteAttribute(XMLAttribute *) ---
    if (doc && fdp.ConsumeBool()) { 
        tinyxml2::XMLElement* target_element = doc->RootElement();

        if (!target_element && fdp.ConsumeBool()) {
            std::string root_name = fdp.ConsumeRandomLengthString(10);
            if (root_name.empty()) root_name = "FuzzRoot"; 
            target_element = doc->NewElement(root_name.c_str());
            doc->InsertFirstChild(target_element); 
        }
        
        if (target_element) { 
            std::string attr_name_to_delete = fdp.ConsumeRandomLengthString(15);
            
            if (attr_name_to_delete.empty()) {
                const tinyxml2::XMLAttribute* first_attr = target_element->FirstAttribute();
                if (first_attr && first_attr->Name()) { // Check Name() not null
                    attr_name_to_delete = first_attr->Name();
                } else {
                    attr_name_to_delete = "fuzz_attr_default";
                }
            }

            if (fdp.ConsumeBool() && !target_element->FindAttribute(attr_name_to_delete.c_str())) {
                std::string attr_value = fdp.ConsumeRandomLengthString(20);
                target_element->SetAttribute(attr_name_to_delete.c_str(), attr_value.c_str());
            }
            
            if (!attr_name_to_delete.empty()) { // Ensure attribute name is not empty for DeleteAttribute
                target_element->DeleteAttribute(attr_name_to_delete.c_str());
            }
        }
    }

    // --- Stage 5: Target API: void tinyxml2::XMLUtil::ConvertUTF32ToUTF8(unsigned long, char *, int *) ---
    if (fdp.ConsumeBool()) { 
        unsigned long utf32_char;
        do {
            utf32_char = fdp.ConsumeIntegralInRange<unsigned long>(0, 0x10FFFF);
        } while (utf32_char >= 0xD800 && utf32_char <= 0xDFFF); 

        char utf8_buffer[5]; 
        int output_length = 0; 

        memset(utf8_buffer, 0, sizeof(utf8_buffer));

        tinyxml2::XMLUtil::ConvertUTF32ToUTF8(utf32_char, utf8_buffer, &output_length);
    }

    // --- Cleanup ---
    delete printer; 
    delete doc;     

    return 0; 
}