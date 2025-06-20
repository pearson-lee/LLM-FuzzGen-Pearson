#include "/src/tinyxml2/tinyxml2.h" // Required header for tinyxml2 library
#include <fuzzer/FuzzedDataProvider.h> // Required for fuzzing
#include <string>
#include <memory> // For std::unique_ptr, ensuring RAII for XMLDocument

// Target APIs:
// 1. void tinyxml2::XMLPrinter::Print(const char *format, ...) - For format string fuzzing and general output.
//    (Fuzzed indirectly via public XMLPrinter methods)
// 2. tinyxml2::XMLDeclaration (and its destructor ~XMLDeclaration) - Lifecycle testing.
// 3. tinyxml2::XMLComment (and its destructor ~XMLComment) - Lifecycle testing.
// 4. tinyxml2::XMLUnknown (and its destructor ~XMLUnknown) - Lifecycle testing.
// 5. tinyxml2::XMLText (and its destructor ~XMLText) - Lifecycle testing.
// Indirectly, TIXML_VSCPRINTF is also fuzzed via XMLPrinter's internal Print calls.

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // Section 1: Fuzz public methods of tinyxml2::XMLPrinter
    // These methods internally use the protected Print function with fixed format strings,
    // exercising its data handling capabilities.
    tinyxml2::XMLPrinter printer_for_public_methods; 
    
    uint8_t op_type = fdp.ConsumeIntegralInRange<uint8_t>(0, 6);
    std::string text_arg = fdp.ConsumeRandomLengthString(100);
    std::string name_arg = fdp.ConsumeRandomLengthString(50);

    switch (op_type) {
        case 0:
            printer_for_public_methods.PushText(text_arg.c_str(), fdp.ConsumeBool());
            break;
        case 1:
            printer_for_public_methods.PushText(fdp.ConsumeIntegral<int>());
            break;
        case 2:
            printer_for_public_methods.PushText(fdp.ConsumeFloatingPoint<double>());
            break;
        case 3:
            printer_for_public_methods.PushComment(text_arg.c_str());
            break;
        case 4:
            printer_for_public_methods.PushDeclaration(text_arg.c_str());
            break;
        case 5:
            printer_for_public_methods.PushUnknown(text_arg.c_str());
            break;
        case 6:
            // Fuzz OpenElement, PushAttribute, CloseElement sequence
            printer_for_public_methods.OpenElement(name_arg.c_str(), fdp.ConsumeBool());
            if (fdp.ConsumeBool()) {
                std::string attr_name = fdp.ConsumeRandomLengthString(30);
                std::string attr_val = fdp.ConsumeRandomLengthString(30);
                printer_for_public_methods.PushAttribute(attr_name.c_str(), attr_val.c_str());
            }
            if (fdp.ConsumeBool()) {
                std::string attr_name_int = fdp.ConsumeRandomLengthString(30);
                printer_for_public_methods.PushAttribute(attr_name_int.c_str(), fdp.ConsumeIntegral<int>());
            }
            if (fdp.ConsumeBool()) {
                std::string text_in_element = fdp.ConsumeRandomLengthString(50);
                printer_for_public_methods.PushText(text_in_element.c_str());
            }
            printer_for_public_methods.CloseElement(fdp.ConsumeBool());
            break;
    }
    // The printer_for_public_methods object goes out of scope here, and its destructor
    // will clean up the internal buffer, ensuring no memory leaks from its operations.

    // Section 2: Fuzz lifecycle of XMLDeclaration, XMLComment, XMLUnknown, XMLText
    // We use an XMLDocument to create and manage these nodes.
    std::unique_ptr<tinyxml2::XMLDocument> doc(new tinyxml2::XMLDocument());

    // Create an XMLDeclaration node.
    if (fdp.ConsumeBool()) {
        std::string decl_text_str = fdp.ConsumeRandomLengthString(100);
        // Allow nullptr to test default declaration string
        const char* decl_text_cstr = (decl_text_str.empty() && fdp.ConsumeBool()) ? nullptr : decl_text_str.c_str();
        tinyxml2::XMLDeclaration* decl_node = doc->NewDeclaration(decl_text_cstr); 
        if (decl_node) { 
            if (fdp.ConsumeBool()) {
                std::string static_decl_data = fdp.ConsumeRandomLengthString(50);
                // Let SetValue manage its own copy of the string
                decl_node->SetValue(static_decl_data.c_str(), false); 
            }
        }
    }

    // Create an XMLComment node.
    if (fdp.ConsumeBool()) {
        std::string comment_text_str = fdp.ConsumeRandomLengthString(200);
        tinyxml2::XMLComment* comment_node = doc->NewComment(comment_text_str.c_str());
        if (comment_node) {
            doc->LinkEndChild(comment_node);
            if (fdp.ConsumeBool()) {
                std::string static_comment_data = fdp.ConsumeRandomLengthString(50);
                // Let SetValue manage its own copy of the string
                comment_node->SetValue(static_comment_data.c_str(), false);
            }
        }
    }

    // Create an XMLUnknown node.
    if (fdp.ConsumeBool()) {
        std::string unknown_text_str = fdp.ConsumeRandomLengthString(100);
        tinyxml2::XMLUnknown* unknown_node = doc->NewUnknown(unknown_text_str.c_str());
        if (unknown_node) {
            doc->LinkEndChild(unknown_node);
            if (fdp.ConsumeBool()) {
                std::string static_unknown_data = fdp.ConsumeRandomLengthString(50);
                // Let SetValue manage its own copy of the string
                unknown_node->SetValue(static_unknown_data.c_str(), false);
            }
        }
    }

    // Create an XMLText node.
    if (fdp.ConsumeBool()) {
        std::string text_data_str = fdp.ConsumeRandomLengthString(300);
        tinyxml2::XMLText* text_node = doc->NewText(text_data_str.c_str());
        if (text_node) {
            doc->LinkEndChild(text_node);
            if (fdp.ConsumeBool()) {
                std::string static_text_data = fdp.ConsumeRandomLengthString(50);
                // Let SetValue manage its own copy of the string
                text_node->SetValue(static_text_data.c_str(), false);
            }
        }
    }
    
    // Coverage: XMLNode::Value() on an XMLDocument (targets tinyxml2.cpp line 851)
    if (fdp.ConsumeBool()) {
        (void)doc->Value(); // XMLDocument::Value() should return nullptr.
    }

    // Coverage: XMLDocument::DeleteNode for a node with a parent (targets tinyxml2.cpp lines 2330-2331)
    if (fdp.ConsumeBool()) {
        std::string elem_name_del = fdp.ConsumeRandomLengthString(20);
        tinyxml2::XMLElement* elem_to_delete = doc->NewElement(elem_name_del.c_str());
        if (elem_to_delete) {
            doc->LinkEndChild(elem_to_delete); 
            doc->DeleteNode(elem_to_delete); 
        }
    }
    
    // Coverage: XMLNode::Unlink for a middle child (targets tinyxml2.cpp lines 901-902)
    // Changed to use DeleteChild as Unlink is private. DeleteChild internally calls Unlink.
    if (fdp.ConsumeBool()) {
        tinyxml2::XMLElement* parent_for_unlink = doc->NewElement("unlinkParent");
        if (parent_for_unlink) {
            doc->LinkEndChild(parent_for_unlink);
            tinyxml2::XMLElement* c1 = doc->NewElement("c1");
            tinyxml2::XMLElement* c2_middle = doc->NewElement("c2_middle");
            tinyxml2::XMLElement* c3 = doc->NewElement("c3");

            if (c1 && c2_middle && c3) {
                parent_for_unlink->LinkEndChild(c1);
                parent_for_unlink->LinkEndChild(c2_middle);
                parent_for_unlink->LinkEndChild(c3);
                
                parent_for_unlink->DeleteChild(c2_middle); 
            }
        }
    }

    // Coverage: XMLNode::InsertEndChild with node from a different document (targets tinyxml2.cpp lines 929-931)
    if (fdp.ConsumeBool()) {
        std::unique_ptr<tinyxml2::XMLDocument> doc2(new tinyxml2::XMLDocument());
        if (doc2) {
            std::string elem_name_doc2_str = fdp.ConsumeRandomLengthString(20);
            tinyxml2::XMLElement* node_from_doc2 = doc2->NewElement(elem_name_doc2_str.c_str());
            if (node_from_doc2) {
                doc->InsertEndChild(node_from_doc2); 
            }
        } 
    }

    // Coverage: XMLNode::InsertChildPreamble for a node that already has a parent (targets tinyxml2.cpp lines 1209-1210)
    if (fdp.ConsumeBool()) {
        tinyxml2::XMLElement* p1 = doc->NewElement(fdp.ConsumeRandomLengthString(10).c_str());
        tinyxml2::XMLElement* p2 = doc->NewElement(fdp.ConsumeRandomLengthString(10).c_str());
        tinyxml2::XMLElement* child_move = doc->NewElement(fdp.ConsumeRandomLengthString(10).c_str());
        if (p1 && p2 && child_move) {
            doc->LinkEndChild(p1);
            doc->LinkEndChild(p2);
            p1->InsertEndChild(child_move); 
            p2->InsertEndChild(child_move); 
        }
    }
    
    bool use_bom = fdp.ConsumeBool();
    doc->SetBOM(use_bom);

    if (fdp.ConsumeBool()) {
        doc->Print(nullptr);
    }

    if (fdp.ConsumeBool()) {
        tinyxml2::XMLPrinter doc_printer; 
        doc->Print(&doc_printer);
    }

    if (fdp.ConsumeBool()) {
        std::unique_ptr<tinyxml2::XMLDocument> doc_no_entities(new tinyxml2::XMLDocument(false)); 
        if (doc_no_entities) {
            std::string text_for_no_entities_str = fdp.ConsumeRandomLengthString(50);
            tinyxml2::XMLText* text_node_no_entities = doc_no_entities->NewText(text_for_no_entities_str.c_str());
            if (text_node_no_entities) {
                doc_no_entities->LinkEndChild(text_node_no_entities);
            }
            tinyxml2::XMLPrinter temp_printer_no_entities; 
            doc_no_entities->Print(&temp_printer_no_entities);
        } 
    }

    return 0;
}