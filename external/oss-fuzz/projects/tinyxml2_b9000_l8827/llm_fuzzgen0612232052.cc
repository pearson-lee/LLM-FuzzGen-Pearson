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
    // std::unique_ptr ensures that the XMLDocument is properly deleted at the end of the scope,
    // which in turn triggers the deletion of all nodes it owns (including the ones we create).
    // This covers the destructors of these XML node types.
    std::unique_ptr<tinyxml2::XMLDocument> doc(new tinyxml2::XMLDocument());

    // Create an XMLDeclaration node.
    // NewDeclaration allocates the node, and it's owned by the XMLDocument.
    // The XMLDocument's destructor will handle its deletion.
    if (fdp.ConsumeBool()) {
        std::string decl_text = fdp.ConsumeRandomLengthString(100);
        // The returned XMLDeclaration* is managed by the 'doc'.
        doc->NewDeclaration(decl_text.c_str()); 
    }

    // Create an XMLComment node.
    if (fdp.ConsumeBool()) {
        std::string comment_text = fdp.ConsumeRandomLengthString(200);
        tinyxml2::XMLComment* comment = doc->NewComment(comment_text.c_str());
        // If comment creation is successful, link it to the document.
        // Nodes created with NewComment are allocated from the document's pool
        // and are deleted when the document is deleted, even if not linked.
        // Linking makes it part of the document structure for printing or traversal.
        if (comment) {
            doc->LinkEndChild(comment);
        }
    }

    // Create an XMLUnknown node.
    // XMLUnknown nodes are typically created by the parser for unrecognized XML.
    if (fdp.ConsumeBool()) {
        std::string unknown_text = fdp.ConsumeRandomLengthString(100);
        tinyxml2::XMLUnknown* unknown = doc->NewUnknown(unknown_text.c_str());
        // Similar to XMLComment, link if successfully created.
        // Memory is managed by the document.
        if (unknown) {
            doc->LinkEndChild(unknown);
        }
    }

    // Create an XMLText node.
    if (fdp.ConsumeBool()) {
        std::string text_data = fdp.ConsumeRandomLengthString(300);
        tinyxml2::XMLText* text_node = doc->NewText(text_data.c_str());
        // Similar to XMLComment, link if successfully created.
        // Memory is managed by the document.
        if (text_node) {
            doc->LinkEndChild(text_node);
        }
    }
    
    // Optionally, print the constructed document using another XMLPrinter.
    // This exercises the Accept/Visit pattern for the created nodes and the printer.
    if (fdp.ConsumeBool()) {
        tinyxml2::XMLPrinter doc_printer; // Manages its own internal buffer.
        doc->Print(&doc_printer);
        // doc_printer's destructor will clean up its buffer.
        // const char* printed_xml = doc_printer.CString(); // Can be used if needed.
    }

    // When 'doc' (std::unique_ptr<tinyxml2::XMLDocument>) goes out of scope,
    // its destructor is called. The XMLDocument destructor deletes all nodes
    // it owns, including any XMLDeclaration, XMLComment, XMLUnknown, XMLText
    // nodes created via NewDeclaration, NewComment, etc. This ensures that
    // the destructors for these node types are called and memory is freed,
    // preventing leaks.

    return 0;
}