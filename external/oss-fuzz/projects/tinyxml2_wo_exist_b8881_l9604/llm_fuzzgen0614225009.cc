#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/tinyxml2/tinyxml2.h" // Project-relative path for tinyxml2.h

// Target APIs:
// 1. tinyxml2::XMLDocument::Parse(const char* xml, size_t nBytes)
// 2. tinyxml2::XMLDocument::RootElement()
// 3. tinyxml2::XMLElement::FirstChildElement(const char* name = nullptr)
// 4. tinyxml2::XMLElement::SetAttribute(const char* name, various types)
// 5. tinyxml2::XMLDocument::Accept(tinyxml2::XMLVisitor* visitor) (used with tinyxml2::XMLPrinter)

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // Create an XMLDocument object.
    // Memory: `doc` is stack-allocated. All XML nodes (elements, attributes, etc.)
    // created by or added to `doc` will be owned by `doc`. When `doc` goes out
    // of scope, its destructor will free all associated memory.
    tinyxml2::XMLDocument doc;

    // API 1: tinyxml2::XMLDocument::Parse()
    // Consume data for XML parsing. Max length 2048 to keep inputs manageable.
    std::string xml_to_parse = fdp.ConsumeRandomLengthString(2048);
    // Parse the XML. Using xml_to_parse.length() allows for null bytes within the input.
    doc.Parse(xml_to_parse.c_str(), xml_to_parse.length());
    // We don't stop on doc.ErrorID() here to allow fuzzing of subsequent API calls
    // even with potentially malformed XML, testing their robustness.

    // API 2: tinyxml2::XMLDocument::RootElement()
    tinyxml2::XMLElement* root = doc.RootElement();
    tinyxml2::XMLElement* child = nullptr;

    if (root) {
        // API 3: tinyxml2::XMLElement::FirstChildElement()
        // Attempt to get a child element.
        // Decide whether to search for a specific name or get the first child.
        if (fdp.ConsumeBool()) {
            std::string child_name_str = fdp.ConsumeRandomLengthString(64); // Max 64 chars for element name
            if (!child_name_str.empty()) { // Ensure non-empty name if searching by name
                 child = root->FirstChildElement(child_name_str.c_str());
            } else {
                 child = root->FirstChildElement(); // Fallback to first child if name is empty
            }
        } else {
            child = root->FirstChildElement(); // Get the first child, whatever its name.
        }
    }

    // API 4: tinyxml2::XMLElement::SetAttribute()
    // Select an element to modify: try child first, then root.
    tinyxml2::XMLElement* element_to_modify = child ? child : root;
    if (element_to_modify) {
        // Consume attribute name and string value. Max 64 chars for name, 128 for value.
        std::string attr_name_str = fdp.ConsumeRandomLengthString(64);
        std::string attr_value_str = fdp.ConsumeRandomLengthString(128);
        // Set a string attribute.
        if (!attr_name_str.empty()) { // Attribute name must not be empty
            element_to_modify->SetAttribute(attr_name_str.c_str(), attr_value_str.c_str());
        }


        // Exercise other overloads of SetAttribute with various data types.
        if (fdp.ConsumeBool()) {
            std::string attr_name_int = fdp.ConsumeRandomLengthString(64);
            if (!attr_name_int.empty()) {
                element_to_modify->SetAttribute(attr_name_int.c_str(), fdp.ConsumeIntegral<int>());
            }
        }
        if (fdp.ConsumeBool()) {
            std::string attr_name_uint = fdp.ConsumeRandomLengthString(64);
             if (!attr_name_uint.empty()) {
                element_to_modify->SetAttribute(attr_name_uint.c_str(), fdp.ConsumeIntegral<unsigned int>());
            }
        }
        if (fdp.ConsumeBool()) {
            std::string attr_name_bool = fdp.ConsumeRandomLengthString(64);
            if (!attr_name_bool.empty()) {
                element_to_modify->SetAttribute(attr_name_bool.c_str(), fdp.ConsumeBool());
            }
        }
        if (fdp.ConsumeBool()) {
            std::string attr_name_double = fdp.ConsumeRandomLengthString(64);
            if (!attr_name_double.empty()) {
                element_to_modify->SetAttribute(attr_name_double.c_str(), fdp.ConsumeFloatingPoint<double>());
            }
        }
         if (fdp.ConsumeBool()) {
            std::string attr_name_float = fdp.ConsumeRandomLengthString(64);
            if (!attr_name_float.empty()) {
                element_to_modify->SetAttribute(attr_name_float.c_str(), fdp.ConsumeFloatingPoint<float>());
            }
        }
        if (fdp.ConsumeBool()) {
            std::string attr_name_int64 = fdp.ConsumeRandomLengthString(64);
            if (!attr_name_int64.empty()) {
                element_to_modify->SetAttribute(attr_name_int64.c_str(), fdp.ConsumeIntegral<int64_t>());
            }
        }

        // === Enhancements for code coverage ===

        // Coverage for XMLElement::SetText (new text node path) and XMLElement::GetText
        std::string text_content1 = fdp.ConsumeRandomLengthString(30);
        element_to_modify->SetText(text_content1.c_str());
        element_to_modify->GetText(); 

        // Coverage for XMLElement::SetText (modify existing text node path)
        if (fdp.ConsumeBool() && element_to_modify->FirstChild() && element_to_modify->FirstChild()->ToText()) {
             std::string text_content2 = fdp.ConsumeRandomLengthString(30);
             element_to_modify->SetText(text_content2.c_str());
             element_to_modify->GetText(); // Call GetText again after modification
        }

        // Coverage for XMLElement::GetText (comment skipping path) and XMLNode::DeleteChildren
        // XMLNode::DeleteChildren is 0% covered. NewComment and NewText are also 0% covered.
        // InsertFirstChild and InsertEndChild are partially covered but this adds more specific scenarios.
        // Memory: New nodes are owned by `doc`. DeleteChildren manages its own memory.
        if (fdp.ConsumeBool()) {
            element_to_modify->DeleteChildren(); // Call to cover XMLNode::DeleteChildren
            tinyxml2::XMLComment* commentNode = doc.NewComment(fdp.ConsumeRandomLengthString(30).c_str());
            if (commentNode) element_to_modify->InsertFirstChild(commentNode); // Insert comment
            tinyxml2::XMLText* textNode = doc.NewText(fdp.ConsumeRandomLengthString(30).c_str());
            if (textNode) element_to_modify->InsertEndChild(textNode); // Insert text after comment
            element_to_modify->GetText(); // Should skip comment and find text
        }
        
        // Coverage for XMLElement::QueryIntText and XMLElement::IntText (both 0% covered)
        // Assumes SetText might have populated text.
        int int_val_text_query;
        element_to_modify->QueryIntText(&int_val_text_query); 
        (void)element_to_modify->IntText(fdp.ConsumeIntegral<int>());

        // Coverage for XMLElement::DeleteAttribute (0% covered)
        // Memory: DeleteAttribute is handled by XMLElement.
        std::string attr_name_for_deletion_op = fdp.ConsumeRandomLengthString(20);
        if (!attr_name_for_deletion_op.empty()) {
          element_to_modify->SetAttribute(attr_name_for_deletion_op.c_str(), "value_to_delete");
          element_to_modify->DeleteAttribute(attr_name_for_deletion_op.c_str()); // Deleting an existing attribute
          element_to_modify->DeleteAttribute(attr_name_for_deletion_op.c_str()); // Attempting to delete a non-existent attribute
        }
        
        // Coverage for XMLElement::InsertNewChildElement (0% covered)
        // Memory: New element is owned by `doc` via `element_to_modify`.
        if (fdp.ConsumeBool()) {
          std::string new_child_element_name = fdp.ConsumeRandomLengthString(20);
          if (!new_child_element_name.empty()) {
            element_to_modify->InsertNewChildElement(new_child_element_name.c_str());
          }
        }
        // === End of enhancements ===
    }

    // API 5: tinyxml2::XMLDocument::Accept() (used with tinyxml2::XMLPrinter)
    // Create a printer to serialize the document to a string.
    // Memory: `printer` is stack-allocated. The string generated by `printer.CStr()`
    // is owned by the `printer` object. It's valid as long as `printer` is in scope.
    tinyxml2::XMLPrinter printer;
    doc.Accept(&printer);

    // Retrieve the printed XML string. This tests the serialization logic.
    // The string `result_xml` makes a copy of the C-string returned by `printer.CStr()`.
    // The memory for `printer.CStr()` is managed by `printer`.
    std::string result_xml(printer.CStr());
    // (void)result_xml; // Suppress unused variable warning if not debugging.

    // All tinyxml2 objects (`doc`, `printer`) are stack-allocated.
    // Their destructors are called automatically when they go out of scope,
    // ensuring that all dynamically allocated memory they manage (like XML nodes
    // within `doc` or the string buffer within `printer`) is deallocated.
    // This prevents memory leaks.

    return 0;
}