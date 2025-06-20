#include "/src/tinyxml2/tinyxml2.h" // Project-relative path for tinyxml2
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <memory>   // For std::unique_ptr
#include <cstddef>  // For size_t
#include <cstdint>  // For uint8_t

// Target APIs:
// 1. DW_TAG_enumeration_typeXMLError tinyxml2::XMLDocument::Parse(const char *, size_t)
// 2. XMLElement * tinyxml2::XMLDocument::NewElement(const char *)
// 3. void tinyxml2::XMLElement::SetAttribute(const char *, const char *)
// 4. void tinyxml2::XMLElement::SetText(const char *)
// 5. void tinyxml2::XMLDocument::Print(XMLPrinter *)
// Added targets based on coverage analysis:
// 6. void tinyxml2::XMLElement::DeleteAttribute(const char *)
// 7. XMLError tinyxml2::XMLElement::Query<Type>Attribute(const char *, <Type>*) for various types
// 8. XMLError tinyxml2::XMLElement::Query<Type>Text(<Type>*) for various types
// 9. const char * tinyxml2::XMLElement::GetText()
// New targets based on further coverage analysis:
// 10. tinyxml2::StrPair::CollapseWhitespace (via XMLDocument constructor option)
// 11. tinyxml2::XMLUtil::SetBoolSerialization
// 12. tinyxml2::XMLElement::SetText(Type) overloads (int, bool, double, etc.)
// 13. tinyxml2::XMLElement::*Attribute(name, defaultValue) overloads
// 14. XMLNode::DeepClone, XMLElement::ShallowClone, and other ShallowClone variants
// 15. XMLDocument::NewComment, NewDeclaration, NewUnknown, NewText
// 16. XMLElement::InsertNewComment, InsertNewDeclaration, InsertNewUnknown, InsertNewText
// 17. XMLNode::ChildElementCount and XMLNode::ChildElementCount(name)
// 18. XMLNode::LastChildElement(name), NextSiblingElement(name), PreviousSiblingElement(name)
// 19. XMLElement::ShallowEqual and other node ShallowEqual methods
// New targets for this enhancement:
// 20. XMLNode::InsertAfterChild and its branches
// 21. ShallowEqual for XMLText, XMLComment, XMLDeclaration, XMLUnknown
// 22. XMLElement::SetAttribute(Type value) overloads (int, bool, double, etc.)
// 23. XMLElement::*Text(defaultValue) functions (IntText, BoolText etc.)
// 24. XMLDocument::DeepCopy
// 25. XMLElement::InsertNewChildElement


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // Use COLLAPSE_WHITESPACE to cover StrPair::CollapseWhitespace during parsing.
    // Also, pass 'true' for processEntities, which is the default.
    std::unique_ptr<tinyxml2::XMLDocument> doc(new tinyxml2::XMLDocument(true, fdp.ConsumeBool() ? tinyxml2::COLLAPSE_WHITESPACE : tinyxml2::PRESERVE_WHITESPACE));

    // Call XMLUtil::SetBoolSerialization to cover this function and test different boolean serializations.
    // Fuzz the true/false strings for bool serialization.
    std::string true_str = fdp.ConsumeRandomLengthString(8);
    std::string false_str = fdp.ConsumeRandomLengthString(8);
    tinyxml2::XMLUtil::SetBoolSerialization(
        fdp.ConsumeBool() ? "true" : true_str.c_str(),
        fdp.ConsumeBool() ? "false" : false_str.c_str()
    );


    // 1. Attempt to parse an XML string from the fuzzer data using XMLDocument::Parse.
    // Consume up to half of the remaining data for parsing to leave data for other operations.
    size_t parse_string_size = fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes() / 2);
    std::string xml_to_parse = fdp.ConsumeBytesAsString(parse_string_size);
    doc->Parse(xml_to_parse.c_str(), xml_to_parse.length()); // size_t for length is correct

    // Get the root element if parsing was successful, or create one.
    tinyxml2::XMLElement *current_element = doc->RootElement();
    if (!current_element) {
        std::string root_name_str = fdp.ConsumeRandomLengthString(32);
        // NewElement requires a non-empty name.
        if (root_name_str.empty()) {
            root_name_str = "defaultRoot";
        }
        current_element = doc->NewElement(root_name_str.c_str());
        if (current_element) {
            doc->InsertFirstChild(current_element); // Add the new root to the document.
        }
    }

    // Proceed with further operations only if we have a valid element to work with.
    if (current_element) {
        // Perform a variable number of operations on the XML document.
        int num_operations = fdp.ConsumeIntegralInRange<int>(1, 20);
        for (int i = 0; i < num_operations; ++i) {
            if (!current_element && fdp.ConsumeIntegralInRange<uint8_t>(0,18) > 12) { // Some new ops don't need current_element
                 // Attempt to re-acquire root if current_element became null and op needs it
                 current_element = doc->RootElement();
                 if (!current_element) { // If still no root, try to create one for subsequent ops
                    std::string temp_root_name = fdp.ConsumeRandomLengthString(10);
                    if(temp_root_name.empty()) temp_root_name = "fallbackRoot";
                    current_element = doc->NewElement(temp_root_name.c_str());
                    if(current_element) doc->InsertFirstChild(current_element);
                    else break; // Cannot proceed if no element can be established
                 }
            } else if (!current_element) { // Break if current_element is null and op needs it
                 break;
            }


            // Choose an operation type. Range extended for new operations.
            // Original ops 0-12. New ops 13-18. Total 19 operations (0-18).
            uint8_t op_type = fdp.ConsumeIntegralInRange<uint8_t>(0, 18);

            switch (op_type) {
                case 0: {
                    // 2. Test XMLDocument::NewElement by creating a new child element.
                    std::string child_name_str = fdp.ConsumeRandomLengthString(32);
                    // NewElement requires a non-empty name.
                    if (child_name_str.empty()) {
                        child_name_str = "defaultChild";
                    }
                    tinyxml2::XMLElement *new_child = doc->NewElement(child_name_str.c_str());
                    if (new_child) {
                        current_element->InsertEndChild(new_child);
                        // Optionally change context to the new child for subsequent operations.
                        if (fdp.ConsumeBool()) {
                            current_element = new_child;
                        }
                    }
                    break;
                }
                case 1: {
                    // 3. Test XMLElement::SetAttribute.
                    std::string attr_name_str = fdp.ConsumeRandomLengthString(32);
                    std::string attr_value_str = fdp.ConsumeRandomLengthString(64);
                    // SetAttribute handles empty names gracefully, but we can be explicit.
                    if (!attr_name_str.empty()) {
                        current_element->SetAttribute(attr_name_str.c_str(), attr_value_str.c_str());
                    }
                    break;
                }
                case 2: {
                    // 4. Test XMLElement::SetText.
                    std::string text_content_str = fdp.ConsumeRandomLengthString(128);
                    current_element->SetText(text_content_str.c_str());
                    break;
                }
                case 3: { // Enhanced navigation to cover more XMLNode navigation functions
                    if (!current_element) break;
                    uint8_t nav_type = fdp.ConsumeIntegralInRange<uint8_t>(0, 5);
                    std::string name_filter_str = fdp.ConsumeRandomLengthString(10);
                    // Use nullptr for name if string is empty to test both named and unnamed variants.
                    const char* name_filter = name_filter_str.empty() ? nullptr : name_filter_str.c_str();

                    tinyxml2::XMLElement* target_element = nullptr;
                    switch (nav_type) {
                        case 0: { // Parent
                            tinyxml2::XMLNode* parent_node = current_element->Parent();
                            if (parent_node) target_element = parent_node->ToElement();
                            break;
                        }
                        case 1: // FirstChildElement (with optional name filter)
                            target_element = current_element->FirstChildElement(name_filter);
                            break;
                        case 2: // LastChildElement (with optional name filter, covers uncovered LastChildElement(name))
                            target_element = current_element->LastChildElement(name_filter);
                            break;
                        case 3: // NextSiblingElement (with optional name filter, covers uncovered NextSiblingElement(name))
                            target_element = current_element->NextSiblingElement(name_filter);
                            break;
                        case 4: // PreviousSiblingElement (with optional name filter, covers uncovered PreviousSiblingElement(name))
                            target_element = current_element->PreviousSiblingElement(name_filter);
                            break;
                        case 5: // Fallback to simple FirstChildElement (no name)
                             target_element = current_element->FirstChildElement();
                             break;
                    }
                    if (target_element) {
                        current_element = target_element;
                    }
                    // If navigation fails, current_element remains the same.
                    break;
                }
                case 4: { // Target XMLElement::DeleteAttribute
                    // Only attempt to delete if an attribute name is generated and attributes might exist.
                    std::string attr_name_to_delete = fdp.ConsumeRandomLengthString(32);
                    if (!attr_name_to_delete.empty() && current_element->FirstAttribute()) {
                        current_element->DeleteAttribute(attr_name_to_delete.c_str());
                    }
                    break;
                }
                case 5: { // Target XMLElement::Query<Type>Attribute functions
                    std::string attr_name_str = fdp.ConsumeRandomLengthString(32);
                    if (!attr_name_str.empty() && current_element->FirstAttribute()) {
                        switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 6)) {
                            case 0: { int val; current_element->QueryIntAttribute(attr_name_str.c_str(), &val); break; }
                            case 1: { unsigned val; current_element->QueryUnsignedAttribute(attr_name_str.c_str(), &val); break; }
                            case 2: { bool val; current_element->QueryBoolAttribute(attr_name_str.c_str(), &val); break; }
                            case 3: { double val; current_element->QueryDoubleAttribute(attr_name_str.c_str(), &val); break; }
                            case 4: { float val; current_element->QueryFloatAttribute(attr_name_str.c_str(), &val); break; }
                            case 5: { int64_t val; current_element->QueryInt64Attribute(attr_name_str.c_str(), &val); break; }
                            case 6: { uint64_t val; current_element->QueryUnsigned64Attribute(attr_name_str.c_str(), &val); break; }
                        }
                    }
                    break;
                }
                case 6: { // Target XMLElement::Query<Type>Text functions and XMLElement::GetText
                    current_element->GetText(); // Call GetText to cover it.
                    if (current_element->FirstChild() && current_element->FirstChild()->ToText()) {
                        switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 6)) {
                            case 0: { int val; current_element->QueryIntText(&val); break; }
                            case 1: { unsigned val; current_element->QueryUnsignedText(&val); break; }
                            case 2: { bool val; current_element->QueryBoolText(&val); break; }
                            case 3: { double val; current_element->QueryDoubleText(&val); break; }
                            case 4: { float val; current_element->QueryFloatText(&val); break; }
                            case 5: { int64_t val; current_element->QueryInt64Text(&val); break; }
                            case 6: { uint64_t val; current_element->QueryUnsigned64Text(&val); break; }
                        }
                    }
                    break;
                }
                case 7: { // Target XMLElement::SetText(Type) overloads to cover them and related XMLUtil::ToStr / XMLPrinter::PushText(Type)
                    if (current_element) {
                        // This covers XMLElement::SetText(Type) and indirectly XMLUtil::ToStr(Type)
                        // and XMLPrinter::PushText(Type) when doc->Print() is called.
                        switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 6)) {
                            case 0: current_element->SetText(fdp.ConsumeIntegral<int>()); break;
                            case 1: current_element->SetText(fdp.ConsumeIntegral<unsigned int>()); break;
                            case 2: current_element->SetText(fdp.ConsumeBool()); break;
                            case 3: current_element->SetText(fdp.ConsumeFloatingPoint<double>()); break;
                            case 4: current_element->SetText(fdp.ConsumeFloatingPoint<float>()); break;
                            case 5: current_element->SetText(fdp.ConsumeIntegral<int64_t>()); break;
                            case 6: current_element->SetText(fdp.ConsumeIntegral<uint64_t>()); break;
                        }
                    }
                    break;
                }
                case 8: { // Target XMLElement::*Attribute(name, defaultValue) overloads for coverage
                    if (current_element) {
                        std::string attr_name_str = fdp.ConsumeRandomLengthString(32);
                        // It's okay for attr_name_str to be empty, functions should handle it.
                        // Calling these functions covers their implementation.
                        switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 6)) {
                            case 0: current_element->IntAttribute(attr_name_str.c_str(), fdp.ConsumeIntegral<int>()); break;
                            case 1: current_element->UnsignedAttribute(attr_name_str.c_str(), fdp.ConsumeIntegral<unsigned int>()); break;
                            case 2: current_element->BoolAttribute(attr_name_str.c_str(), fdp.ConsumeBool()); break;
                            case 3: current_element->DoubleAttribute(attr_name_str.c_str(), fdp.ConsumeFloatingPoint<double>()); break;
                            case 4: current_element->FloatAttribute(attr_name_str.c_str(), fdp.ConsumeFloatingPoint<float>()); break;
                            case 5: current_element->Int64Attribute(attr_name_str.c_str(), fdp.ConsumeIntegral<int64_t>()); break;
                            case 6: current_element->Unsigned64Attribute(attr_name_str.c_str(), fdp.ConsumeIntegral<uint64_t>()); break;
                        }
                    }
                    break;
                }
                case 9: { // Target XMLNode::DeepClone and various ShallowClone methods for coverage
                    if (current_element) {
                        tinyxml2::XMLNode* cloned_node = nullptr;
                        if (fdp.ConsumeBool()) { // Try to clone current_element itself
                            if (fdp.ConsumeBool()) { // Target XMLElement::ShallowClone
                                cloned_node = current_element->ShallowClone(doc.get());
                            } else { // Target XMLNode::DeepClone (XMLElement inherits from XMLNode)
                                cloned_node = current_element->DeepClone(doc.get());
                            }
                        } else { // Try to clone a child node of a specific type
                            tinyxml2::XMLNode* child_node_to_clone = current_element->FirstChild();
                            if (child_node_to_clone) {
                                // Attempt to clone specific types of children to cover their ShallowClone
                                if (child_node_to_clone->ToText() && fdp.ConsumeBool()) {
                                     cloned_node = child_node_to_clone->ToText()->ShallowClone(doc.get());
                                } else if (child_node_to_clone->ToComment() && fdp.ConsumeBool()) {
                                     cloned_node = child_node_to_clone->ToComment()->ShallowClone(doc.get());
                                } else if (child_node_to_clone->ToDeclaration() && fdp.ConsumeBool()) {
                                     cloned_node = child_node_to_clone->ToDeclaration()->ShallowClone(doc.get());
                                } else if (child_node_to_clone->ToUnknown() && fdp.ConsumeBool()) {
                                     cloned_node = child_node_to_clone->ToUnknown()->ShallowClone(doc.get());
                                } else if (child_node_to_clone->ToElement()) { // Fallback to XMLElement if others not picked
                                     cloned_node = child_node_to_clone->ToElement()->ShallowClone(doc.get());
                                }
                            }
                        }

                        if (cloned_node) {
                            // Cloned node is owned by 'doc'. To prevent it from altering the main structure
                            // or causing issues if not properly integrated, delete it.
                            // This ensures memory safety for the cloned node.
                            doc->DeleteNode(cloned_node);
                        }
                    }
                    break;
                }
                case 10: { // Target XMLDocument::New{Comment,Decl,Unknown,Text} and XMLElement::InsertNew{Comment,Decl,Unknown,Text}
                    std::string content = fdp.ConsumeRandomLengthString(32);
                    if (content.empty() && fdp.ConsumeBool()) content = "fuzzDefault"; // Ensure non-empty content sometimes

                    if (fdp.ConsumeBool() && current_element) { // Use XMLElement::InsertNew...
                        // These functions create and insert the node, memory is managed by the document.
                        switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 3)) {
                            case 0: current_element->InsertNewComment(content.c_str()); break;
                            case 1: current_element->InsertNewDeclaration(content.c_str()); break;
                            case 2: current_element->InsertNewUnknown(content.c_str()); break;
                            case 3: current_element->InsertNewText(content.c_str()); break;
                        }
                    } else { // Use XMLDocument::New... and then insert
                        tinyxml2::XMLNode* new_node = nullptr;
                        uint8_t node_type = fdp.ConsumeIntegralInRange<uint8_t>(0, 3);
                        switch (node_type) {
                            case 0: new_node = doc->NewComment(content.c_str()); break;
                            case 1: new_node = doc->NewDeclaration(content.c_str()); break;
                            case 2: new_node = doc->NewUnknown(content.c_str()); break;
                            case 3: new_node = doc->NewText(content.c_str()); break;
                        }

                        if (new_node) {
                            tinyxml2::XMLNode* inserted_node_ptr = nullptr;
                            // Decide where and how to insert
                            if (new_node->ToDeclaration()) { // Declarations usually go first in the document
                                inserted_node_ptr = doc->InsertFirstChild(new_node);
                            } else if (current_element && fdp.ConsumeBool()) { // Insert into current_element
                                inserted_node_ptr = current_element->InsertEndChild(new_node);
                            } else { // Insert into document
                                inserted_node_ptr = doc->InsertEndChild(new_node);
                            }
                            
                            // If insertion failed, the node created by NewComment/NewText etc. must be deleted.
                            // A node created by doc->New... is owned by the doc's pool but not in the tree yet.
                            // If Insert...Child fails, it returns nullptr and the node remains unparented.
                            if (!inserted_node_ptr) {
                                doc->DeleteNode(new_node); // Memory safety: delete uninserted node.
                            }
                        }
                    }
                    break;
                }
                case 11: { // Target XMLNode::ChildElementCount and ChildElementCount(name) for coverage
                    if (current_element) {
                        if (fdp.ConsumeBool()) {
                            current_element->ChildElementCount(); // Call overload without name
                        } else {
                            std::string child_name_str = fdp.ConsumeRandomLengthString(10);
                            // Call overload with name (can be empty string, function should handle)
                            current_element->ChildElementCount(child_name_str.c_str());
                        }
                    }
                    break;
                }
                case 12: { // Target XMLElement::ShallowEqual (and other node types' ShallowEqual)
                    if (current_element) {
                        tinyxml2::XMLNode* compare_target = nullptr;
                        uint8_t choice = fdp.ConsumeIntegralInRange<uint8_t>(0,3);
                        if (choice == 0 && current_element->FirstChild()) {
                            compare_target = current_element->FirstChild();
                        } else if (choice == 1 && current_element->NextSibling()) {
                            compare_target = current_element->NextSibling();
                        } else if (choice == 2 && doc->RootElement() && doc->RootElement() != current_element) {
                            compare_target = doc->RootElement();
                        } else { // Fallback: create a temporary element for comparison
                            std::string temp_name = fdp.ConsumeRandomLengthString(10);
                            if (temp_name.empty()) temp_name = "tempCompareElem";
                            tinyxml2::XMLElement* temp_element = doc->NewElement(temp_name.c_str());
                            if (temp_element) {
                                current_element->ShallowEqual(temp_element); // Call ShallowEqual
                                // temp_element is not inserted, so it must be deleted.
                                doc->DeleteNode(temp_element); // Memory safety: delete temporary node.
                            }
                            break; 
                        }

                        if (compare_target) {
                            // This will call the appropriate ShallowEqual based on current_element's actual type
                            current_element->ShallowEqual(compare_target);
                        }
                    }
                    break;
                }
                // --- Start of new operations for enhanced coverage ---
                case 13: { // Target ShallowEqual for XMLText, XMLComment, XMLDeclaration, XMLUnknown
                    tinyxml2::XMLNode* node1 = nullptr;
                    tinyxml2::XMLNode* node2 = nullptr;
                    std::string content1 = fdp.ConsumeRandomLengthString(20);
                    std::string content2 = fdp.ConsumeRandomLengthString(20);

                    uint8_t node_type_choice = fdp.ConsumeIntegralInRange<uint8_t>(0, 3);
                    switch (node_type_choice) {
                        case 0: // XMLText
                            node1 = doc->NewText(content1.c_str());
                            node2 = doc->NewText(content2.c_str());
                            break;
                        case 1: // XMLComment
                            node1 = doc->NewComment(content1.c_str());
                            node2 = doc->NewComment(content2.c_str());
                            break;
                        case 2: // XMLDeclaration
                            node1 = doc->NewDeclaration(content1.c_str());
                            node2 = doc->NewDeclaration(content2.c_str());
                            break;
                        case 3: // XMLUnknown
                            node1 = doc->NewUnknown(content1.c_str());
                            node2 = doc->NewUnknown(content2.c_str());
                            break;
                    }

                    if (node1 && node2) {
                        node1->ShallowEqual(node2); // Call ShallowEqual to cover specific type implementations.
                        // Nodes are owned by the doc's memory pool. Delete them as they are not inserted into the tree.
                        doc->DeleteNode(node1); // Memory safety.
                        doc->DeleteNode(node2); // Memory safety.
                    } else { // Handle cases where New... might have failed (e.g. OOM, though unlikely for small strings)
                        if (node1) doc->DeleteNode(node1);
                        if (node2) doc->DeleteNode(node2);
                    }
                    break;
                }
                case 14: { // Target XMLElement::SetAttribute(<Type> value) overloads
                    if (current_element) {
                        std::string attr_name = fdp.ConsumeRandomLengthString(16);
                        if (attr_name.empty()) attr_name = "typedAttr"; // Ensure name is not empty for predictability

                        uint8_t type_choice = fdp.ConsumeIntegralInRange<uint8_t>(0, 6);
                        switch (type_choice) { // These calls cover XMLElement::SetAttribute(Type) and XMLAttribute::SetAttribute(Type)
                            case 0: current_element->SetAttribute(attr_name.c_str(), fdp.ConsumeIntegral<int>()); break;
                            case 1: current_element->SetAttribute(attr_name.c_str(), fdp.ConsumeIntegral<unsigned int>()); break;
                            case 2: current_element->SetAttribute(attr_name.c_str(), fdp.ConsumeBool()); break;
                            case 3: current_element->SetAttribute(attr_name.c_str(), fdp.ConsumeFloatingPoint<double>()); break;
                            case 4: current_element->SetAttribute(attr_name.c_str(), fdp.ConsumeFloatingPoint<float>()); break;
                            case 5: current_element->SetAttribute(attr_name.c_str(), fdp.ConsumeIntegral<int64_t>()); break;
                            case 6: current_element->SetAttribute(attr_name.c_str(), fdp.ConsumeIntegral<uint64_t>()); break;
                        }
                    }
                    break;
                }
                case 15: { // Target XMLElement::<Type>Text(defaultValue) functions
                    if (current_element) {
                        // These functions get the text, convert to type, or return defaultValue. Covers XMLElement::*Text(defVal).
                        uint8_t type_choice = fdp.ConsumeIntegralInRange<uint8_t>(0, 6);
                        switch (type_choice) {
                            case 0: (void)current_element->IntText(fdp.ConsumeIntegral<int>()); break;
                            case 1: (void)current_element->UnsignedText(fdp.ConsumeIntegral<unsigned int>()); break;
                            case 2: (void)current_element->BoolText(fdp.ConsumeBool()); break;
                            case 3: (void)current_element->DoubleText(fdp.ConsumeFloatingPoint<double>()); break;
                            case 4: (void)current_element->FloatText(fdp.ConsumeFloatingPoint<float>()); break;
                            case 5: (void)current_element->Int64Text(fdp.ConsumeIntegral<int64_t>()); break;
                            case 6: (void)current_element->Unsigned64Text(fdp.ConsumeIntegral<uint64_t>()); break;
                        }
                    }
                    break;
                }
                case 16: { // Target XMLDocument::DeepCopy
                    // Create a new document to copy into.
                    std::unique_ptr<tinyxml2::XMLDocument> target_doc(new tinyxml2::XMLDocument(
                        fdp.ConsumeBool(), // processEntities for target
                        fdp.PickValueInArray({tinyxml2::PRESERVE_WHITESPACE, tinyxml2::COLLAPSE_WHITESPACE}) // whitespaceMode for target
                    ));
                    doc->DeepCopy(target_doc.get()); // Perform the deep copy.
                    // target_doc and its copied content are managed by unique_ptr and cleaned up automatically.
                    // This covers XMLDocument::DeepCopy.
                    break;
                }
                case 17: { // Target XMLElement::InsertNewChildElement
                    if (current_element) {
                        std::string name = fdp.ConsumeRandomLengthString(16);
                        if (name.empty()) name = "insertedChildElem"; // Ensure name for predictability
                        tinyxml2::XMLElement* new_elem = current_element->InsertNewChildElement(name.c_str());
                        // new_elem is managed by the document if successfully inserted.
                        // If fdp.ConsumeBool() is true, switch context to the new element.
                        if (new_elem && fdp.ConsumeBool()) {
                            current_element = new_elem;
                        }
                    }
                    break;
                }
                case 18: { // Target XMLNode::InsertAfterChild and its branches
                    tinyxml2::XMLElement* parent_for_iac = current_element ? current_element->ToElement() : nullptr;
                    if (!parent_for_iac) { // Ensure parent_for_iac is a valid XMLElement
                        std::string pname = fdp.ConsumeRandomLengthString(10);
                        if (pname.empty()) pname = "iacParent";
                        parent_for_iac = doc->NewElement(pname.c_str());
                        if (parent_for_iac) doc->InsertEndChild(parent_for_iac); // Add to doc to be a valid parent
                        else break; 
                    }

                    std::string c1_name_str = fdp.ConsumeRandomLengthString(10);
                    if (c1_name_str.empty()) c1_name_str = "iac_c1";
                    tinyxml2::XMLElement* c1_after_this = doc->NewElement(c1_name_str.c_str());
                    if (!c1_after_this) break;
                    parent_for_iac->InsertEndChild(c1_after_this); // c1_after_this is now a child of parent_for_iac

                    std::string c2_name_str = fdp.ConsumeRandomLengthString(10);
                    if (c2_name_str.empty()) c2_name_str = "iac_c2";
                    
                    tinyxml2::XMLNode* inserted_node_iac = nullptr;
                    uint8_t iac_scenario = fdp.ConsumeIntegralInRange<uint8_t>(0, 4);

                    if (iac_scenario == 0) { // Normal insert (c1_after_this might be last or have siblings)
                        tinyxml2::XMLElement* c2_add_this = doc->NewElement(c2_name_str.c_str());
                        if (c2_add_this) {
                            inserted_node_iac = parent_for_iac->InsertAfterChild(c1_after_this, c2_add_this);
                            if (!inserted_node_iac) doc->DeleteNode(c2_add_this); // Memory safety if insertion failed
                        }
                    } else if (iac_scenario == 1) { // afterThis == addThis (insert c1_after_this after itself)
                        inserted_node_iac = parent_for_iac->InsertAfterChild(c1_after_this, c1_after_this); // Should be no-op or return c1
                    } else if (iac_scenario == 2) { // afterThis->_parent != this
                        tinyxml2::XMLElement* other_parent_iac = doc->NewElement("iacOtherParent");
                        tinyxml2::XMLElement* c2_add_this = doc->NewElement(c2_name_str.c_str());
                        if (other_parent_iac && c2_add_this) {
                            doc->InsertEndChild(other_parent_iac); // Add other_parent_iac to the document
                            // c1_after_this is child of parent_for_iac. Try to insert c2_add_this into other_parent_iac after c1_after_this.
                            inserted_node_iac = other_parent_iac->InsertAfterChild(c1_after_this, c2_add_this); // This should hit assert path.
                            if (!inserted_node_iac) doc->DeleteNode(c2_add_this);
                        } else {
                            if (other_parent_iac) doc->DeleteNode(other_parent_iac);
                            if (c2_add_this) doc->DeleteNode(c2_add_this);
                        }
                    } else if (iac_scenario == 3) { // addThis->_document != _document
                        std::unique_ptr<tinyxml2::XMLDocument> other_doc_for_iac(new tinyxml2::XMLDocument());
                        tinyxml2::XMLElement* c2_other_doc_node = other_doc_for_iac->NewElement(c2_name_str.c_str());
                        if (c2_other_doc_node) {
                            // Try to insert node from other_doc_for_iac into parent_for_iac (in main doc).
                            inserted_node_iac = parent_for_iac->InsertAfterChild(c1_after_this, c2_other_doc_node); // Should hit assert path.
                            // c2_other_doc_node is managed by other_doc_for_iac, no deletion from main doc needed.
                        }
                    } else { // Default: c1_after_this is last child, insert c2_add_this after it.
                        tinyxml2::XMLElement* c2_add_this = doc->NewElement(c2_name_str.c_str());
                         if (c2_add_this) {
                            inserted_node_iac = parent_for_iac->InsertAfterChild(c1_after_this, c2_add_this);
                            if (!inserted_node_iac) doc->DeleteNode(c2_add_this);
                        }
                    }
                    // c1_after_this is managed as it was inserted into parent_for_iac.
                    // Other created nodes are either inserted and managed, or deleted if not inserted/insertion failed.
                    break;
                }
            }
        }
    }

    // 5. Test XMLDocument::Print using XMLPrinter.
    tinyxml2::XMLPrinter printer(nullptr, fdp.ConsumeBool()); // Fuzz compact mode for printer
    doc->Print(&printer);
    // XMLPrinter is stack-allocated and manages its own buffer if not given a FILE*.
    // This is memory-safe.

    // XMLDocument 'doc' and all its nodes are deallocated when 'doc' (unique_ptr) goes out of scope.
    return 0;
}