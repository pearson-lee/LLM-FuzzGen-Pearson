#include "/src/tinyxml2/tinyxml2.h" // Project-relative path for tinyxml2
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <memory>   // For std::unique_ptr
#include <cstddef>  // For size_t
#include <cstdint>  // For uint8_t
#include <cstdio>   // For FILE, tmpfile, fwrite, rewind, fclose (for LoadFile/SaveFile coverage)

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
// 20. XMLNode::InsertAfterChild
// 21. XMLText::ShallowEqual, XMLComment::ShallowEqual, XMLDeclaration::ShallowEqual, XMLUnknown::ShallowEqual
// 22. XMLElement::SetAttribute(name, Type) and XMLAttribute::SetAttribute(Type) for various types
// 23. XMLElement::*Text(defaultValue) for various types
// 24. XMLDocument::ErrorStr, XMLDocument::PrintError, XMLDocument::ErrorName
// 25. XMLDocument::DeepCopy
// 26. XMLElement::InsertNewChildElement
// 27. XMLDocument::LoadFile(FILE*), XMLDocument::SaveFile(FILE*, bool)
// 28. XMLPrinter::PushAttribute(Type), XMLPrinter::PushText(Type)

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // Use COLLAPSE_WHITESPACE to cover StrPair::CollapseWhitespace during parsing.
    // Also, pass 'true' for processEntities, which is the default.
    std::unique_ptr<tinyxml2::XMLDocument> doc(new tinyxml2::XMLDocument(true, tinyxml2::COLLAPSE_WHITESPACE));

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
    
    // Input with numeric character entities (e.g., &#123; or &#xABC;) is needed to cover XMLUtil::ConvertUTF32ToUTF8.
    // FuzzedDataProvider may generate such inputs naturally. If coverage for ConvertUTF32ToUTF8 remains low,
    // explicit injection of entities could be considered, but is omitted for now to keep changes minimal.

    doc->Parse(xml_to_parse.c_str(), xml_to_parse.length()); // size_t for length is correct

    // START MODIFICATION: Call error functions to improve their coverage.
    // These functions are safe to call even if no error occurred.
    doc->ErrorStr();  // Target XMLDocument::ErrorStr
    doc->ErrorName(); // Target XMLDocument::ErrorName
    if (fdp.ConsumeIntegralInRange(0, 3) == 0) { // Call PrintError sometimes (1 in 4 chance) to avoid excessive fuzzer log noise.
       doc->PrintError(); // Target XMLDocument::PrintError
    }
    // END MODIFICATION

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
            if (!current_element && !(doc->FirstChild())) { // Safety check: ensure there's some node to work on, or break.
                                                          // current_element might become null after some ops (e.g. LoadFile)
                current_element = doc->RootElement(); // Try to re-acquire root
                if (!current_element) { // If still no root, try to create one for subsequent ops
                    std::string temp_root_name = fdp.ConsumeRandomLengthString(10);
                    if(temp_root_name.empty()) temp_root_name = "fallbackRoot";
                    current_element = doc->NewElement(temp_root_name.c_str());
                    if(current_element) doc->InsertFirstChild(current_element);
                    else break; // If cannot create a root, stop operations.
                }
            }


            // Choose an operation type. Range extended for new operations.
            // Original ops 0-12. New ops 13-20. Total 21 operations (0-20).
            uint8_t op_type = fdp.ConsumeIntegralInRange<uint8_t>(0, 20);

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
                        if (current_element) current_element->InsertEndChild(new_child);
                        else doc->InsertEndChild(new_child); // Insert to doc if current_element is null

                        // Optionally change context to the new child for subsequent operations.
                        if (fdp.ConsumeBool()) {
                            current_element = new_child;
                        }
                    }
                    break;
                }
                case 1: {
                    // 3. Test XMLElement::SetAttribute.
                    if (!current_element) break;
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
                    if (!current_element) break;
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
                    if (!current_element) break;
                    // Only attempt to delete if an attribute name is generated and attributes might exist.
                    std::string attr_name_to_delete = fdp.ConsumeRandomLengthString(32);
                    if (!attr_name_to_delete.empty() && current_element->FirstAttribute()) {
                        current_element->DeleteAttribute(attr_name_to_delete.c_str());
                    }
                    break;
                }
                case 5: { // Target XMLElement::Query<Type>Attribute functions
                    if (!current_element) break;
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
                    if (!current_element) break;
                    current_element->GetText();
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
                    if (current_element) { // Ensure current_element is valid
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
                                } else { // Fallback: clone the child_node_to_clone itself if it's not one of the above specific types or if bool was false
                                     cloned_node = child_node_to_clone->ShallowClone(doc.get());
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
                // START MODIFICATION: Enhanced ShallowEqual to cover various node types
                case 12: { // Target XMLElement::ShallowEqual and other node types' ShallowEqual (XMLText, XMLComment, etc.)
                    tinyxml2::XMLNode* node1 = nullptr;
                    tinyxml2::XMLNode* node2 = nullptr;

                    // Choose a type for the nodes to be compared
                    uint8_t node_type_choice = fdp.ConsumeIntegralInRange<uint8_t>(0, 4); // 0:Elem, 1:Text, 2:Comment, 3:Decl, 4:Unknown
                    std::string val1 = fdp.ConsumeRandomLengthString(20);
                    if (val1.empty()) val1 = "sE_val1";

                    switch (node_type_choice) {
                        case 0: node1 = doc->NewElement(val1.c_str()); break;
                        case 1: node1 = doc->NewText(val1.c_str()); break;
                        case 2: node1 = doc->NewComment(val1.c_str()); break;
                        case 3: node1 = doc->NewDeclaration(val1.c_str()); break;
                        case 4: node1 = doc->NewUnknown(val1.c_str()); break;
                    }

                    if (node1) {
                        std::string val2 = fdp.ConsumeBool() ? val1 : fdp.ConsumeRandomLengthString(20);
                        if (val2.empty() && val1 != val2) val2 = "sE_val2_diff"; // Ensure different if intended
                        else if (val2.empty()) val2 = val1; // Ensure same if intended or val1 was empty

                        switch (node_type_choice) { // Create another node of the same type for comparison
                            case 0: node2 = doc->NewElement(val2.c_str()); break;
                            case 1: node2 = doc->NewText(val2.c_str()); break;
                            case 2: node2 = doc->NewComment(val2.c_str()); break;
                            case 3: node2 = doc->NewDeclaration(val2.c_str()); break;
                            case 4: node2 = doc->NewUnknown(val2.c_str()); break;
                        }

                        if (node2) {
                            node1->ShallowEqual(node2); // Test ShallowEqual for the chosen node type
                            doc->DeleteNode(node2);     // Memory safety: delete temporary node2 as it's not inserted
                        }

                        // Optionally, compare node1 with current_element if it exists
                        if (current_element) {
                            node1->ShallowEqual(current_element);
                        }
                        doc->DeleteNode(node1); // Memory safety: delete temporary node1 as it's not inserted
                    }
                    break;
                }
                // END MODIFICATION

                // START MODIFICATION: Add new operations to cover more APIs
                case 13: { // Target XMLNode::InsertAfterChild
                    if (current_element && current_element->FirstChild()) {
                        tinyxml2::XMLNode* after_this_node = current_element->FirstChild();
                        // Optionally pick a later sibling to insert after
                        if (fdp.ConsumeBool() && after_this_node->NextSibling()) {
                            after_this_node = after_this_node->NextSibling();
                        }

                        std::string new_elem_name = fdp.ConsumeRandomLengthString(16);
                        if (new_elem_name.empty()) new_elem_name = "insertedAfterElem";
                        tinyxml2::XMLElement* add_this_elem = doc->NewElement(new_elem_name.c_str());

                        if (add_this_elem) {
                            tinyxml2::XMLNode* inserted_node = current_element->InsertAfterChild(after_this_node, add_this_elem);
                            if (!inserted_node) {
                                // Insertion failed, add_this_elem is not in the tree. Delete it.
                                doc->DeleteNode(add_this_elem); // Memory safety for uninserted node
                            }
                            // If successful, inserted_node == add_this_elem, and it's managed by the document.
                        }
                    }
                    break;
                }
                case 14: { // Target XMLElement::SetAttribute(name, Type) and XMLAttribute::SetAttribute(Type)
                    if (current_element) {
                        std::string attr_name = fdp.ConsumeRandomLengthString(32);
                        if (attr_name.empty()) attr_name = "typedAttrExample";

                        uint8_t type_choice = fdp.ConsumeIntegralInRange<uint8_t>(0, 6);
                        switch (type_choice) {
                            case 0: current_element->SetAttribute(attr_name.c_str(), fdp.ConsumeIntegral<int>()); break;
                            case 1: current_element->SetAttribute(attr_name.c_str(), fdp.ConsumeIntegral<unsigned int>()); break;
                            case 2: current_element->SetAttribute(attr_name.c_str(), fdp.ConsumeBool()); break;
                            case 3: current_element->SetAttribute(attr_name.c_str(), fdp.ConsumeFloatingPoint<double>()); break;
                            case 4: current_element->SetAttribute(attr_name.c_str(), fdp.ConsumeFloatingPoint<float>()); break;
                            case 5: current_element->SetAttribute(attr_name.c_str(), fdp.ConsumeIntegral<int64_t>()); break;
                            case 6: current_element->SetAttribute(attr_name.c_str(), fdp.ConsumeIntegral<uint64_t>()); break;
                        }
                        // This covers XMLElement::SetAttribute(name, Type), which internally calls
                        // XMLAttribute::SetAttribute(Type). Also helps cover XMLPrinter::PushAttribute(name, Type)
                        // when doc->Print() is called later, as the attribute value is typed.
                    }
                    break;
                }
                case 15: { // Target XMLElement::<Type>Text(defaultValue) getter methods
                    if (current_element) {
                        uint8_t type_choice = fdp.ConsumeIntegralInRange<uint8_t>(0, 6);
                        switch (type_choice) {
                            case 0: current_element->IntText(fdp.ConsumeIntegral<int>()); break;
                            case 1: current_element->UnsignedText(fdp.ConsumeIntegral<unsigned int>()); break;
                            case 2: current_element->BoolText(fdp.ConsumeBool()); break;
                            case 3: current_element->DoubleText(fdp.ConsumeFloatingPoint<double>()); break;
                            case 4: current_element->FloatText(fdp.ConsumeFloatingPoint<float>()); break;
                            case 5: current_element->Int64Text(fdp.ConsumeIntegral<int64_t>()); break;
                            case 6: current_element->Unsigned64Text(fdp.ConsumeIntegral<uint64_t>()); break;
                        }
                    }
                    break;
                }
                case 16: { // Target XMLDocument::DeepCopy
                    std::unique_ptr<tinyxml2::XMLDocument> doc_copy(new tinyxml2::XMLDocument(
                        fdp.ConsumeBool(), // processEntities
                        fdp.PickValueInArray({tinyxml2::PRESERVE_WHITESPACE, tinyxml2::COLLAPSE_WHITESPACE}) // whitespaceMode
                    ));
                    if (doc_copy) {
                        doc->DeepCopy(doc_copy.get()); // Perform the deep copy.
                        // doc_copy and its contents are managed by its unique_ptr and automatically cleaned up.
                    }
                    break;
                }
                case 17: { // Target XMLElement::InsertNewChildElement
                    if (current_element) {
                        std::string child_name_str = fdp.ConsumeRandomLengthString(32);
                        if (child_name_str.empty()) {
                            child_name_str = "defaultNewChildViaInsert";
                        }
                        tinyxml2::XMLElement* new_child = current_element->InsertNewChildElement(child_name_str.c_str());
                        // new_child is managed by the document if successfully created and inserted.
                        if (new_child && fdp.ConsumeBool()) { // Optionally switch context
                            current_element = new_child;
                        }
                    }
                    break;
                }
                case 18: { // Target XMLDocument::LoadFile(FILE*)
                    std::string data_to_load = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0,1024));
                    FILE* temp_fp = tmpfile(); // Creates a temporary file, opened in "wb+" mode.
                    if (temp_fp) {
                        if (!data_to_load.empty()) { // fwrite might behave unexpectedly with size 0 on some platforms
                           fwrite(data_to_load.data(), 1, data_to_load.size(), temp_fp);
                        }
                        rewind(temp_fp); // Seek to beginning for reading.
                        
                        // LoadFile clears the document.
                        doc->LoadFile(temp_fp); // Target API call
                        fclose(temp_fp); // Closes and automatically deletes the temporary file.

                        // After LoadFile, current_element might be invalid or doc empty.
                        // Re-establish current_element for subsequent operations.
                        current_element = doc->RootElement();
                        if (!current_element) {
                            std::string root_name_str = fdp.ConsumeRandomLengthString(32);
                            if (root_name_str.empty()) root_name_str = "defaultRootPostLoad";
                            current_element = doc->NewElement(root_name_str.c_str());
                            if (current_element) doc->InsertFirstChild(current_element);
                        }
                    }
                    break;
                }
                case 19: { // Target XMLDocument::SaveFile(FILE*, bool)
                    FILE* temp_fp = tmpfile(); // Creates a temporary file.
                    if (temp_fp) {
                        doc->SaveFile(temp_fp, fdp.ConsumeBool()); // Target API call
                        fclose(temp_fp); // Closes and automatically deletes the temporary file.
                    }
                    break;
                }
                case 20: { // Target XMLPrinter typed PushAttribute and PushText methods
                    tinyxml2::XMLPrinter local_printer(nullptr, fdp.ConsumeBool()); // Use internal buffer, fuzz compact mode

                    // XMLPrinter::PushAttribute(name, Type)
                    std::string pa_name = fdp.ConsumeRandomLengthString(10);
                    if (pa_name.empty()) pa_name = "pa"; // Ensure non-empty name for attribute
                    switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 5)) {
                        case 0: local_printer.PushAttribute(pa_name.c_str(), fdp.ConsumeIntegral<int>()); break;
                        case 1: local_printer.PushAttribute(pa_name.c_str(), fdp.ConsumeIntegral<unsigned int>()); break;
                        case 2: local_printer.PushAttribute(pa_name.c_str(), fdp.ConsumeIntegral<int64_t>()); break;
                        case 3: local_printer.PushAttribute(pa_name.c_str(), fdp.ConsumeIntegral<uint64_t>()); break;
                        case 4: local_printer.PushAttribute(pa_name.c_str(), fdp.ConsumeBool()); break;
                        case 5: local_printer.PushAttribute(pa_name.c_str(), fdp.ConsumeFloatingPoint<double>()); break;
                    }

                    // XMLPrinter::PushText(Type)
                    switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 6)) {
                        case 0: local_printer.PushText(fdp.ConsumeIntegral<int>()); break;
                        case 1: local_printer.PushText(fdp.ConsumeIntegral<unsigned int>()); break;
                        case 2: local_printer.PushText(fdp.ConsumeIntegral<int64_t>()); break;
                        case 3: local_printer.PushText(fdp.ConsumeIntegral<uint64_t>()); break;
                        case 4: local_printer.PushText(fdp.ConsumeBool()); break;
                        case 5: local_printer.PushText(fdp.ConsumeFloatingPoint<float>()); break;
                        case 6: local_printer.PushText(fdp.ConsumeFloatingPoint<double>()); break;
                    }
                    // local_printer is stack-allocated and manages its own buffer if not given a FILE*.
                    // Its CStr() could be used, but here we just call methods for coverage.
                    break;
                }
                // END MODIFICATION
            }
        }
    }

    // 5. Test XMLDocument::Print using XMLPrinter.
    tinyxml2::XMLPrinter printer;
    doc->Print(&printer);
    // XMLPrinter is stack-allocated and manages its own buffer if not given a FILE*.
    // This is memory-safe.

    // XMLDocument 'doc' and all its nodes are deallocated when 'doc' (unique_ptr) goes out of scope.
    return 0;
}