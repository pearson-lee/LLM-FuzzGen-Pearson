#include "/src/tinyxml2/tinyxml2.h" // Project-relative path for tinyxml2
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <memory>   // For std::unique_ptr
#include <cstddef>  // For size_t
#include <cstdint>  // For uint8_t
#include <cstdio>   // For FILE, tmpfile, fwrite, rewind, fclose, fopen, remove (for LoadFile/SaveFile coverage)
#include <sstream>  // For std::stringstream (for character entity generation)
#include <vector>   // For std::vector if needed by FuzzedDataProvider helpers, though not directly used here

// Target APIs: (original list for context, not all are 0% coverage now)
// ... (original list omitted for brevity in thought process, but kept in mind) ...
// New targets for this enhancement iteration are based on 0% coverage lines:
// - XMLVisitor base virtual methods (VisitEnter, VisitExit, Visit for various node types)
// - XMLPrinter::Print(const char* format, ...) and its internal calls like TIXML_VSCPRINTF
// - XMLPrinter buffer methods: CStr(), CStrSize(), ClearBuffer()
// - XMLAttribute::*Value() methods (IntValue, BoolValue, etc.) and XMLAttribute::GetLineNum()
// - XMLElement::QueryStringAttribute
// - Various XMLNode utility methods: GetLineNum(), NoChildren(), LastChild(), PreviousSibling(), SetUserData(), GetUserData(), GetDocument()
// - Various XMLDocument utility methods: ToDocument(), ErrorID(), ErrorLineNum(), ShallowClone(), ShallowEqual()
// - XMLHandle and XMLConstHandle usage

// START MODIFICATION: Custom XMLVisitor to target base class implementations.
// By not overriding all virtual methods, we ensure that the base XMLVisitor's
// methods are called for those specific node types or events.
class CoverMyVisitor : public tinyxml2::XMLVisitor {
public:
    virtual ~CoverMyVisitor() {}

    // Explicitly call base or provide minimal override for some methods
    virtual bool VisitEnter(const tinyxml2::XMLDocument& doc) override {
        (void)doc; // Suppress unused parameter warning
        return tinyxml2::XMLVisitor::VisitEnter(doc);
    }

    virtual bool VisitExit(const tinyxml2::XMLDocument& doc) override {
        (void)doc;
        return tinyxml2::XMLVisitor::VisitExit(doc);
    }

    // INTENTIONALLY NOT OVERRIDING:
    // virtual bool VisitEnter( const tinyxml2::XMLElement& element, const tinyxml2::XMLAttribute* firstAttribute )
    // This will cause XMLVisitor::VisitEnter(XMLElement, XMLAttribute) to be called.

    virtual bool VisitExit(const tinyxml2::XMLElement& element) override {
        (void)element; // Suppress unused parameter warning
        return tinyxml2::XMLVisitor::VisitExit(element);
    }

    virtual bool Visit(const tinyxml2::XMLDeclaration& declaration) override {
        (void)declaration; // Suppress unused parameter warning
        return tinyxml2::XMLVisitor::Visit(declaration);
    }

    // INTENTIONALLY NOT OVERRIDING:
    // virtual bool Visit( const tinyxml2::XMLText& text )
    // This will cause XMLVisitor::Visit(XMLText) to be called.

    virtual bool Visit(const tinyxml2::XMLComment& comment) override {
        (void)comment; // Suppress unused parameter warning
        return tinyxml2::XMLVisitor::Visit(comment);
    }

    // INTENTIONALLY NOT OVERRIDING:
    // virtual bool Visit( const tinyxml2::XMLUnknown& unknown )
    // This will cause XMLVisitor::Visit(XMLUnknown) to be called.
};
// END MODIFICATION

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    std::unique_ptr<tinyxml2::XMLDocument> doc(new tinyxml2::XMLDocument(true, tinyxml2::COLLAPSE_WHITESPACE));

    std::string true_str = fdp.ConsumeRandomLengthString(8);
    std::string false_str = fdp.ConsumeRandomLengthString(8);
    tinyxml2::XMLUtil::SetBoolSerialization(
        fdp.ConsumeBool() ? "true" : true_str.c_str(),
        fdp.ConsumeBool() ? "false" : false_str.c_str()
    );

    size_t initial_parse_chunk_size = fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes() / 3);
    std::string xml_to_parse = fdp.ConsumeBytesAsString(initial_parse_chunk_size);

    if (fdp.ConsumeBool() && fdp.remaining_bytes() > 30) {
        std::string entity_str;
        uint32_t char_val = fdp.ConsumeIntegralInRange<uint32_t>(1, 0x1FFFFF);
        if (fdp.ConsumeBool()) {
            entity_str = "&#" + std::to_string(char_val) + ";";
        } else {
            std::stringstream ss_hex;
            ss_hex << std::hex << char_val;
            entity_str = "&#x" + ss_hex.str() + ";";
        }
        xml_to_parse += entity_str;
    }

    size_t final_parse_chunk_size = fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes() / 2);
    xml_to_parse += fdp.ConsumeBytesAsString(final_parse_chunk_size);

    doc->Parse(xml_to_parse.c_str(), xml_to_parse.length());

    doc->ErrorStr();
    doc->ErrorName();
    if (fdp.ConsumeIntegralInRange(0, 3) == 0) {
       doc->PrintError();
    }

    tinyxml2::XMLElement *current_element = doc->RootElement();
    if (!current_element) {
        std::string root_name_str = fdp.ConsumeRandomLengthString(32);
        if (root_name_str.empty()) {
            root_name_str = "defaultRoot";
        }
        current_element = doc->NewElement(root_name_str.c_str());
        if (current_element) {
            doc->InsertFirstChild(current_element);
        }
    }

    if (current_element) {
        // START MODIFICATION: Extended op_type range for new operations.
        int num_operations = fdp.ConsumeIntegralInRange<int>(1, 25); // Increased upper bound for more ops
        for (int i = 0; i < num_operations; ++i) {
            if (!current_element && !(doc->FirstChild())) {
                current_element = doc->RootElement();
                if (!current_element) {
                    std::string temp_root_name = fdp.ConsumeRandomLengthString(10);
                    if(temp_root_name.empty()) temp_root_name = "fallbackRoot";
                    current_element = doc->NewElement(temp_root_name.c_str());
                    if(current_element) doc->InsertFirstChild(current_element);
                    else break;
                }
            }

            uint8_t op_type = fdp.ConsumeIntegralInRange<uint8_t>(0, 26); // Extended range for new case 26
            // END MODIFICATION

            // START MODIFICATION: Corrected outer switch case to include all operations 0-26
            switch (op_type) {
                case 0: case 1: case 2: case 3: case 4: case 5: case 6: case 7: case 8: case 9: case 10: case 11: case 12: case 13: case 14: case 15: case 16: case 17: case 18: case 19: case 20: case 21: case 22: case 23: case 24: case 25: case 26:
                // END MODIFICATION
                {
                    // Representative original operations (subset for brevity)
                    if (op_type == 0 && current_element) { 
                        tinyxml2::XMLElement *new_child = doc->NewElement("ChildOp0");
                        if (new_child) current_element->InsertEndChild(new_child);
                    } else if (op_type == 1 && current_element) { 
                        current_element->SetAttribute("AttrOp1", "ValOp1");
                    } else if (op_type == 2 && current_element) { 
                         current_element->SetText("TextOp2");
                    }

                     switch (op_type) { 
                        case 0: { std::string child_name_str = fdp.ConsumeRandomLengthString(32); if (child_name_str.empty()) { child_name_str = "defaultChild"; } tinyxml2::XMLElement *new_child = doc->NewElement(child_name_str.c_str()); if (new_child) { if (current_element) current_element->InsertEndChild(new_child); else doc->InsertEndChild(new_child); if (fdp.ConsumeBool()) { current_element = new_child; } } break; }
                        case 1: { if (!current_element) break; std::string attr_name_str = fdp.ConsumeRandomLengthString(32); std::string attr_value_str = fdp.ConsumeRandomLengthString(64); if (!attr_name_str.empty()) { current_element->SetAttribute(attr_name_str.c_str(), attr_value_str.c_str());} break; }
                        case 2: { if (!current_element) break; std::string text_content_str = fdp.ConsumeRandomLengthString(128); current_element->SetText(text_content_str.c_str()); break;}
                        case 3: { if (!current_element) break; uint8_t nav_type = fdp.ConsumeIntegralInRange<uint8_t>(0, 5); std::string name_filter_str = fdp.ConsumeRandomLengthString(10); const char* name_filter = name_filter_str.empty() ? nullptr : name_filter_str.c_str(); tinyxml2::XMLElement* target_element = nullptr; switch (nav_type) { case 0: { tinyxml2::XMLNode* parent_node = current_element->Parent(); if (parent_node) target_element = parent_node->ToElement(); break; } case 1: target_element = current_element->FirstChildElement(name_filter); break; case 2: target_element = current_element->LastChildElement(name_filter); break; case 3: target_element = current_element->NextSiblingElement(name_filter); break; case 4: target_element = current_element->PreviousSiblingElement(name_filter); break; case 5: target_element = current_element->FirstChildElement(); break;} if (target_element) { current_element = target_element; } break;}
                        case 4: { if (!current_element) break; std::string attr_name_to_delete = fdp.ConsumeRandomLengthString(32); if (!attr_name_to_delete.empty() && current_element->FirstAttribute()) { current_element->DeleteAttribute(attr_name_to_delete.c_str()); } break;}
                        case 5: { // MODIFICATION: Target XMLElement::QueryStringAttribute and XMLAttribute::*Value methods
                            if (!current_element) break;
                            std::string attr_name_str = fdp.ConsumeRandomLengthString(32);
                            if (!attr_name_str.empty()) {
                                uint8_t query_type = fdp.ConsumeIntegralInRange<uint8_t>(0, 7); // Extended for QueryStringAttribute
                                switch (query_type) {
                                    case 0: { int val; current_element->QueryIntAttribute(attr_name_str.c_str(), &val); break; }
                                    case 1: { unsigned val; current_element->QueryUnsignedAttribute(attr_name_str.c_str(), &val); break; }
                                    case 2: { bool val; current_element->QueryBoolAttribute(attr_name_str.c_str(), &val); break; }
                                    case 3: { double val; current_element->QueryDoubleAttribute(attr_name_str.c_str(), &val); break; }
                                    case 4: { float val; current_element->QueryFloatAttribute(attr_name_str.c_str(), &val); break; }
                                    case 5: { int64_t val; current_element->QueryInt64Attribute(attr_name_str.c_str(), &val); break; }
                                    case 6: { uint64_t val; current_element->QueryUnsigned64Attribute(attr_name_str.c_str(), &val); break; }
                                    case 7: { // Target XMLElement::QueryStringAttribute
                                        const char* val_str = nullptr;
                                        current_element->QueryStringAttribute(attr_name_str.c_str(), &val_str);
                                        break;
                                    }
                                }

                                if (fdp.ConsumeBool()) { // Target XMLAttribute methods
                                    const tinyxml2::XMLAttribute* attr = current_element->FindAttribute(attr_name_str.c_str());
                                    if (attr) {
                                        attr->Name();        // Already covered, but good for context
                                        attr->Value();       // Already covered
                                        attr->IntValue();    // Target XMLAttribute::IntValue
                                        attr->Int64Value();  // Target XMLAttribute::Int64Value
                                        attr->UnsignedValue(); // Target XMLAttribute::UnsignedValue
                                        attr->Unsigned64Value(); // Target XMLAttribute::Unsigned64Value
                                        attr->BoolValue();   // Target XMLAttribute::BoolValue
                                        attr->DoubleValue(); // Target XMLAttribute::DoubleValue
                                        attr->FloatValue();  // Target XMLAttribute::FloatValue
                                        attr->GetLineNum();  // Target XMLAttribute::GetLineNum
                                    }
                                }
                            }
                            break;
                        } // END MODIFICATION
                        case 6: { if (!current_element) break; current_element->GetText(); if (current_element->FirstChild() && current_element->FirstChild()->ToText()) { switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 6)) { case 0: { int val; current_element->QueryIntText(&val); break; } case 1: { unsigned val; current_element->QueryUnsignedText(&val); break; } case 2: { bool val; current_element->QueryBoolText(&val); break; } case 3: { double val; current_element->QueryDoubleText(&val); break; } case 4: { float val; current_element->QueryFloatText(&val); break; } case 5: { int64_t val; current_element->QueryInt64Text(&val); break; } case 6: { uint64_t val; current_element->QueryUnsigned64Text(&val); break; } } } break;}
                        case 7: { if (current_element) { switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 6)) { case 0: current_element->SetText(fdp.ConsumeIntegral<int>()); break; case 1: current_element->SetText(fdp.ConsumeIntegral<unsigned int>()); break; case 2: current_element->SetText(fdp.ConsumeBool()); break; case 3: current_element->SetText(fdp.ConsumeFloatingPoint<double>()); break; case 4: current_element->SetText(fdp.ConsumeFloatingPoint<float>()); break; case 5: current_element->SetText(fdp.ConsumeIntegral<int64_t>()); break; case 6: current_element->SetText(fdp.ConsumeIntegral<uint64_t>()); break; } } break;}
                        case 8: { if (current_element) { std::string attr_name_str = fdp.ConsumeRandomLengthString(32); switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 6)) { case 0: current_element->IntAttribute(attr_name_str.c_str(), fdp.ConsumeIntegral<int>()); break; case 1: current_element->UnsignedAttribute(attr_name_str.c_str(), fdp.ConsumeIntegral<unsigned int>()); break; case 2: current_element->BoolAttribute(attr_name_str.c_str(), fdp.ConsumeBool()); break; case 3: current_element->DoubleAttribute(attr_name_str.c_str(), fdp.ConsumeFloatingPoint<double>()); break; case 4: current_element->FloatAttribute(attr_name_str.c_str(), fdp.ConsumeFloatingPoint<float>()); break; case 5: current_element->Int64Attribute(attr_name_str.c_str(), fdp.ConsumeIntegral<int64_t>()); break; case 6: current_element->Unsigned64Attribute(attr_name_str.c_str(), fdp.ConsumeIntegral<uint64_t>()); break; } } break;}
                        case 9: { if (current_element) { tinyxml2::XMLNode* cloned_node = nullptr; if (fdp.ConsumeBool()) { if (fdp.ConsumeBool()) { cloned_node = current_element->ShallowClone(doc.get()); } else { cloned_node = current_element->DeepClone(doc.get()); } } else { tinyxml2::XMLNode* child_node_to_clone = current_element->FirstChild(); if (child_node_to_clone) { if (child_node_to_clone->ToText() && fdp.ConsumeBool()) { cloned_node = child_node_to_clone->ToText()->ShallowClone(doc.get()); } else if (child_node_to_clone->ToComment() && fdp.ConsumeBool()) { cloned_node = child_node_to_clone->ToComment()->ShallowClone(doc.get()); } else if (child_node_to_clone->ToDeclaration() && fdp.ConsumeBool()) { cloned_node = child_node_to_clone->ToDeclaration()->ShallowClone(doc.get()); } else if (child_node_to_clone->ToUnknown() && fdp.ConsumeBool()) { cloned_node = child_node_to_clone->ToUnknown()->ShallowClone(doc.get()); } else if (child_node_to_clone->ToElement()) { cloned_node = child_node_to_clone->ToElement()->ShallowClone(doc.get()); } else { cloned_node = child_node_to_clone->ShallowClone(doc.get()); } } } if (cloned_node) { doc->DeleteNode(cloned_node); } } break;}
                        case 10: { std::string content = fdp.ConsumeRandomLengthString(32); if (content.empty() && fdp.ConsumeBool()) content = "fuzzDefault"; if (fdp.ConsumeBool() && current_element) { switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 3)) { case 0: current_element->InsertNewComment(content.c_str()); break; case 1: current_element->InsertNewDeclaration(content.c_str()); break; case 2: current_element->InsertNewUnknown(content.c_str()); break; case 3: current_element->InsertNewText(content.c_str()); break; } } else { tinyxml2::XMLNode* new_node = nullptr; uint8_t node_type = fdp.ConsumeIntegralInRange<uint8_t>(0, 3); switch (node_type) { case 0: new_node = doc->NewComment(content.c_str()); break; case 1: new_node = doc->NewDeclaration(content.c_str()); break; case 2: new_node = doc->NewUnknown(content.c_str()); break; case 3: new_node = doc->NewText(content.c_str()); break; } if (new_node) { tinyxml2::XMLNode* inserted_node_ptr = nullptr; if (new_node->ToDeclaration()) { inserted_node_ptr = doc->InsertFirstChild(new_node); } else if (current_element && fdp.ConsumeBool()) { inserted_node_ptr = current_element->InsertEndChild(new_node); } else { inserted_node_ptr = doc->InsertEndChild(new_node); } if (!inserted_node_ptr) { doc->DeleteNode(new_node); } } } break;}
                        case 11: { if (current_element) { if (fdp.ConsumeBool()) { current_element->ChildElementCount(); } else { std::string child_name_str = fdp.ConsumeRandomLengthString(10); current_element->ChildElementCount(child_name_str.c_str()); } } break;}
                        case 12: { tinyxml2::XMLNode* node1 = nullptr; tinyxml2::XMLNode* node2 = nullptr; uint8_t node_type_choice = fdp.ConsumeIntegralInRange<uint8_t>(0, 4); std::string val1 = fdp.ConsumeRandomLengthString(20); if (val1.empty()) val1 = "sE_val1"; switch (node_type_choice) { case 0: node1 = doc->NewElement(val1.c_str()); break; case 1: node1 = doc->NewText(val1.c_str()); break; case 2: node1 = doc->NewComment(val1.c_str()); break; case 3: node1 = doc->NewDeclaration(val1.c_str()); break; case 4: node1 = doc->NewUnknown(val1.c_str()); break; } if (node1) { std::string val2 = fdp.ConsumeBool() ? val1 : fdp.ConsumeRandomLengthString(20); if (val2.empty() && val1 != val2) val2 = "sE_val2_diff"; else if (val2.empty()) val2 = val1; switch (node_type_choice) { case 0: node2 = doc->NewElement(val2.c_str()); break; case 1: node2 = doc->NewText(val2.c_str()); break; case 2: node2 = doc->NewComment(val2.c_str()); break; case 3: node2 = doc->NewDeclaration(val2.c_str()); break; case 4: node2 = doc->NewUnknown(val2.c_str()); break; } if (node2) { node1->ShallowEqual(node2); doc->DeleteNode(node2); } if (current_element) { node1->ShallowEqual(current_element); } doc->DeleteNode(node1); } break;}
                        case 13: { if (current_element && current_element->FirstChild()) { tinyxml2::XMLNode* after_this_node = current_element->FirstChild(); if (fdp.ConsumeBool() && after_this_node->NextSibling()) { after_this_node = after_this_node->NextSibling(); } std::string new_elem_name = fdp.ConsumeRandomLengthString(16); if (new_elem_name.empty()) new_elem_name = "insertedAfterElem"; tinyxml2::XMLElement* add_this_elem = doc->NewElement(new_elem_name.c_str()); if (add_this_elem) { tinyxml2::XMLNode* inserted_node = current_element->InsertAfterChild(after_this_node, add_this_elem); if (!inserted_node) { doc->DeleteNode(add_this_elem); } } } break;}
                        case 14: { if (current_element) { std::string attr_name = fdp.ConsumeRandomLengthString(32); if (attr_name.empty()) attr_name = "typedAttrExample"; uint8_t type_choice = fdp.ConsumeIntegralInRange<uint8_t>(0, 6); switch (type_choice) { case 0: current_element->SetAttribute(attr_name.c_str(), fdp.ConsumeIntegral<int>()); break; case 1: current_element->SetAttribute(attr_name.c_str(), fdp.ConsumeIntegral<unsigned int>()); break; case 2: current_element->SetAttribute(attr_name.c_str(), fdp.ConsumeBool()); break; case 3: current_element->SetAttribute(attr_name.c_str(), fdp.ConsumeFloatingPoint<double>()); break; case 4: current_element->SetAttribute(attr_name.c_str(), fdp.ConsumeFloatingPoint<float>()); break; case 5: current_element->SetAttribute(attr_name.c_str(), fdp.ConsumeIntegral<int64_t>()); break; case 6: current_element->SetAttribute(attr_name.c_str(), fdp.ConsumeIntegral<uint64_t>()); break; } } break;}
                        case 15: { if (current_element) { uint8_t type_choice = fdp.ConsumeIntegralInRange<uint8_t>(0, 6); switch (type_choice) { case 0: current_element->IntText(fdp.ConsumeIntegral<int>()); break; case 1: current_element->UnsignedText(fdp.ConsumeIntegral<unsigned int>()); break; case 2: current_element->BoolText(fdp.ConsumeBool()); break; case 3: current_element->DoubleText(fdp.ConsumeFloatingPoint<double>()); break; case 4: current_element->FloatText(fdp.ConsumeFloatingPoint<float>()); break; case 5: current_element->Int64Text(fdp.ConsumeIntegral<int64_t>()); break; case 6: current_element->Unsigned64Text(fdp.ConsumeIntegral<uint64_t>()); break; } } break;}
                        case 16: { std::unique_ptr<tinyxml2::XMLDocument> doc_copy(new tinyxml2::XMLDocument( fdp.ConsumeBool(), fdp.PickValueInArray({tinyxml2::PRESERVE_WHITESPACE, tinyxml2::COLLAPSE_WHITESPACE}) )); if (doc_copy) { doc->DeepCopy(doc_copy.get()); } break;}
                        case 17: { if (current_element) { std::string child_name_str = fdp.ConsumeRandomLengthString(32); if (child_name_str.empty()) { child_name_str = "defaultNewChildViaInsert"; } tinyxml2::XMLElement* new_child = current_element->InsertNewChildElement(child_name_str.c_str()); if (new_child && fdp.ConsumeBool()) { current_element = new_child; } } break;}
                        case 18: { std::string data_to_load = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0,1024)); FILE* temp_fp = tmpfile(); if (temp_fp) { if (!data_to_load.empty()) { fwrite(data_to_load.data(), 1, data_to_load.size(), temp_fp); } rewind(temp_fp); doc->LoadFile(temp_fp); fclose(temp_fp); current_element = doc->RootElement(); if (!current_element) { std::string root_name_str = fdp.ConsumeRandomLengthString(32); if (root_name_str.empty()) root_name_str = "defaultRootPostLoad"; current_element = doc->NewElement(root_name_str.c_str()); if (current_element) doc->InsertFirstChild(current_element); } } break;}
                        case 19: { FILE* temp_fp = tmpfile(); if (temp_fp) { doc->SaveFile(temp_fp, fdp.ConsumeBool()); fclose(temp_fp); } break;}
                        case 20: { tinyxml2::XMLPrinter local_printer(nullptr, fdp.ConsumeBool()); std::string pa_name = fdp.ConsumeRandomLengthString(10); if (pa_name.empty()) pa_name = "pa"; switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 5)) { case 0: local_printer.PushAttribute(pa_name.c_str(), fdp.ConsumeIntegral<int>()); break; case 1: local_printer.PushAttribute(pa_name.c_str(), fdp.ConsumeIntegral<unsigned int>()); break; case 2: local_printer.PushAttribute(pa_name.c_str(), fdp.ConsumeIntegral<int64_t>()); break; case 3: local_printer.PushAttribute(pa_name.c_str(), fdp.ConsumeIntegral<uint64_t>()); break; case 4: local_printer.PushAttribute(pa_name.c_str(), fdp.ConsumeBool()); break; case 5: local_printer.PushAttribute(pa_name.c_str(), fdp.ConsumeFloatingPoint<double>()); break; } switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 6)) { case 0: local_printer.PushText(fdp.ConsumeIntegral<int>()); break; case 1: local_printer.PushText(fdp.ConsumeIntegral<unsigned int>()); break; case 2: local_printer.PushText(fdp.ConsumeIntegral<int64_t>()); break; case 3: local_printer.PushText(fdp.ConsumeIntegral<uint64_t>()); break; case 4: local_printer.PushText(fdp.ConsumeBool()); break; case 5: local_printer.PushText(fdp.ConsumeFloatingPoint<float>()); break; case 6: local_printer.PushText(fdp.ConsumeFloatingPoint<double>()); break; } break;}
                        case 21: { uint8_t load_file_scenario = fdp.ConsumeIntegralInRange<uint8_t>(0, 2); if (load_file_scenario == 0) { doc->LoadFile(static_cast<const char*>(nullptr)); } else if (load_file_scenario == 1) { const char* invalid_filename_base = "/this/path/should/not/exist/file.xml"; std::string long_fname_str = fdp.ConsumeRandomLengthString(1024); const char* invalid_filename = invalid_filename_base; if (fdp.ConsumeBool() && !long_fname_str.empty()) { invalid_filename = long_fname_str.c_str(); } doc->LoadFile(invalid_filename); } else { std::string data_to_write_to_file = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 512)); const char* temp_c_filename = "fuzz_load_cfilename.xml"; FILE* fp_write = fopen(temp_c_filename, "wb"); if (fp_write) { if (!data_to_write_to_file.empty()) { fwrite(data_to_write_to_file.data(), 1, data_to_write_to_file.size(), fp_write); } fclose(fp_write); doc->LoadFile(temp_c_filename); std::remove(temp_c_filename); } else { std::remove(temp_c_filename); } } current_element = doc->RootElement(); if (!current_element) { std::string root_name_str = fdp.ConsumeRandomLengthString(32); if (root_name_str.empty()) root_name_str = "defaultRootPostLoadCFile"; current_element = doc->NewElement(root_name_str.c_str()); if (current_element) doc->InsertFirstChild(current_element); } break;}
                        case 22: { uint8_t save_file_scenario = fdp.ConsumeIntegralInRange<uint8_t>(0, 2); bool compact = fdp.ConsumeBool(); if (save_file_scenario == 0) { doc->SaveFile(static_cast<const char*>(nullptr), compact); } else if (save_file_scenario == 1) { const char* invalid_filename_base = "/this/path/should/not/exist/file_to_save.xml"; std::string long_fname_str = fdp.ConsumeRandomLengthString(1024); const char* invalid_filename = invalid_filename_base; if (fdp.ConsumeBool() && !long_fname_str.empty()) { invalid_filename = long_fname_str.c_str(); } doc->SaveFile(invalid_filename, compact); } else { const char* temp_c_save_filename = "fuzz_save_cfilename.xml"; doc->SaveFile(temp_c_save_filename, compact); std::remove(temp_c_save_filename); } break;}
                        case 23: { if (current_element) { current_element->SetValue("static_fuzz_val_for_setinternedstr", true); } break;}
                        case 24: { FILE* temp_fp_for_printer = tmpfile(); if (temp_fp_for_printer) { tinyxml2::XMLPrinter printer_with_file(temp_fp_for_printer, fdp.ConsumeBool() ); printer_with_file.OpenElement(fdp.ConsumeBool() ? "TestElemFile1" : "AnotherTest", fdp.ConsumeBool()); if (fdp.ConsumeBool()) { printer_with_file.PushAttribute(fdp.ConsumeRandomLengthString(5).c_str(), fdp.ConsumeRandomLengthString(5).c_str()); } if (fdp.ConsumeBool()) { printer_with_file.PushText(fdp.ConsumeRandomLengthString(10).c_str()); } if (fdp.ConsumeBool()) { printer_with_file.PushText(fdp.ConsumeIntegral<int>()); } else { printer_with_file.PushText(fdp.ConsumeFloatingPoint<double>()); } printer_with_file.CloseElement(fdp.ConsumeBool()); if (fdp.ConsumeBool()) { doc->Print(&printer_with_file); } fclose(temp_fp_for_printer); } break;}
                        case 25: { if (current_element) { std::string attr_name_str = fdp.ConsumeRandomLengthString(16); if (attr_name_str.empty()) attr_name_str = "defaultFuzzAttr"; const char* attr_name = attr_name_str.c_str(); if (fdp.ConsumeBool()) { std::string non_existent_attr_name_str = fdp.ConsumeRandomLengthString(10) + "_nonexist"; if(non_existent_attr_name_str.empty()) non_existent_attr_name_str = "guaranteed_non_existent_attr"; current_element->Attribute(non_existent_attr_name_str.c_str(), fdp.ConsumeBool() ? nullptr : "some_val"); } std::string attr_val_str = fdp.ConsumeRandomLengthString(16); current_element->SetAttribute(attr_name, attr_val_str.c_str()); current_element->Attribute(attr_name, nullptr); current_element->Attribute(attr_name, attr_val_str.c_str()); std::string different_attr_val_str = attr_val_str + "_diff"; if (attr_val_str.empty() && different_attr_val_str == "_diff") { different_attr_val_str = "non_empty_diff_val"; } else if (attr_val_str == different_attr_val_str) { different_attr_val_str += "X"; } if (fdp.ConsumeBool()) { std::string random_diff_val = fdp.ConsumeRandomLengthString(16); if (random_diff_val != attr_val_str) { different_attr_val_str = random_diff_val; } } current_element->Attribute(attr_name, different_attr_val_str.c_str()); } break;}
                        // START MODIFICATION: New case for various Node/Doc utilities and Handle classes
                        case 26: {
                            if (current_element) {
                                current_element->GetDocument(); // Target XMLNode::GetDocument()
                                current_element->GetLineNum();  // Target XMLNode::GetLineNum()
                                current_element->NoChildren();  // Target XMLNode::NoChildren()
                                // SetUserData takes void*, using a fuzzed integer cast to void* is a common fuzzing technique.
                                // Memory safety: This is just an opaque value, not dereferenced by TinyXML2 itself.
                                current_element->SetUserData(reinterpret_cast<void*>(static_cast<uintptr_t>(fdp.ConsumeIntegral<uint32_t>()))); // Target XMLNode::SetUserData()
                                current_element->GetUserData(); // Target XMLNode::GetUserData()

                                const tinyxml2::XMLNode* first_child_node = current_element->FirstChild();
                                if (first_child_node) {
                                    first_child_node->LastChild(); // Target XMLNode::LastChild() (const version)
                                    const tinyxml2::XMLNode* second_child_node = first_child_node->NextSibling();
                                    if (second_child_node) {
                                        second_child_node->PreviousSibling(); // Target XMLNode::PreviousSibling() (const version)
                                    }
                                }
                                current_element->LastChild(); // Target XMLNode::LastChild() (non-const version on current_element)

                                if (fdp.ConsumeBool()) {
                                    tinyxml2::XMLHandle handle(current_element);
                                    handle.FirstChildElement(fdp.ConsumeRandomLengthString(5).c_str());
                                    handle.ToElement();
                                    handle.FirstChild().ToText(); 
                                }
                                if (fdp.ConsumeBool()) {
                                    const tinyxml2::XMLElement* const_current_element = current_element;
                                    tinyxml2::XMLConstHandle const_handle(const_current_element);
                                    const_handle.FirstChildElement(fdp.ConsumeRandomLengthString(5).c_str());
                                    const_handle.ToElement(); 
                                    const_handle.LastChild().ToUnknown(); 
                                }
                            }
                            doc->ToDocument();      // Target XMLDocument::ToDocument() (const version)
                            doc->ErrorID();         // Target XMLDocument::ErrorID()
                            doc->ErrorLineNum();    // Target XMLDocument::ErrorLineNum()
                            doc->GetLineNum();      // Target XMLNode::GetLineNum() (inherited by XMLDocument)

                            doc->ShallowClone(nullptr); 
                            doc->ShallowEqual(nullptr); 
                            break;
                        }
                        // END MODIFICATION
                        default: break;
                     }
                }
                break;
                default: 
                    break;
            }
        }
    }

    if (fdp.ConsumeBool()) {
        doc->SetBOM(fdp.ConsumeBool());
    }

    if (fdp.ConsumeBool()) {
        CoverMyVisitor my_custom_visitor;
        doc->Accept(&my_custom_visitor);
    }

    tinyxml2::XMLPrinter printer; 
    
    if (fdp.ConsumeBool()) { 
        if (fdp.ConsumeBool()) {
            printer.PushText(fdp.ConsumeIntegral<int>());
        } else {
            printer.PushText(fdp.ConsumeFloatingPoint<double>());
        }
    }
    
    doc->Print(&printer);

    printer.CStr();     
    printer.CStrSize(); 

    // Call public methods that use variadic Print internally, on the printer with _fp == nullptr.
    // This helps cover TIXML_VSCPRINTF, which is called by XMLPrinter::Print when _fp == nullptr.
    if (fdp.ConsumeBool()) {
        std::string elem_name = fdp.ConsumeRandomLengthString(15);
        if (elem_name.empty()) elem_name = "FuzzElem"; // Ensure non-empty name
        printer.OpenElement(elem_name.c_str()); // Uses variadic Print

        if (fdp.ConsumeBool()) {
            std::string attr_name = fdp.ConsumeRandomLengthString(10);
            if (attr_name.empty()) attr_name = "attrInt";
            // PushAttribute(name, int) indirectly calls variadic Print with format " %s=\"%d\"" (or similar)
            printer.PushAttribute(attr_name.c_str(), fdp.ConsumeIntegral<int>());
        }
        if (fdp.ConsumeBool()) {
            std::string attr_name_str = fdp.ConsumeRandomLengthString(10);
            if (attr_name_str.empty()) attr_name_str = "attrStr";
            std::string attr_val_str = fdp.ConsumeRandomLengthString(20);
            // PushAttribute(name, string) indirectly calls variadic Print with format " %s=\"%s\"" (or similar)
            printer.PushAttribute(attr_name_str.c_str(), attr_val_str.c_str());
        }
        if (fdp.ConsumeBool()) {
            std::string comment_text = fdp.ConsumeRandomLengthString(20);
            printer.PushComment(comment_text.c_str()); // Uses variadic Print
        }
        printer.CloseElement(); // Uses variadic Print
    } else {
        // A simple static sequence of calls to ensure some variadic Print usage
        printer.OpenElement("StaticTestElem");
        printer.PushAttribute("version", 1);
        printer.PushText("Some static text content.");
        printer.CloseElement();
    }
    printer.ClearBuffer(fdp.ConsumeBool()); 

    return 0;
}