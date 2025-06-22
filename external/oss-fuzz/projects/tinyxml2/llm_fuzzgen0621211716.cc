#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include <cstdio> // For FILE, tmpfile, fclose
#include <memory> // For std::unique_ptr (though we will remove it for tinyxml2 nodes)

#include "/src/tinyxml2/tinyxml2.h"

// Custom XMLVisitor to exercise XMLVisitor virtual functions and their calls in Accept
// This helps cover the 0% coverage on XMLVisitor::Visit* functions.
class FuzzVisitor : public tinyxml2::XMLVisitor {
public:
    // Optional: Pass an XMLPrinter to also exercise XMLPrinter::Visit* functions
    FuzzVisitor(tinyxml2::XMLPrinter* printer = nullptr) : _printer(printer) {}

    bool VisitEnter(const tinyxml2::XMLDocument& doc) override {
        if (_printer) _printer->VisitEnter(doc);
        return true;
    }
    bool VisitExit(const tinyxml2::XMLDocument& doc) override {
        if (_printer) _printer->VisitExit(doc);
        return true;
    }
    bool VisitEnter(const tinyxml2::XMLElement& element, const tinyxml2::XMLAttribute* firstAttribute) override {
        if (_printer) _printer->VisitEnter(element, firstAttribute);
        return true;
    }
    bool VisitExit(const tinyxml2::XMLElement& element) override {
        if (_printer) _printer->VisitExit(element);
        return true;
    }
    bool Visit(const tinyxml2::XMLDeclaration& declaration) override {
        if (_printer) _printer->Visit(declaration);
        return true;
    }
    bool Visit(const tinyxml2::XMLText& text) override {
        if (_printer) _printer->Visit(text);
        return true;
    }
    bool Visit(const tinyxml2::XMLComment& comment) override {
        if (_printer) _printer->Visit(comment);
        return true;
    }
    bool Visit(const tinyxml2::XMLUnknown& unknown) override {
        if (_printer) _printer->Visit(unknown);
        return true;
    }
    // Removed: bool Visit(const tinyxml2::XMLAttribute& attribute) override
    // tinyxml2::XMLVisitor does not have a virtual Visit for XMLAttribute.
    // XMLPrinter does not have a corresponding Visit for XMLAttribute, so no _printer call here.
    // This function was causing the "only virtual member functions can be marked 'override'" error.

private:
    tinyxml2::XMLPrinter* _printer;
};


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // 1. Fuzz XMLDocument::Parse and related parsing functions
    // This covers many internal parsing functions like XMLNode::ParseDeep,
    // XMLElement::ParseDeep, XMLAttribute::ParseDeep, etc.
    std::string xml_string = fdp.ConsumeRemainingBytesAsString();
    tinyxml2::XMLDocument doc;
    doc.Parse(xml_string.c_str());

    // 2. Fuzz XMLPrinter::Print(const char*, ...) and TIXML_VSCPRINTF
    // Create an XMLPrinter without a FILE* to force it to use its internal buffer,
    // which then calls TIXML_VSCPRINTF and TIXML_VSNPRINTF.
    tinyxml2::XMLPrinter printer;
    // Removed direct calls to printer.Print(format_string.c_str(), ...);
    // These were causing "Print is a protected member" errors.
    // XMLDocument::Print(&printer) will exercise the printer's internal logic.

    // Also call XMLDocument::Print with the printer to exercise that path.
    doc.Print(&printer);

    // Call XMLDocument::Print with nullptr to cover the 'else' branch where it creates its own printer.
    doc.Print(nullptr);

    // Added to cover tinyxml2::XMLPrinter::Print(const char*, ...) and TIXML_VSCPRINTF
    // This function was 0% covered. We need to call it indirectly through a custom printer.
    // Since Print is protected, we can't call it directly.
    // However, the XMLPrinter constructor takes a FILE* and if it's nullptr, it uses an internal buffer.
    // The internal buffer path calls TIXML_VSCPRINTF.
    // We can't directly call the variadic Print, but we can ensure the internal buffer path is taken.
    // The existing doc.Print(&printer) already does this.
    // To specifically target the variadic Print, we would need to expose it or find another indirect call.
    // For now, we will add a dummy call to a function that *might* use it, or acknowledge it's hard to hit.
    // The search_function output shows XMLPrinter::Print(const char*, void) which is the variadic one.
    // It's protected, so direct calls are not possible.
    // The existing doc.Print(&printer) should be exercising the internal buffer logic for the printer.
    // Let's try to trigger it by printing a document with various data types.
    tinyxml2::XMLDocument print_doc;
    tinyxml2::XMLElement* root_elem = print_doc.NewElement("root");
    print_doc.InsertFirstChild(root_elem);
    root_elem->SetAttribute("int_attr", fdp.ConsumeIntegral<int>());
    root_elem->SetAttribute("double_attr", fdp.ConsumeFloatingPoint<double>());
    root_elem->SetText(fdp.ConsumeRandomLengthString(100).c_str());
    tinyxml2::XMLPrinter fuzzed_printer;
    print_doc.Print(&fuzzed_printer);


    // 3. Fuzz XMLNode::InsertAfterChild(tinyxml2::XMLNode*, tinyxml2::XMLNode*)
    // This function had low coverage, especially for its core insertion logic.
    if (doc.RootElement()) {
        tinyxml2::XMLElement* root = doc.RootElement();

        // Replaced std::unique_ptr with raw pointers.
        // tinyxml2::XMLDocument manages the memory for nodes created with NewElement
        // and inserted into the document. Using unique_ptr with a private destructor
        // causes compilation errors.
        tinyxml2::XMLElement* new_element1 = doc.NewElement("new_node_1");
        tinyxml2::XMLElement* new_element2 = doc.NewElement("new_node_2");
        tinyxml2::XMLElement* new_element3 = doc.NewElement("new_node_3");

        // Scenario 1: Insert after an existing child or as first child.
        // This avoids passing nullptr to afterThis, which caused a SEGV.
        if (root->FirstChildElement()) {
            root->InsertAfterChild(root->FirstChildElement(), new_element1);
        } else {
            root->InsertFirstChild(new_element1);
        }

        // Scenario 2: Removed the call to InsertAfterChild with nullptr for addThis,
        // as tinyxml2 asserts on a null addThis.
        // Ensure new_element3 is also owned by the document to prevent leak.
        root->InsertEndChild(new_element3);


        // Scenario 3: Insert a child that already has a parent
        // This covers the `addThis->Parent()` branch (line 1366).
        if (root->FirstChildElement()) {
            tinyxml2::XMLElement* existing_child = root->FirstChildElement();
            root->InsertEndChild(new_element2); // Add new_element2 to root, giving it a parent
            root->InsertAfterChild(existing_child, new_element2); // new_element2 now has a parent
        } else {
            // This else branch (lines 140-142) was not covered.
            // To hit this, root->FirstChildElement() must be false.
            // This means the root element has no children.
            root->InsertEndChild(new_element2); // Ensure new_element2 is added if no children exist
        }

        // Scenario 4: Insert after an existing child, covering the core insertion logic
        // Add multiple children to ensure the while loop in InsertAfterChild is exercised.
        tinyxml2::XMLElement* child_a = doc.NewElement("child_A");
        tinyxml2::XMLElement* child_b = doc.NewElement("child_B");
        tinyxml2::XMLElement* child_c = doc.NewElement("child_C");
        root->InsertEndChild(child_a);
        root->InsertEndChild(child_b);
        root->InsertEndChild(child_c);

        tinyxml2::XMLElement* insert_me = doc.NewElement("insert_me");
        // Insert 'insert_me' after 'child_b'. This should hit the `node == afterThis` branch (line 1376).
        root->InsertAfterChild(root->FirstChildElement("child_B"), insert_me);

        // Scenario 5: Insert after the last child to cover `addThis->_next == nullptr` (line 1380 else branch).
        tinyxml2::XMLElement* insert_last = doc.NewElement("insert_last");
        root->InsertAfterChild(root->LastChildElement(), insert_last);

        // Added to improve coverage for XMLNode::InsertAfterChild, specifically for edge cases
        // where 'afterThis' is the first child and 'addThis' is also the first child.
        tinyxml2::XMLElement* first_child = root->FirstChildElement();
        if (first_child) {
            tinyxml2::XMLElement* another_new_element = doc.NewElement("another_new_element");
            root->InsertFirstChild(another_new_element); // Make it the new first child
            root->InsertAfterChild(first_child, another_new_element); // Insert after original first child
        }
    }

    // Added to cover the else branch of Scenario 3 in XMLNode::InsertAfterChild (lines 140-142).
    // This new document will have no children initially, allowing the 'else' branch to be taken.
    tinyxml2::XMLDocument doc_no_children;
    tinyxml2::XMLElement* root_no_children = doc_no_children.NewElement("root_no_children");
    doc_no_children.InsertFirstChild(root_no_children);
    tinyxml2::XMLElement* new_element_no_children = doc_no_children.NewElement("new_element_no_children");
    // This call will now hit the 'else' branch at line 140 if root_no_children has no children.
    root_no_children->InsertEndChild(new_element_no_children);


    // 4. Fuzz XMLDocument::LoadFile(_IO_FILE*)
    // This function had low branch coverage, especially for error paths and empty files.
    // Create a temporary file and write fuzzed data to it.
    FILE* tmp = tmpfile(); // tmpfile() creates a temporary file that is automatically deleted on close or program exit.
    if (tmp) {
        std::string file_content = fdp.ConsumeRandomLengthString(1024);
        fwrite(file_content.c_str(), 1, file_content.length(), tmp);
        fseek(tmp, 0, SEEK_SET); // Rewind to the beginning of the file

        tinyxml2::XMLDocument doc_file;
        doc_file.LoadFile(tmp); // This will exercise the fread loop and Parse calls.

        // Try with an "empty" file to cover the `n == 0` branch (line 2296) and `XML_SUCCESS` return (line 2297).
        FILE* empty_tmp = tmpfile();
        if (empty_tmp) {
            fseek(empty_tmp, 0, SEEK_SET); // Ensure it's empty
            tinyxml2::XMLDocument doc_empty;
            doc_empty.LoadFile(empty_tmp);
            fclose(empty_tmp); // Close the empty temporary file
        }

        // Try with malformed XML to trigger Parse errors within LoadFile,
        // covering the `error != XML_SUCCESS` branch (line 2287).
        FILE* malformed_tmp = tmpfile();
        if (malformed_tmp) {
            std::string malformed_xml = "<root><unclosed_tag>"; // Malformed XML
            fwrite(malformed_xml.c_str(), 1, malformed_xml.length(), malformed_tmp);
            fseek(malformed_tmp, 0, SEEK_SET);
            tinyxml2::XMLDocument doc_malformed;
            doc_malformed.LoadFile(malformed_tmp);
            fclose(malformed_tmp); // Close the malformed temporary file
        }

        fclose(tmp); // Close the main temporary file
    }

    // Added to cover tinyxml2::XMLDocument::LoadFile(char const*)
    // This overload was not covered.
    std::string temp_filename = "fuzz_temp_file_" + std::to_string(fdp.ConsumeIntegral<uint32_t>()) + ".xml";
    FILE* temp_file_char_ptr = fopen(temp_filename.c_str(), "wb");
    if (temp_file_char_ptr) {
        std::string file_content_char_ptr = fdp.ConsumeRandomLengthString(1024);
        fwrite(file_content_char_ptr.c_str(), 1, file_content_char_ptr.length(), temp_file_char_ptr);
        fclose(temp_file_char_ptr);

        tinyxml2::XMLDocument doc_load_file_char_ptr;
        doc_load_file_char_ptr.LoadFile(temp_filename.c_str());
        remove(temp_filename.c_str()); // Clean up the temporary file
    }

    // Added to cover tinyxml2::XMLDocument::SaveFile(char const*, bool)
    // This overload was not covered.
    std::string save_filename = "fuzz_save_file_" + std::to_string(fdp.ConsumeIntegral<uint32_t>()) + ".xml";
    doc.SaveFile(save_filename.c_str(), fdp.ConsumeBool());
    remove(save_filename.c_str()); // Clean up the temporary file


    // 5. Fuzz DynArray::EnsureCapacity(unsigned long)
    // This function had very low coverage (26.67% line, 25.00% branch).
    // It's an internal utility, so we trigger it indirectly.
    // XMLPrinter's internal stack (`_stack`) is a `DynArray<char const*, 10ul>`.
    // We can trigger `EnsureCapacity` by creating a deeply nested XML structure
    // and then printing it, which will cause the printer to push many elements
    // onto its stack, forcing reallocation.
    tinyxml2::XMLDocument nested_doc;
    tinyxml2::XMLElement* current_element = nested_doc.NewElement("root");
    nested_doc.InsertFirstChild(current_element);
    // Push more than the initial capacity (10) to force reallocation.
    for (int i = 0; i < 15; ++i) {
        std::string tag_name = "level_" + std::to_string(i);
        tinyxml2::XMLElement* new_child = nested_doc.NewElement(tag_name.c_str());
        current_element->InsertEndChild(new_child);
        current_element = new_child;
    }
    // Printing this deeply nested document will exercise the printer's stack and its DynArray.
    tinyxml2::XMLPrinter nested_printer;
    nested_doc.Print(&nested_printer);

    // Fuzz XMLVisitor functions (0% coverage) and XMLDocument::Accept
    // Create a document with various node types to ensure all Visit functions are called.
    tinyxml2::XMLDocument visitor_doc;
    visitor_doc.Parse("<root><element attribute=\"value\"><text>some text</text></element><!--comment--><![CDATA[cdata_section]]><?unknown_instruction?><!DOCTYPE doc>");
    
    // Test with a basic FuzzVisitor
    FuzzVisitor visitor;
    visitor_doc.Accept(&visitor);

    // Test with a FuzzVisitor that also passes calls to an XMLPrinter
    tinyxml2::XMLPrinter visitor_printer;
    FuzzVisitor printer_visitor(&visitor_printer);
    visitor_doc.Accept(&printer_visitor);

    // Added to cover XMLElement::QueryStringAttribute and other QueryAttribute overloads
    // These functions were showing 0% coverage.
    if (doc.RootElement()) {
        tinyxml2::XMLElement* root = doc.RootElement();
        root->SetAttribute("string_attr", "test_string");
        root->SetAttribute("int_attr", 123);
        root->SetAttribute("bool_attr", true);
        root->SetAttribute("double_attr", 123.45);

        const char* str_val = nullptr;
        root->QueryStringAttribute("string_attr", &str_val);

        int int_val = 0;
        root->QueryIntAttribute("int_attr", &int_val);

        bool bool_val = false;
        root->QueryBoolAttribute("bool_attr", &bool_val);

        double double_val = 0.0;
        root->QueryDoubleAttribute("double_attr", &double_val);

        // Added to cover specific QueryAttribute overloads that were 0% covered.
        // These are typically called by the more specific Query*Attribute functions,
        // but explicit calls ensure coverage.
        root->QueryAttribute("string_attr", &str_val);
        root->QueryAttribute("int_attr", &int_val);
        root->QueryAttribute("bool_attr", &bool_val);
        root->QueryAttribute("double_attr", &double_val);
        // Also test with non-existent attributes to hit different branches
        root->QueryAttribute("non_existent_str", &str_val);
        root->QueryAttribute("non_existent_int", &int_val);
    }

    // Added to cover XMLUtil::SetBoolSerialization
    // This function had 50% branch coverage.
    tinyxml2::XMLUtil::SetBoolSerialization("true_val", "false_val");
    // To hit more branches, call with different values to ensure internal logic is fully exercised.
    tinyxml2::XMLUtil::SetBoolSerialization("1", "0");


    // Added to cover XMLDocument::DeepCopy
    // This function had 75% branch coverage.
    tinyxml2::XMLDocument deep_copy_doc;
    doc.DeepCopy(&deep_copy_doc);
    // To cover more branches in ShallowClone (called by DeepCopy), ensure the document has various node types.
    tinyxml2::XMLDocument complex_doc;
    complex_doc.Parse("<root><elem/><!--comment--><![CDATA[cdata]]><?proc_inst?><!DOCTYPE doc>");
    tinyxml2::XMLDocument complex_copy;
    complex_doc.DeepCopy(&complex_copy);


    // Added to cover XMLElement::InsertNewChildElement and other InsertNew* functions
    // These functions had 50% branch coverage.
    if (doc.RootElement()) {
        tinyxml2::XMLElement* root = doc.RootElement();
        root->InsertNewChildElement("new_child_element");
        root->InsertNewComment("new_comment");
        root->InsertNewText("new_text");
        root->InsertNewDeclaration("new_declaration");
        root->InsertNewUnknown("new_unknown");

        // To cover more branches, try inserting empty strings and into elements with existing children.
        root->InsertNewChildElement("");
        root->InsertNewComment("");
        root->InsertNewText("");
        root->InsertNewDeclaration("");
        root->InsertNewUnknown("");
    }

    // Added to cover tinyxml2::XMLNode::ToComment() which had 0% coverage.
    tinyxml2::XMLDocument comment_doc;
    tinyxml2::XMLComment* comment_node = comment_doc.NewComment("test comment");
    comment_doc.InsertFirstChild(comment_node);
    tinyxml2::XMLComment* retrieved_comment = comment_node->ToComment();
    (void)retrieved_comment; // Use to prevent unused variable warning

    // Added to cover tinyxml2::XMLText::~XMLText() which had 0% coverage.
    // Create a text node and let it go out of scope to ensure destructor is called.
    {
        tinyxml2::XMLDocument text_doc;
        tinyxml2::XMLText* text_node = text_doc.NewText("temporary text");
        text_doc.InsertFirstChild(text_node);
    } // text_doc and its nodes are destructed here.

    // Added to cover tinyxml2::MemPoolT<*>::ItemSize() const which had 0% coverage.
    // These are internal, but we can call them on existing MemPools.
    // Note: Accessing private members for fuzzing is generally acceptable.
    // The specific template instantiations are not directly exposed, but we can infer them.
    // For example, XMLDocument has internal MemPools.
    // This is a best effort to hit these, as direct access is not straightforward.
    // The existing code that creates nodes will implicitly call these.

    // Added to cover tinyxml2::MemPoolT<*>::Free(void*) branches.
    // By creating and then deleting various nodes, we aim to exercise different
    // scenarios within the Free function (e.g., freeing the last block, a middle block).
    tinyxml2::XMLDocument free_test_doc;
    tinyxml2::XMLElement* root_free = free_test_doc.NewElement("root_free");
    free_test_doc.InsertFirstChild(root_free);
    std::vector<tinyxml2::XMLNode*> nodes_to_delete;
    for (int i = 0; i < 20; ++i) { // Create more nodes than default block size to force multiple blocks
        tinyxml2::XMLElement* elem = free_test_doc.NewElement(("elem_" + std::to_string(i)).c_str());
        root_free->InsertEndChild(elem);
        nodes_to_delete.push_back(elem);
    }
    // Delete nodes in various orders to hit different Free branches
    if (root_free->FirstChild()) {
        free_test_doc.DeleteNode(root_free->FirstChild()); // Delete first
    }
    if (root_free->LastChild()) {
        free_test_doc.DeleteNode(root_free->LastChild()); // Delete last
    }
    if (nodes_to_delete.size() > 5) {
        free_test_doc.DeleteNode(nodes_to_delete[5]); // Delete a middle node
    }
    // Delete all remaining children
    root_free->DeleteChildren();


    // Added to cover tinyxml2::XMLNode::~XMLNode() branches.
    // Create nodes with and without children, and let them be destructed.
    {
        tinyxml2::XMLDocument node_dtor_doc;
        tinyxml2::XMLElement* parent_node = node_dtor_doc.NewElement("parent");
        node_dtor_doc.InsertFirstChild(parent_node);
        tinyxml2::XMLElement* child_node = node_dtor_doc.NewElement("child");
        parent_node->InsertEndChild(child_node);
        // parent_node and child_node will be destructed when node_dtor_doc goes out of scope.
    }
    {
        tinyxml2::XMLDocument node_dtor_no_children_doc;
        tinyxml2::XMLElement* single_node = node_dtor_no_children_doc.NewElement("single");
        node_dtor_no_children_doc.InsertFirstChild(single_node);
        // single_node will be destructed when node_dtor_no_children_doc goes out of scope.
    }

    // Added to cover tinyxml2::XMLNode::InsertEndChild and InsertFirstChild branches.
    // Insert into an empty list, then into a list with one item, then multiple.
    tinyxml2::XMLDocument insert_doc;
    tinyxml2::XMLElement* insert_root = insert_doc.NewElement("insert_root");
    insert_doc.InsertFirstChild(insert_root);

    // InsertFirstChild into empty
    tinyxml2::XMLElement* first_child_1 = insert_doc.NewElement("first_child_1");
    insert_root->InsertFirstChild(first_child_1);

    // InsertEndChild into list with one item
    tinyxml2::XMLElement* end_child_1 = insert_doc.NewElement("end_child_1");
    insert_root->InsertEndChild(end_child_1);

    // InsertFirstChild into list with multiple items
    tinyxml2::XMLElement* first_child_2 = insert_doc.NewElement("first_child_2");
    insert_root->InsertFirstChild(first_child_2);

    // InsertEndChild into list with multiple items
    tinyxml2::XMLElement* end_child_2 = insert_doc.NewElement("end_child_2");
    insert_root->InsertEndChild(end_child_2);


    // Added to cover tinyxml2::XMLNode::DeleteNode branches.
    tinyxml2::XMLDocument delete_doc;
    tinyxml2::XMLElement* delete_root = delete_doc.NewElement("delete_root");
    delete_doc.InsertFirstChild(delete_root);
    tinyxml2::XMLElement* child_to_delete_1 = delete_doc.NewElement("child_to_delete_1");
    tinyxml2::XMLElement* child_to_delete_2 = delete_doc.NewElement("child_to_delete_2");
    tinyxml2::XMLElement* child_to_delete_3 = delete_doc.NewElement("child_to_delete_3");
    delete_root->InsertEndChild(child_to_delete_1);
    delete_root->InsertEndChild(child_to_delete_2);
    delete_root->InsertEndChild(child_to_delete_3);

    delete_doc.DeleteNode(child_to_delete_2); // Delete middle child
    delete_doc.DeleteNode(child_to_delete_1); // Delete first child
    delete_doc.DeleteNode(child_to_delete_3); // Delete last child

    // Delete a root node
    tinyxml2::XMLDocument delete_root_doc;
    tinyxml2::XMLElement* only_root = delete_root_doc.NewElement("only_root");
    delete_root_doc.InsertFirstChild(only_root);
    delete_root_doc.DeleteNode(only_root);


    // Added to cover ShallowClone and ShallowEqual branches for various node types.
    // Create specific node types and compare them.

    // XMLElement ShallowEqual
    tinyxml2::XMLDocument elem_doc1, elem_doc2;
    tinyxml2::XMLElement* elem1 = elem_doc1.NewElement("test");
    tinyxml2::XMLElement* elem2 = elem_doc2.NewElement("test");
    tinyxml2::XMLElement* elem3 = elem_doc1.NewElement("different");
    if (elem1 && elem2) elem1->ShallowEqual(elem2); // Equal
    if (elem1 && elem3) elem1->ShallowEqual(elem3); // Different name

    // XMLComment ShallowEqual
    tinyxml2::XMLDocument comment_doc1, comment_doc2;
    tinyxml2::XMLComment* comment1 = comment_doc1.NewComment("test comment");
    tinyxml2::XMLComment* comment2 = comment_doc2.NewComment("test comment");
    tinyxml2::XMLComment* comment3 = comment_doc1.NewComment("different comment");
    if (comment1 && comment2) comment1->ShallowEqual(comment2);
    if (comment1 && comment3) comment1->ShallowEqual(comment3);

    // XMLText ShallowEqual
    tinyxml2::XMLDocument text_doc1, text_doc2;
    tinyxml2::XMLText* text1 = text_doc1.NewText("test text");
    tinyxml2::XMLText* text2 = text_doc2.NewText("test text");
    tinyxml2::XMLText* text3 = text_doc1.NewText("different text");
    if (text1 && text2) text1->ShallowEqual(text2);
    if (text1 && text3) text1->ShallowEqual(text3);

    // XMLDeclaration ShallowEqual
    tinyxml2::XMLDocument decl_doc1, decl_doc2;
    tinyxml2::XMLDeclaration* decl1 = decl_doc1.NewDeclaration("version='1.0'");
    tinyxml2::XMLDeclaration* decl2 = decl_doc2.NewDeclaration("version='1.0'");
    tinyxml2::XMLDeclaration* decl3 = decl_doc1.NewDeclaration("version='1.1'");
    if (decl1 && decl2) decl1->ShallowEqual(decl2);
    if (decl1 && decl3) decl1->ShallowEqual(decl3);

    // XMLUnknown ShallowEqual
    tinyxml2::XMLDocument unknown_doc1, unknown_doc2;
    tinyxml2::XMLUnknown* unknown1 = unknown_doc1.NewUnknown("instruction");
    tinyxml2::XMLUnknown* unknown2 = unknown_doc2.NewUnknown("instruction");
    tinyxml2::XMLUnknown* unknown3 = unknown_doc1.NewUnknown("different instruction");
    if (unknown1 && unknown2) unknown1->ShallowEqual(unknown2);
    if (unknown1 && unknown3) unknown1->ShallowEqual(unknown3);

    // Also test XMLNode::ShallowEqual with different types
    tinyxml2::XMLNode* node_elem = elem1;
    tinyxml2::XMLNode* node_comment = comment1;
    if (node_elem && node_comment) node_elem->ShallowEqual(node_comment); // Should return false


    // Added to cover XMLAttribute::ParseDeep branches.
    // Fuzzing with various attribute formats, including malformed ones.
    tinyxml2::XMLDocument attr_parse_doc;
    attr_parse_doc.Parse("<elem attr1='val1' attr2=\"val2\" attr3=val3 attr4='\"val4\"' attr5='&amp;' attr6='&#x20;' attr7='&#32;' attr8='unclosed");


    // Added to cover XMLElement::SetText(char const*) branches.
    if (doc.RootElement()) {
        tinyxml2::XMLElement* root = doc.RootElement();
        root->SetText(""); // Set empty text
        root->SetText(fdp.ConsumeRandomLengthString(50).c_str()); // Set fuzzed text
    }

    // Added to cover XMLElement::Query*Text branches for various conversion failures.
    if (doc.RootElement()) {
        tinyxml2::XMLElement* root = doc.RootElement();
        root->SetText("not_an_int");
        int int_text_val = 0;
        root->QueryIntText(&int_text_val);

        root->SetText("not_a_bool");
        bool bool_text_val = false;
        root->QueryBoolText(&bool_text_val);

        root->SetText("not_a_float");
        float float_text_val = 0.0f;
        root->QueryFloatText(&float_text_val);
    }

    // Added to cover XMLElement::ParseAttributes branches.
    // Fuzz with various attribute parsing scenarios, including malformed attributes.
    tinyxml2::XMLDocument parse_attrs_doc;
    parse_attrs_doc.Parse("<elem attr1='val1' attr2=\"val2\" attr3=val3 attr4='\"val4\"' attr5='&amp;' attr6='&#x20;' attr7='&#32;' attr8='unclosed\" attr9='val9'/>");


    // Added to cover XMLElement::DeleteAttribute(tinyxml2::XMLAttribute*) branches.
    if (doc.RootElement()) {
        tinyxml2::XMLElement* root = doc.RootElement();
        root->SetAttribute("del_attr_1", "val1");
        root->SetAttribute("del_attr_2", "val2");
        root->SetAttribute("del_attr_3", "val3");

        // Fix: Change to const XMLAttribute* as FindAttribute returns const.
        // Fix: Use DeleteAttribute(const char*) instead of the private DeleteAttribute(XMLAttribute*).
        const tinyxml2::XMLAttribute* attr1 = root->FindAttribute("del_attr_1");
        const tinyxml2::XMLAttribute* attr2 = root->FindAttribute("del_attr_2");
        const tinyxml2::XMLAttribute* attr3 = root->FindAttribute("del_attr_3");

        if (attr2) root->DeleteAttribute(attr2->Name()); // Delete middle
        if (attr1) root->DeleteAttribute(attr1->Name()); // Delete first
        if (attr3) root->DeleteAttribute(attr3->Name()); // Delete last
    }

    // Added to cover XMLElement::ShallowEqual branches.
    tinyxml2::XMLDocument elem_equal_doc1;
    tinyxml2::XMLElement* elem_equal1 = elem_equal_doc1.NewElement("test");
    elem_equal_doc1.InsertFirstChild(elem_equal1);
    elem_equal1->SetAttribute("attr", "val");

    tinyxml2::XMLDocument elem_equal_doc2;
    tinyxml2::XMLElement* elem_equal2 = elem_equal_doc2.NewElement("test");
    elem_equal_doc2.InsertFirstChild(elem_equal2);
    elem_equal2->SetAttribute("attr", "val");

    tinyxml2::XMLDocument elem_equal_doc3;
    tinyxml2::XMLElement* elem_equal3 = elem_equal_doc3.NewElement("different");
    elem_equal_doc3.InsertFirstChild(elem_equal3);

    elem_equal1->ShallowEqual(elem_equal2); // Equal
    elem_equal1->ShallowEqual(elem_equal3); // Different name
    // Removed: elem_equal1->ShallowEqual(nullptr); // Null comparison - this was causing the SEGV


    // Added to cover XMLElement::Accept branches.
    // Ensure elements with different child types are accepted.
    tinyxml2::XMLDocument accept_doc;
    accept_doc.Parse("<root><elem/><!--c--><text/><?pi?><!D></root>");
    FuzzVisitor accept_visitor;
    accept_doc.Accept(&accept_visitor);


    // Added to cover XMLDocument::Identify branches.
    // Provide various XML snippets to hit different identification paths.
    tinyxml2::XMLDocument identify_doc;
    identify_doc.Parse("<!--comment only-->");
    identify_doc.Parse("<?xml version='1.0'?>");
    identify_doc.Parse("<?pi instruction?>");
    identify_doc.Parse("<!DOCTYPE doc>");
    identify_doc.Parse("text only"); // Should identify as XMLText
    identify_doc.Parse("<root/>");


    // Added to cover XMLDocument::NewDeclaration branches.
    tinyxml2::XMLDocument decl_doc;
    decl_doc.NewDeclaration("version='1.0'");
    decl_doc.NewDeclaration(""); // Empty declaration


    // Added to cover XMLDocument::DeleteNode branches.
    tinyxml2::XMLDocument doc_delete_node;
    tinyxml2::XMLElement* root_del = doc_delete_node.NewElement("root");
    doc_delete_node.InsertFirstChild(root_del);
    tinyxml2::XMLElement* child_del = doc_delete_node.NewElement("child");
    root_del->InsertEndChild(child_del);

    doc_delete_node.DeleteNode(child_del); // Delete a child node
    doc_delete_node.DeleteNode(root_del); // Delete the root node


    // Added to cover XMLDocument::LoadFile(char const*) error paths.
    // Try loading a non-existent file.
    tinyxml2::XMLDocument non_existent_file_doc;
    non_existent_file_doc.LoadFile("non_existent_file.xml");


    // Added to cover XMLDocument::SaveFile(char const*, bool) error paths.
    // Try saving to a read-only directory (difficult to simulate in fuzzing env).
    // Instead, try saving to a path that might cause issues (e.g., very long name).
    std::string long_filename = "long_fuzz_save_file_";
    for (int i = 0; i < 200; ++i) {
        long_filename += "a";
    }
    long_filename += ".xml";
    doc.SaveFile(long_filename.c_str(), fdp.ConsumeBool());
    remove(long_filename.c_str());


    // Added to cover XMLDocument::Parse(char const*, unsigned long) branches.
    // Provide very large input to test buffer handling.
    std::string large_xml = "<root>" + fdp.ConsumeRandomLengthString(100000) + "</root>";
    tinyxml2::XMLDocument large_doc;
    large_doc.Parse(large_xml.c_str(), large_xml.length());

    // Provide malformed XML to hit error paths.
    tinyxml2::XMLDocument malformed_parse_doc;
    malformed_parse_doc.Parse("<root><unclosed_tag>", 20);


    // Added to cover XMLDocument::ErrorStr() const branches.
    // Trigger various errors and then call ErrorStr().
    tinyxml2::XMLDocument error_str_doc;
    error_str_doc.Parse("<root><", 7); // XML_ERROR_PARSING_ELEMENT
    error_str_doc.ErrorStr();

    tinyxml2::XMLDocument error_str_doc2;
    error_str_doc2.Parse("<root attr='val", 15); // XML_ERROR_PARSING_ATTRIBUTE
    error_str_doc2.ErrorStr();

    tinyxml2::XMLDocument error_str_doc3;
    error_str_doc3.Parse("<?xml version='1.0' encoding='UTF-8'?>", 38); // No error
    error_str_doc3.ErrorStr();


    // Acknowledging XMLPrinter::Print(const char*, ...) and TIXML_VSCPRINTF.
    // These functions are variadic and protected/internal.
    // Directly calling them from the fuzz target is not possible through public APIs.
    // Their coverage is typically achieved indirectly when internal library functions
    // that use them (e.g., for error reporting or debugging) are triggered.
    // The existing fuzz target already exercises XMLPrinter extensively through
    // XMLDocument::Print, which should cover most of the printer's core logic.
    // Further direct fuzzing of these specific variadic functions is not feasible
    // without modifying the tinyxml2 library itself to expose them or their callers.

    return 0;
}