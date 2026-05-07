#include "/src/tinyxml2/tinyxml2.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>
#include <memory> // For std::unique_ptr
#include <algorithm> // For std::min
#include <cstdio> // For remove
#include <unistd.h> // For unlink

// Minimalistic visitor for XMLDocument::Accept to ensure it's called.
// This helps cover the various Visit* methods in XMLVisitor which show 0% coverage.
class FuzzVisitor : public tinyxml2::XMLVisitor
{
public:
    virtual bool VisitEnter(const tinyxml2::XMLDocument& /*doc*/) override { return true; }
    virtual bool VisitExit(const tinyxml2::XMLDocument& /*doc*/) override { return true; }
    virtual bool VisitEnter(const tinyxml2::XMLElement& /*element*/, const tinyxml2::XMLAttribute* /*firstAttribute*/) override { return true; }
    virtual bool VisitExit(const tinyxml2::XMLElement& /*element*/) override { return true; }
    virtual bool Visit(const tinyxml2::XMLDeclaration& /*declaration*/) override { return true; }
    virtual bool Visit(const tinyxml2::XMLText& /*text*/) override { return true; }
    virtual bool Visit(const tinyxml2::XMLComment& /*comment*/) override { return true; }
    virtual bool Visit(const tinyxml2::XMLUnknown& /*unknown*/) override { return true; }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // Use a unique_ptr for XMLDocument to ensure it's always deleted,
    // which in turn cleans up all nodes created by this document.
    // Replaced std::make_unique with std::unique_ptr(new ...) for C++11 compatibility.
    std::unique_ptr<tinyxml2::XMLDocument> doc(new tinyxml2::XMLDocument());

    // API 1: tinyxml2::XMLNode::ChildElementCount(char const*) const
    /*
     * ANALYSIS: The function-level coverage report showed tinyxml2::XMLNode::ChildElementCount(char const*) const had 0% line and branch coverage.
     * IMPLEMENTATION: Create an XML structure with various elements and call ChildElementCount with different names,
     *                 including NULL and non-existent names, to trigger all code paths.
     */
    {
        tinyxml2::XMLElement* root = doc->NewElement("root_child_count");
        doc->InsertFirstChild(root);

        // Add some children with fuzzed names
        int num_children = fdp.ConsumeIntegralInRange<int>(0, 5);
        std::vector<std::string> child_names;
        for (int i = 0; i < num_children; ++i) {
            std::string child_name = fdp.ConsumeRandomLengthString(std::min((size_t)10, fdp.remaining_bytes()));
            if (child_name.empty()) { // Ensure name is not empty for valid elements
                child_name = "default_child";
            }
            tinyxml2::XMLElement* child = doc->NewElement(child_name.c_str());
            root->InsertEndChild(child);
            child_names.push_back(child_name);
        }

        // Call with a fuzzed search name
        std::string search_name = fdp.ConsumeRandomLengthString(std::min((size_t)10, fdp.remaining_bytes()));
        if (!search_name.empty()) {
            root->ChildElementCount(search_name.c_str());
        }

        // Test with NULL name (should be handled gracefully or assert)
        if (fdp.ConsumeBool()) {
            root->ChildElementCount(nullptr);
        }
        // Test with an existing child name if available
        if (!child_names.empty() && fdp.ConsumeBool()) {
            root->ChildElementCount(child_names[fdp.ConsumeIntegralInRange<size_t>(0, child_names.size() - 1)].c_str());
        }

        /*
         * ANALYSIS: The function-level coverage report showed tinyxml2::XMLNode::ChildElementCount() const (no arguments) had 0% line and branch coverage.
         * IMPLEMENTATION: Call the no-argument version of ChildElementCount on the root element.
         */
        root->ChildElementCount();
    }

    // API 2: tinyxml2::XMLNode::InsertAfterChild(tinyxml2::XMLNode*, tinyxml2::XMLNode*)
    /*
     * ANALYSIS: The function-level coverage report showed tinyxml2::XMLNode::InsertAfterChild had 0% line and branch coverage.
     *           The line-level report indicated several branches related to document ownership, parent-child relationships,
     *           and specific node configurations (e.g., afterThis being the last child or the same as addThis) were missed.
     * IMPLEMENTATION: Create multiple documents and nodes to trigger these specific scenarios, ensuring memory safety.
     */
    {
        tinyxml2::XMLElement* root = doc->NewElement("root_insert");
        doc->InsertEndChild(root);

        tinyxml2::XMLElement* child1 = doc->NewElement("child1");
        tinyxml2::XMLElement* child2 = doc->NewElement("child2");
        tinyxml2::XMLElement* child3 = doc->NewElement("child3");

        root->InsertEndChild(child1);
        root->InsertEndChild(child2);

        // Scenario 1: addThis belongs to a different document (line 989 in tinyxml2.cpp)
        // This should trigger a TIXMLASSERT(false) in the debug build.
        if (fdp.ConsumeBool()) {
            // Replaced std::make_unique with std::unique_ptr(new ...) for C++11 compatibility.
            std::unique_ptr<tinyxml2::XMLDocument> other_doc(new tinyxml2::XMLDocument());
            tinyxml2::XMLElement* other_doc_child = other_doc->NewElement("other_child");
            root->InsertAfterChild(child1, other_doc_child);
            // 'other_doc_child' is owned by 'other_doc' and will be freed when 'other_doc' goes out of scope.
        }

        // Scenario 2: afterThis is not a child of 'this' (line 996 in tinyxml2.cpp)
        // This should trigger a TIXMLASSERT(false) in the debug build.
        if (fdp.ConsumeBool()) {
            tinyxml2::XMLElement* orphan_child = doc->NewElement("orphan");
            // Do not insert orphan_child into root, so its parent is NULL.
            root->InsertAfterChild(child1, orphan_child);
            // Since orphan_child was not successfully inserted into 'root',
            // it remains owned by 'doc' but not linked into the tree.
            // It will be cleaned up when 'doc' is deleted.
        }

        // Scenario 3: afterThis == addThis (line 1000 in tinyxml2.cpp)
        if (fdp.ConsumeBool()) {
            root->InsertAfterChild(child1, child1);
        }

        // Scenario 4: afterThis is the last child (line 1008 in tinyxml2.cpp)
        if (fdp.ConsumeBool()) {
            tinyxml2::XMLElement* new_child = doc->NewElement("new_last");
            root->InsertAfterChild(child2, new_child); // child2 is currently the last child
        }

        // Normal case (if not covered by previous branches)
        if (fdp.ConsumeBool()) {
            root->InsertAfterChild(child1, child3);
        }
    }

    // API 3: tinyxml2::XMLElement::QueryIntText(int*) const
    /*
     * ANALYSIS: The function-level coverage report showed tinyxml2::XMLElement::QueryIntText had 0% line and branch coverage.
     *           The line-level report indicated that the conditions for having a text child and successful integer conversion were missed.
     * IMPLEMENTATION: Create elements with valid integer text, invalid text, and no text to cover all paths.
     */
    {
        tinyxml2::XMLElement* element_int = doc->NewElement("int_val_query");
        doc->InsertEndChild(element_int);

        int val;
        // Case 1: Valid integer text
        std::string int_str = std::to_string(fdp.ConsumeIntegral<int>());
        element_int->SetText(int_str.c_str());
        element_int->QueryIntText(&val);

        // Case 2: Invalid (non-integer) text
        std::string non_int_str = fdp.ConsumeRandomLengthString(std::min((size_t)10, fdp.remaining_bytes()));
        if (!non_int_str.empty()) {
            element_int->SetText(non_int_str.c_str());
            element_int->QueryIntText(&val);
        }

        // Case 3: No text child (element_no_text has no text set)
        tinyxml2::XMLElement* element_no_text = doc->NewElement("no_text_query");
        doc->InsertEndChild(element_no_text);
        element_no_text->QueryIntText(&val);
    }

    // API 4: tinyxml2::XMLDocument::ErrorStr() const, PrintError() const, ErrorName() const
    /*
     * ANALYSIS: The function-level coverage report showed tinyxml2::XMLDocument::ErrorStr, PrintError, and ErrorName had 0% line and branch coverage.
     *           The line-level report indicated that the branch for _errorStr being empty was missed for ErrorStr.
     * IMPLEMENTATION: Call ErrorStr on a document with no errors and on a document after parsing an invalid XML string.
     *                 Also call PrintError and ErrorName after an error to cover these functions.
     */
    {
        // Case 1: No error (empty _errorStr) - 'doc' is initially error-free.
        doc->ErrorStr();
        doc->PrintError(); // Call PrintError on a document with no error
        doc->ErrorName();  // Call ErrorName on a document with no error

        // Case 2: With error - parse an invalid XML string to set an error.
        // Replaced std::make_unique with std::unique_ptr(new ...) for C++11 compatibility.
        std::unique_ptr<tinyxml2::XMLDocument> error_doc(new tinyxml2::XMLDocument());
        std::string invalid_xml = fdp.ConsumeRandomLengthString(std::min((size_t)100, fdp.remaining_bytes()));
        error_doc->Parse(invalid_xml.c_str(), invalid_xml.length());
        error_doc->ErrorStr();
        /*
         * ANALYSIS: The function-level coverage report showed tinyxml2::XMLDocument::PrintError() const and tinyxml2::XMLDocument::ErrorName() const had 0% coverage.
         * IMPLEMENTATION: Call these functions on a document that has encountered an error.
         */
        error_doc->PrintError();
        error_doc->ErrorName();
    }

    // API 5: tinyxml2::XMLElement::SetText(int)
    /*
     * ANALYSIS: The function-level coverage report showed tinyxml2::XMLElement::SetText(int) had 0% line and branch coverage.
     * IMPLEMENTATION: Create an XMLElement and set its text using an integer value generated by the fuzzer.
     */
    {
        tinyxml2::XMLElement* element_set_int = doc->NewElement("set_int_val");
        doc->InsertEndChild(element_set_int);
        element_set_int->SetText(fdp.ConsumeIntegral<int>());
    }

    // New API Coverage Block: tinyxml2::XMLElement::GetText() const
    /*
     * ANALYSIS: The function-level coverage report showed tinyxml2::XMLElement::GetText() const had 0% line and branch coverage.
     * IMPLEMENTATION: Create elements with and without text content and call GetText() on them.
     */
    {
        tinyxml2::XMLElement* element_with_text = doc->NewElement("element_get_text");
        doc->InsertEndChild(element_with_text);
        std::string text_content = fdp.ConsumeRandomLengthString(std::min((size_t)20, fdp.remaining_bytes()));
        if (!text_content.empty()) {
            element_with_text->SetText(text_content.c_str());
        }
        element_with_text->GetText(); // Call GetText on element with fuzzed text

        tinyxml2::XMLElement* element_without_text = doc->NewElement("element_no_text_get_text");
        doc->InsertEndChild(element_without_text);
        element_without_text->GetText(); // Call GetText on element without text
    }

    // New API Coverage Block: tinyxml2::XMLElement::SetText and Query*Text for various types
    /*
     * ANALYSIS: The function-level coverage report showed many overloads of tinyxml2::XMLElement::SetText (unsigned int, long, unsigned long, bool, float, double)
     *           and corresponding Query*Text methods had 0% line and branch coverage.
     * IMPLEMENTATION: Create elements and call these SetText and Query*Text overloads with fuzzed data to cover them.
     */
    {
        tinyxml2::XMLElement* elem_uint = doc->NewElement("set_query_uint");
        doc->InsertEndChild(elem_uint);
        unsigned int uival = fdp.ConsumeIntegral<unsigned int>();
        elem_uint->SetText(uival);
        unsigned int query_uival;
        elem_uint->QueryUnsignedText(&query_uival);

        tinyxml2::XMLElement* elem_long = doc->NewElement("set_query_long");
        doc->InsertEndChild(elem_long);
        long lval = fdp.ConsumeIntegral<long>();
        elem_long->SetText(lval);
        long query_lval;
        elem_long->QueryInt64Text(&query_lval);

        tinyxml2::XMLElement* elem_ulong = doc->NewElement("set_query_ulong");
        doc->InsertEndChild(elem_ulong);
        unsigned long ulval = fdp.ConsumeIntegral<unsigned long>();
        elem_ulong->SetText(ulval);
        unsigned long query_ulval;
        elem_ulong->QueryUnsigned64Text(&query_ulval);

        tinyxml2::XMLElement* elem_bool = doc->NewElement("set_query_bool");
        doc->InsertEndChild(elem_bool);
        bool bval = fdp.ConsumeBool();
        elem_bool->SetText(bval);
        bool query_bval;
        elem_bool->QueryBoolText(&query_bval);

        tinyxml2::XMLElement* elem_float = doc->NewElement("set_query_float");
        doc->InsertEndChild(elem_float);
        float fval = fdp.ConsumeFloatingPoint<float>();
        elem_float->SetText(fval);
        float query_fval;
        elem_float->QueryFloatText(&query_fval);

        tinyxml2::XMLElement* elem_double = doc->NewElement("set_query_double");
        doc->InsertEndChild(elem_double);
        double dval = fdp.ConsumeFloatingPoint<double>();
        elem_double->SetText(dval);
        double query_dval;
        elem_double->QueryDoubleText(&query_dval);
    }

    // New API Coverage Block: tinyxml2::XMLNode::DeepClone(tinyxml2::XMLDocument*) const
    /*
     * ANALYSIS: The function-level coverage report showed tinyxml2::XMLNode::DeepClone(tinyxml2::XMLDocument*) const had 0% coverage.
     * IMPLEMENTATION: Create a sample XML structure and then deep clone a node from it. The cloned node is owned by the original document.
     */
    {
        tinyxml2::XMLElement* root_clone = doc->NewElement("root_clone");
        doc->InsertEndChild(root_clone);
        tinyxml2::XMLElement* child_clone = doc->NewElement("child_to_clone");
        root_clone->InsertEndChild(child_clone);
        child_clone->SetAttribute("attr", "value");
        child_clone->SetText("some text");

        tinyxml2::XMLNode* cloned_node = root_clone->DeepClone(doc.get());
        // The cloned_node is now owned by 'doc'. We can insert it or just let it be cleaned up by 'doc's destructor.
        if (cloned_node) {
            doc->InsertEndChild(cloned_node); // Add to the document to ensure it's part of the tree
        }
    }

    // New API Coverage Block: tinyxml2::XMLElement::InsertNewComment/Text/Declaration/Unknown
    /*
     * ANALYSIS: The function-level coverage report showed tinyxml2::XMLElement::InsertNewComment, InsertNewText,
     *           InsertNewDeclaration, and InsertNewUnknown all had 0% coverage.
     * IMPLEMENTATION: Create an XMLElement and use these factory methods to add different types of nodes as its children.
     */
    {
        tinyxml2::XMLElement* root_factory = doc->NewElement("root_factory");
        doc->InsertEndChild(root_factory);

        std::string comment_str = fdp.ConsumeRandomLengthString(std::min((size_t)20, fdp.remaining_bytes()));
        if (!comment_str.empty()) {
            root_factory->InsertNewComment(comment_str.c_str());
        }

        std::string text_str = fdp.ConsumeRandomLengthString(std::min((size_t)20, fdp.remaining_bytes()));
        if (!text_str.empty()) {
            root_factory->InsertNewText(text_str.c_str());
        }

        std::string decl_str = fdp.ConsumeRandomLengthString(std::min((size_t)20, fdp.remaining_bytes()));
        if (!decl_str.empty()) {
            root_factory->InsertNewDeclaration(decl_str.c_str());
        }

        std::string unknown_str = fdp.ConsumeRandomLengthString(std::min((size_t)20, fdp.remaining_bytes()));
        if (!unknown_str.empty()) {
            root_factory->InsertNewUnknown(unknown_str.c_str());
        }
    }

    // New API Coverage Block: tinyxml2::XMLHandle and tinyxml2::XMLConstHandle methods
    /*
     * ANALYSIS: The function-level coverage report showed all constructors and methods for tinyxml2::XMLHandle
     *           and tinyxml2::XMLConstHandle had 0% coverage. These are utility classes for safe tree navigation.
     * IMPLEMENTATION: Create a small XML tree, then use XMLHandle and XMLConstHandle to navigate it and call various methods.
     */
    {
        tinyxml2::XMLElement* handle_root = doc->NewElement("handle_root");
        doc->InsertEndChild(handle_root);
        tinyxml2::XMLElement* handle_child1 = doc->NewElement("handle_child1");
        handle_root->InsertEndChild(handle_child1);
        tinyxml2::XMLElement* handle_child2 = doc->NewElement("handle_child2");
        handle_root->InsertEndChild(handle_child2);
        tinyxml2::XMLText* handle_text = doc->NewText("handle text");
        handle_child1->InsertEndChild(handle_text);

        // Test XMLHandle
        tinyxml2::XMLHandle handle(handle_root);
        handle = handle; // Test assignment operator
        tinyxml2::XMLHandle handle_copy(handle); // Test copy constructor

        handle.FirstChildElement("handle_child1");
        handle.FirstChild();
        handle.LastChildElement();
        handle.LastChild();
        handle.NextSiblingElement();
        handle.NextSibling();
        handle.PreviousSiblingElement();
        handle.PreviousSibling();
        handle.ToElement();
        handle.ToText();
        handle.ToUnknown();
        handle.ToDeclaration();

        // Test XMLConstHandle
        tinyxml2::XMLConstHandle const_handle(static_cast<const tinyxml2::XMLNode*>(handle_root));
        const_handle = const_handle; // Test assignment operator
        tinyxml2::XMLConstHandle const_handle_copy(const_handle); // Test copy constructor

        const_handle.FirstChildElement("handle_child1");
        const_handle.FirstChild();
        const_handle.LastChildElement();
        const_handle.LastChild();
        const_handle.NextSiblingElement();
        const_handle.NextSibling();
        const_handle.PreviousSiblingElement();
        const_handle.PreviousSibling();
        const_handle.ToElement();
        const_handle.ToText();
        const_handle.ToUnknown();
        const_handle.ToDeclaration();
    }

    // Additional coverage for XMLVisitor methods
    /*
     * ANALYSIS: The function-level coverage report showed many XMLVisitor functions (e.g., VisitEnter, Visit) with 0% coverage.
     *           Calling XMLDocument::Accept with a custom visitor will trigger these as it traverses the document tree.
     * IMPLEMENTATION: Create a simple FuzzVisitor and pass it to doc->Accept(). This was already present,
     *                 but it's good to ensure it's still called after adding more complex structures.
     */
    FuzzVisitor visitor;
    doc->Accept(&visitor);

    // New API Coverage Block: tinyxml2::XMLPrinter functions
    /*
     * ANALYSIS: The function-level coverage report showed tinyxml2::XMLPrinter::Print, PushHeader,
     *           and various PushText overloads had 0% coverage.
     * IMPLEMENTATION: Create an XMLPrinter and use it to print a document, and call PushHeader and PushText overloads.
     */
    {
        tinyxml2::XMLPrinter printer;
        // Print a simple document to cover XMLPrinter::Print
        doc->Print(&printer);

        // Call PushHeader
        printer.PushHeader(fdp.ConsumeBool(), fdp.ConsumeBool());

        // Call PushText overloads
        printer.PushText(fdp.ConsumeIntegral<long>());
        printer.PushText(fdp.ConsumeIntegral<unsigned long>());
        printer.PushText(fdp.ConsumeIntegral<int>());
        printer.PushText(fdp.ConsumeIntegral<unsigned int>());
        printer.PushText(fdp.ConsumeBool());
        printer.PushText(fdp.ConsumeFloatingPoint<float>());
        printer.PushText(fdp.ConsumeFloatingPoint<double>());

        // Also cover ClearBuffer and CStrSize
        printer.ClearBuffer(fdp.ConsumeBool());
        printer.CStrSize();
    }

    // New API Coverage Block: tinyxml2::XMLDocument::LoadFile and SaveFile
    /*
     * ANALYSIS: The function-level coverage report showed tinyxml2::XMLDocument::LoadFile(char const*)
     *           and SaveFile(char const*, bool) had some missed lines/branches.
     *           Specifically, LoadFile(FILE*) and SaveFile(FILE*) overloads also had missed coverage.
     * IMPLEMENTATION: Create a temporary file, save the document to it, then load it back.
     *                 Also test the FILE* overloads.
     */
    {
        std::string filename = std::string("/tmp/") + _FUZZ_TARGET_NAME + ".xml";

        // SaveFile(char const*, bool)
        doc->SaveFile(filename.c_str(), fdp.ConsumeBool());

        // LoadFile(char const*)
        std::unique_ptr<tinyxml2::XMLDocument> loaded_doc_path(new tinyxml2::XMLDocument());
        loaded_doc_path->LoadFile(filename.c_str());

        // SaveFile(FILE*)
        FILE* fp_save = fopen(filename.c_str(), "wb");
        if (fp_save) {
            doc->SaveFile(fp_save, fdp.ConsumeBool());
            fclose(fp_save);
        }

        // LoadFile(FILE*)
        FILE* fp_load = fopen(filename.c_str(), "rb");
        if (fp_load) {
            std::unique_ptr<tinyxml2::XMLDocument> loaded_doc_fp(new tinyxml2::XMLDocument());
            loaded_doc_fp->LoadFile(fp_load);
            fclose(fp_load);
        }

        // Clean up the temporary file
        unlink(filename.c_str());
    }

    // New API Coverage Block: tinyxml2::XMLDocument::NewComment, NewDeclaration, NewUnknown
    /*
     * ANALYSIS: The function-level coverage report showed tinyxml2::XMLDocument::NewComment,
     *           NewDeclaration, and NewUnknown had 0% coverage.
     * IMPLEMENTATION: Call these factory methods directly on the document.
     */
    {
        std::string comment_val = fdp.ConsumeRandomLengthString(std::min((size_t)20, fdp.remaining_bytes()));
        if (!comment_val.empty()) {
            doc->NewComment(comment_val.c_str());
        }
        std::string decl_val = fdp.ConsumeRandomLengthString(std::min((size_t)20, fdp.remaining_bytes()));
        if (!decl_val.empty()) {
            doc->NewDeclaration(decl_val.c_str());
        }
        std::string unknown_val = fdp.ConsumeRandomLengthString(std::min((size_t)20, fdp.remaining_bytes()));
        if (!unknown_val.empty()) {
            doc->NewUnknown(unknown_val.c_str());
        }
    }

    return 0;
}