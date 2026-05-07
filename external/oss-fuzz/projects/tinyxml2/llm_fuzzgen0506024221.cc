#include "/src/tinyxml2/tinyxml2.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>
#include <memory> // For std::unique_ptr
#include <algorithm> // For std::min

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

    // API 4: tinyxml2::XMLDocument::ErrorStr() const
    /*
     * ANALYSIS: The function-level coverage report showed tinyxml2::XMLDocument::ErrorStr had 0% line and branch coverage.
     *           The line-level report indicated that the branch for _errorStr being empty was missed.
     * IMPLEMENTATION: Call ErrorStr on a document with no errors and on a document after parsing an invalid XML string.
     */
    {
        // Case 1: No error (empty _errorStr) - 'doc' is initially error-free.
        doc->ErrorStr();

        // Case 2: With error - parse an invalid XML string to set an error.
        // Replaced std::make_unique with std::unique_ptr(new ...) for C++11 compatibility.
        std::unique_ptr<tinyxml2::XMLDocument> error_doc(new tinyxml2::XMLDocument());
        std::string invalid_xml = fdp.ConsumeRandomLengthString(std::min((size_t)100, fdp.remaining_bytes()));
        error_doc->Parse(invalid_xml.c_str(), invalid_xml.length());
        error_doc->ErrorStr();
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

    // Additional coverage for XMLVisitor methods
    /*
     * ANALYSIS: The function-level coverage report showed many XMLVisitor functions (e.g., VisitEnter, Visit) with 0% coverage.
     *           Calling XMLDocument::Accept with a custom visitor will trigger these as it traverses the document tree.
     * IMPLEMENTATION: Create a simple FuzzVisitor and pass it to doc->Accept().
     */
    FuzzVisitor visitor;
    doc->Accept(&visitor);

    return 0;
}