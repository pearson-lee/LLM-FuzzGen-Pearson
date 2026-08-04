/* BLOCKER_STRATEGY_CONTRACT
required_state: The `input` parameter of `tinyxml2::XMLUtil::ConvertUTF32ToUTF8` must be >= `0x200000`.
state_constructor: A direct call to `tinyxml2::XMLUtil::ConvertUTF32ToUTF8` with an `input` value consumed from `FuzzedDataProvider` in the range `[0x200000, 0xFFFFFFFF]`. The call path through `doc.Parse()` and `GetCharacterRef` is insufficient as `GetCharacterRef` filters values > `0x10FFFF`.
trigger_api: `tinyxml2::XMLUtil::ConvertUTF32ToUTF8(input, ...)`
preserved_invariants: All existing `fdp.Consume...` calls and API invocations are preserved in their original order. The new logic is added at the end of the function to avoid invalidating existing test cases.
END_BLOCKER_STRATEGY_CONTRACT */

#include <cstddef>
#include <cstdint>
#include <string>
#include <unistd.h>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>
#include "/src/tinyxml2/tinyxml2.h"

// Custom visitor to exercise the XMLVisitor interface.
class MyVisitor : public tinyxml2::XMLVisitor {
public:
    bool VisitEnter(const tinyxml2::XMLElement&, const tinyxml2::XMLAttribute*) override { return true; }
    bool VisitExit(const tinyxml2::XMLElement&) override { return true; }
    bool Visit(const tinyxml2::XMLDeclaration&) override { return true; }
    bool Visit(const tinyxml2::XMLText&) override { return true; }
    bool Visit(const tinyxml2::XMLComment&) override { return true; }
    bool Visit(const tinyxml2::XMLUnknown&) override { return true; }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // Create the main XML document. All nodes are owned by this document.
    tinyxml2::XMLDocument doc;

    std::string xml_data = fdp.ConsumeRandomLengthString();

    /*
     * ANALYSIS: The function-level coverage report showed XMLDocument::LoadFile
     *           had low line and branch coverage. The line-level report confirmed
     *           this was due to untested error handling, such as when fopen fails.
     * IMPLEMENTATION: The following code block writes fuzzed data to a temporary
     *                 file and attempts to load it. It also attempts to load from
     *                 an invalid path to trigger the fopen failure branch.
     */
    {
        // Define a unique temporary file path.
        const std::string path = "/tmp/llm_fuzzgen.tmp";
        FILE* fp = fopen(path.c_str(), "w");
        if (fp) {
            fwrite(xml_data.c_str(), 1, xml_data.size(), fp);
            fclose(fp);
            // Attempt to load the created file.
            doc.LoadFile(path.c_str());
            // Clean up the temporary file.
            unlink(path.c_str());
        }

        // Attempt to load from a likely invalid path to trigger error.
        doc.LoadFile("/tmp");
    }

    /*
     * ANALYSIS: The coverage report for XMLDocument::SaveFile showed that the
     *           error handling for a failed file open was not covered.
     * IMPLEMENTATION: Call SaveFile with a path that is intentionally invalid
     *                 to trigger the fopen failure branch.
     */
    doc.SaveFile("/invalid_path/test.xml", false);


    // Parse the XML data directly to continue testing other APIs.
    doc.Parse(xml_data.c_str());

    /*
     * ANALYSIS: The function-level coverage report showed that all methods of
     *           the XMLVisitor class were completely uncovered (0% coverage).
     * IMPLEMENTATION: A custom visitor `MyVisitor` is defined above. Here, we
     *                 create an instance of it and call `doc.Accept()` to traverse
     *                 the parsed document, thereby exercising all the `Visit` methods.
     */
    MyVisitor visitor;
    doc.Accept(&visitor);

    // Create some nodes to test node-specific APIs.
    tinyxml2::XMLElement* root = doc.NewElement(fdp.ConsumeRandomLengthString(10).c_str());
    if (root) {
        doc.InsertFirstChild(root);

        /*
         * ANALYSIS: The function-level coverage report showed that XMLNode::GetDocument()
         *           and XMLDocument::RootElement() were completely uncovered.
         * IMPLEMENTATION: Call these methods to ensure they are exercised.
         */
        root->GetDocument();
        doc.RootElement();

        tinyxml2::XMLText* text1 = doc.NewText(fdp.ConsumeRandomLengthString(20).c_str());
        tinyxml2::XMLText* text2 = doc.NewText(text1->Value()); // Same value as text1
        tinyxml2::XMLComment* comment1 = doc.NewComment(fdp.ConsumeRandomLengthString(20).c_str());

        if (text1 && text2 && comment1) {
            root->InsertEndChild(text1);
            root->InsertEndChild(text2);
            root->InsertEndChild(comment1);

            /*
             * ANALYSIS: The ShallowEqual methods for XMLText, XMLComment, etc.,
             *           had uncovered branches. Specifically, the case where the
             *           compared node is of a different type was missed, as was the
             *           case where two nodes of the same type have equal values.
             * IMPLEMENTATION: We call ShallowEqual to compare a text node with a
             *                 comment node (triggers wrong-type branch). We also
             *                 compare two text nodes that were created with the
             *                 same value (triggers equal-value branch).
             */
            text1->ShallowEqual(comment1); // Compare different types.
            text1->ShallowEqual(text2);    // Compare same types with same value.
            
            /*
             * ANALYSIS: The line coverage for various ShallowClone methods (XMLText,
             *           XMLComment, etc.) shows that the branch for a null document
             *           argument is never taken.
             * IMPLEMENTATION: Call ShallowClone with a nullptr argument. The returned
             *                 node is owned by the document and will be freed automatically.
             */
            text1->ShallowClone(nullptr);
        }

        /*
         * ANALYSIS: The line coverage report for XMLElement::DeleteAttribute
         *           showed two uncovered paths: deleting a null attribute, and
         *           deleting an attribute that is not the first one in the list.
         *           Additionally, the overload taking an XMLAttribute* was not covered.
         * IMPLEMENTATION: We call DeleteAttribute with nullptr to cover the null
         *                 check. Then we add two attributes and delete the second
         *                 one to exercise the logic for removing a non-first attribute.
         *                 Finally, we get a pointer to the first attribute and delete it
         *                 using the `DeleteAttribute(XMLAttribute*)` overload.
         */
        root->DeleteAttribute(static_cast<const char*>(nullptr));
        root->SetAttribute(fdp.ConsumeRandomLengthString(5).c_str(), fdp.ConsumeRandomLengthString(5).c_str());
        const std::string attr_name = fdp.ConsumeRandomLengthString(5);
        root->SetAttribute(attr_name.c_str(), fdp.ConsumeRandomLengthString(5).c_str());
        root->DeleteAttribute(attr_name.c_str());
        const tinyxml2::XMLAttribute* first_attr = root->FirstAttribute();
        if (first_attr) {
            root->DeleteAttribute(first_attr->Name());
        }

        /*
         * ANALYSIS: The line coverage report for XMLNode::InsertChildPreamble shows
         *           an untaken branch for when a node with an existing parent is inserted.
         * IMPLEMENTATION: Create a node, insert it, then create a second node and
         *                 insert the first node into the second, triggering the unlink logic.
         */
        tinyxml2::XMLElement* child1 = doc.NewElement("child1");
        if (child1) {
            root->InsertFirstChild(child1);
            tinyxml2::XMLElement* child2 = doc.NewElement("child2");
            if (child2) {
                root->InsertEndChild(child2);
                // Re-insert child1 under child2 to trigger the unlink logic.
                child2->InsertFirstChild(child1);
            }
        }
    }

    /*
     * ANALYSIS: The coverage report for XMLNode::DeleteNode indicated that the
     *           initial check for a null node pointer was never executed for the
     *           static `XMLNode::DeleteNode` version.
     * IMPLEMENTATION: The following line directly calls the static DeleteNode with a null
     *                 pointer to exercise this specific error-handling branch.
     */
    doc.DeleteNode(nullptr);

    /*
     * ANALYSIS: The function-level coverage report showed several `To...` methods
     *           like `ToDeclaration` and `ToUnknown` were uncovered.
     * IMPLEMENTATION: Create a declaration and an unknown node, insert them,
     *                 and then call the corresponding `To...` methods on them.
     */
    tinyxml2::XMLDeclaration* decl = doc.NewDeclaration();
    tinyxml2::XMLUnknown* unknown = doc.NewUnknown(fdp.ConsumeRandomLengthString(10).c_str());
    if (decl && unknown) {
        doc.InsertFirstChild(decl);
        doc.InsertEndChild(unknown);
        decl->ToDeclaration();
        unknown->ToUnknown();
    }

    /*
     * ANALYSIS: The coverage report for the `XMLPrinter` constructor showed a branch
     *           related to apostrophe escaping was not taken. Also, methods that use
     *           an `XMLPrinter` with a file pointer (`_fp`) were not covered.
     * IMPLEMENTATION: Construct an `XMLPrinter` with a temporary file and the
     *                 `DONT_ESCAPE_APOS_CHARS_IN_ATTRIBUTES` flag. Then call `doc.Print()`
     *                 to exercise the printing logic with these options.
     */
    {
        const std::string path = "/tmp/llm_fuzzgen_printer.tmp";
        FILE* fp = fopen(path.c_str(), "w");
        if (fp) {
            tinyxml2::XMLPrinter printer(fp, false, 0, tinyxml2::XMLPrinter::DONT_ESCAPE_APOS_CHARS_IN_ATTRIBUTES);
            doc.Print(&printer);
            fclose(fp);
            unlink(path.c_str());
        }
    }

    /*
     * ANALYSIS: The function-level coverage report showed that
     *           `XMLDocument::ShallowEqual` was uncovered.
     * IMPLEMENTATION: Create a second document and call `ShallowEqual` to
     *                 compare it with the primary document.
     */
    tinyxml2::XMLDocument doc2;
    doc.ShallowEqual(&doc2);

    /*
     * BLOCKER: tinyxml2::XMLUtil::ConvertUTF32ToUTF8
     * PREDICATE: else if ( input < 0x200000 )
     * UNREACHED: *length = 0;
     *
     * ANALYSIS: The runtime call path to the blocker function
     *           `ConvertUTF32ToUTF8` is via `XMLUtil::GetCharacterRef`.
     *           However, `GetCharacterRef` validates the parsed character
     *           reference against `MAX_CODE_POINT` (0x10FFFF), which is less
     *           than the value required (>= 0x200000) to hit the target `else`
     *           branch. The existing API path makes it impossible to reach the
     *           blocker.
     *
     * IMPLEMENTATION: To overcome this, we directly call the static utility
     *                 function `XMLUtil::ConvertUTF32ToUTF8` with a value
     *                 explicitly chosen from the fuzzer input to be in the
     *                 range that triggers the desired branch.
     */
    {
        // NOTE: No viable alternative public API route was identified from the available evidence.
        char buf[10];
        int length = 0;
        // Consume a value >= 0x200000 to trigger the target branch.
        unsigned long input = fdp.ConsumeIntegralInRange<unsigned long>(0x200000, 0xFFFFFFFF);
        tinyxml2::XMLUtil::ConvertUTF32ToUTF8(input, buf, &length);
    }


    // The XMLDocument `doc` will be destroyed at the end of this function,
    // and its destructor is responsible for freeing all memory associated
    // with the nodes (elements, text, comments, etc.) it created.

    return 0;
}