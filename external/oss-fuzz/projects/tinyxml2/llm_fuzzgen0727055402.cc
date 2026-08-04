#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <unistd.h>

#include <fuzzer/FuzzedDataProvider.h>
#include "/src/tinyxml2/tinyxml2.h"

// Custom visitor to exercise the XMLVisitor API
class MyVisitor : public tinyxml2::XMLVisitor {
public:
    explicit MyVisitor(FuzzedDataProvider* fdp) : m_fdp(fdp) {}
    virtual ~MyVisitor() {}

    /*
     * ANALYSIS: The function-level coverage report shows that all `XMLVisitor` virtual
     *           functions are completely uncovered (0% coverage).
     * IMPLEMENTATION: The methods below are overrides of the base `XMLVisitor` class.
     *                 They use the FuzzedDataProvider to return random boolean values.
     *                 This exercises the control flow in the `Accept` methods of
     *                 different node types, which depend on the visitor's return values
     *                 to decide whether to continue or stop the DOM traversal.
     */
    bool VisitEnter(const tinyxml2::XMLElement&, const tinyxml2::XMLAttribute*) override {
        return m_fdp->ConsumeBool();
    }
    bool VisitExit(const tinyxml2::XMLElement&) override {
        return m_fdp->ConsumeBool();
    }
    bool Visit(const tinyxml2::XMLDeclaration&) override {
        return m_fdp->ConsumeBool();
    }
    bool Visit(const tinyxml2::XMLText&) override {
        return m_fdp->ConsumeBool();
    }
    bool Visit(const tinyxml2::XMLComment&) override {
        return m_fdp->ConsumeBool();
    }
    bool Visit(const tinyxml2::XMLUnknown&) override {
        return m_fdp->ConsumeBool();
    }

private:
    FuzzedDataProvider* m_fdp;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // Set whitespace mode at construction, as there is no setter method.
    bool collapseWhitespace = fdp.ConsumeBool();
    tinyxml2::XMLDocument doc(true, collapseWhitespace ? tinyxml2::COLLAPSE_WHITESPACE : tinyxml2::PRESERVE_WHITESPACE);

    // Consume data for XML content.
    std::string xml_data = fdp.ConsumeRandomLengthString(2048);

    /*
     * ANALYSIS: The line coverage report for `XMLDocument::LoadFile(FILE*)` shows multiple
     *           uncovered branches related to file I/O errors and empty files.
     * IMPLEMENTATION: The following block creates a temporary file, writes fuzzer-generated
     *                 data to it, and then calls `doc.LoadFile()` to parse it. This
     *                 exercises the file-based parsing logic. By sometimes providing
     *                 empty data, we can also hit the `if (filelength == 0)` branch.
     *                 The file is properly named using the `_FUZZ_TARGET_NAME` macro to
     *                 prevent race conditions and is deleted before the function exits.
     */
    std::string filename = std::string("/tmp/") + _FUZZ_TARGET_NAME + ".xml";
    FILE* fp = fopen(filename.c_str(), "wb");
    if (fp) {
        fwrite(xml_data.c_str(), 1, xml_data.size(), fp);
        fclose(fp);
        // doc.LoadFile(const char*) internally calls doc.LoadFile(FILE*)
        doc.LoadFile(filename.c_str());
        unlink(filename.c_str());
    }

    /*
     * ANALYSIS: The line coverage report for `XMLDocument::Identify` shows an uncovered
     *           branch related to whitespace handling.
     * IMPLEMENTATION: The `doc` is constructed with either COLLAPSE_WHITESPACE or
     *                 PRESERVE_WHITESPACE mode based on fuzzer input. The subsequent `doc.Parse()`
     *                 call will then use this mode, allowing the fuzzer to potentially
     *                 generate an input that triggers different whitespace handling branches.
     */
    doc.Parse(xml_data.c_str(), xml_data.size());

    // If a document was successfully parsed, exercise the visitor and deletion APIs.
    if (doc.RootElement()) {
        tinyxml2::XMLElement* root = doc.RootElement();

        /*
         * ANALYSIS: The detailed fuzz target coverage report showed that the conditions
         *           `doc.RootElement()->FirstChild()` and `doc.RootElement()->FirstAttribute()`
         *           were never true, preventing the `DeleteNode` and `DeleteAttribute` calls
         *           from being exercised on actual nodes/attributes.
         * IMPLEMENTATION: The following code block uses fuzzer data to proactively
         *                 insert new child elements and attributes into a successfully parsed
         *                 document. This ensures that the deletion logic further down has
         *                 valid objects to operate on, thus covering those previously-missed branches.
         */
        if (fdp.ConsumeBool()) {
            std::string elemName = fdp.ConsumeRandomLengthString(16);
            if (!elemName.empty()) {
                root->InsertNewChildElement(elemName.c_str());
            }
        }
        if (fdp.ConsumeBool()) {
            std::string attrName = fdp.ConsumeRandomLengthString(16);
            std::string attrValue = fdp.ConsumeRandomLengthString(16);
            if (!attrName.empty()) {
                root->SetAttribute(attrName.c_str(), attrValue.c_str());
            }
        }

        // Instantiate and use the custom visitor.
        MyVisitor visitor(&fdp);
        doc.Accept(&visitor);

        // Exercise deletion APIs with both valid and invalid (nullptr) inputs.
        // These are now more likely to have something to delete.
        if (fdp.ConsumeBool() && doc.RootElement()->FirstChild()) {
            // Delete a real node to exercise the main logic path.
            doc.DeleteNode(doc.RootElement()->FirstChild());
        }

        if (fdp.ConsumeBool() && doc.RootElement()->FirstAttribute()) {
            // Delete a real attribute to exercise the main logic path.
            doc.RootElement()->DeleteAttribute(doc.RootElement()->FirstAttribute()->Name());
        }
    }

    /*
     * ANALYSIS: The function-level coverage report indicates that the entire XMLPrinter
     *           class is largely uncovered.
     * IMPLEMENTATION: The following code creates an XMLPrinter, uses the document's Accept()
     *                 method to visit nodes and print the document's content, and then
     *                 retrieves the resulting string. This exercises the core printing logic.
     */
    tinyxml2::XMLPrinter printer;
    doc.Accept(&printer);
    (void)printer.CStr(); // Access the string to ensure the work isn't optimized away.

    /*
     * ANALYSIS: The function-level coverage report shows 0% coverage for XMLHandle,
     *           XMLConstHandle, and various node conversion functions (e.g., ToElement, ToText).
     * IMPLEMENTATION: The following block creates both XMLHandle and XMLConstHandle to wrap
     *                 the document. It then calls various navigation methods
     *                 on them to exercise this family of uncovered functions.
     */
    if (fdp.ConsumeBool()) {
        tinyxml2::XMLHandle handle(&doc);
        handle.FirstChild();
        handle.FirstChildElement();
        handle.LastChild();
    }
    if (fdp.ConsumeBool()) {
        tinyxml2::XMLConstHandle constHandle(&doc);
        constHandle.FirstChild();
        constHandle.FirstChildElement();
        constHandle.LastChild();
    }

    /*
     * ANALYSIS: The function-level coverage report shows low coverage for the cloning functions
     *           like `DeepClone` and the various `ShallowClone` implementations.
     * IMPLEMENTATION: The following code calls `DeepClone` on the document. The result is a
     *                 new XMLDocument that owns its own memory, so it must be explicitly deleted
     *                 to prevent a memory leak. This exercises the deep-copy logic.
     */
    if (fdp.ConsumeBool()) {
        tinyxml2::XMLDocument* clone = new tinyxml2::XMLDocument();
        doc.DeepClone(clone);
        if (clone) {
            // The cloned document must be deleted to avoid a memory leak.
            delete clone;
        }
    }

    /*
     * ANALYSIS: The line coverage report for `XMLNode::DeleteNode` shows that the
     *           initial `if (node == nullptr)` check is never taken.
     * IMPLEMENTATION: The following code explicitly calls `DeleteNode` with `nullptr` to
     *                 cover this simple but important null-check branch.
     */
    if (fdp.ConsumeBool()) {
        doc.DeleteNode(nullptr);
    }

    return 0;
}