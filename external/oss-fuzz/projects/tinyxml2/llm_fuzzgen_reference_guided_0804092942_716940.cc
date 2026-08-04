/* BLOCKER_STRATEGY_CONTRACT
required_state: `TIXML_FTELL(fp)` must return -1L inside `tinyxml2::XMLDocument::LoadFile(FILE*)`. This can be achieved by passing a `FILE*` stream that is not seekable.
state_constructor: A pipe is created using `pipe()`. The fuzzer-generated `xml_data` is written to the write-end of the pipe. The read-end is converted to a `FILE*` using `fdopen()`.
trigger_api: `doc.LoadFile(FILE*)` is called with the `FILE*` associated with the read-end of the pipe.
preserved_invariants: The original fuzzing logic, including the creation of a temporary file and parsing of `xml_data` via `LoadFile(const char*)` and `Parse()`, must be preserved. The sequence of FuzzedDataProvider consumption for the original logic must not be altered.
END_BLOCKER_STRATEGY_CONTRACT */

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

        /*
         * ANALYSIS: The original fuzzer failed to cover the deletion of actual nodes and
         *           attributes because the checks were unreliable.
         * IMPLEMENTATION: This revised logic checks for the existence of a child/attribute
         *                 and then uses fuzzer input to decide whether to delete it. This
         *                 more reliably exercises the `DeleteNode` and `DeleteAttribute` code paths.
         */
        if (doc.RootElement()->FirstChild() && fdp.ConsumeBool()) {
            doc.DeleteNode(doc.RootElement()->FirstChild());
        }

        if (doc.RootElement()->FirstAttribute() && fdp.ConsumeBool()) {
            doc.RootElement()->DeleteAttribute(doc.RootElement()->FirstAttribute()->Name());
        }

        /*
         * ANALYSIS: The function-level coverage report showed 0% coverage for many of the
         *           `To...` type conversion functions (e.g., `ToText`, `ToComment`) and low
         *           coverage for `ShallowClone`.
         * IMPLEMENTATION: The following loop iterates through the document's nodes, calling
         *                 the various `To...` functions to exercise them. It also calls
         *                 `ShallowClone` and correctly `delete`s the returned node to
         *                 prevent memory leaks while improving coverage.
         */
        for (tinyxml2::XMLNode* node = doc.RootElement()->FirstChild(); node; node = node->NextSibling()) {
            if (fdp.ConsumeBool()) {
                tinyxml2::XMLNode* clone = node->ShallowClone(&doc);
                if (clone) {
                    doc.DeleteNode(clone);
                }
            }
            (void)node->ToElement();
            (void)node->ToText();
            (void)node->ToComment();
            (void)node->ToDeclaration();
            (void)node->ToUnknown();
        }

        /*
         * ANALYSIS: The function-level coverage report showed that `XMLDocument::SaveFile`
         *           was not being exercised.
         * IMPLEMENTATION: This block calls `SaveFile` on the parsed document, writing to a
         *                 temporary file that is immediately deleted. It uses fuzzer input
         *                 to decide whether to use the compact format, thus covering more
         *                 branches within the save logic.
         */
        std::string save_filename = std::string("/tmp/") + _FUZZ_TARGET_NAME + "_save.xml";
        doc.SaveFile(save_filename.c_str(), fdp.ConsumeBool());
        unlink(save_filename.c_str());
    }

    /*
     * ANALYSIS: The function-level coverage report indicates that the entire XMLPrinter
     *           class is largely uncovered. The existing fuzzer only used the default constructor.
     *           The constructor taking a FILE* was not covered.
     * IMPLEMENTATION: The following code creates an XMLPrinter with the FILE* constructor
     *                 to exercise more of its functionality. It also uses the document's
     *                 Accept() method to print the document's content.
     */
    tinyxml2::XMLPrinter printer;
    doc.Accept(&printer);
    (void)printer.CStr(); // Access the string to ensure the work isn't optimized away.
    
    if (fdp.ConsumeBool()) {
        std::string printer_filename = std::string("/tmp/") + _FUZZ_TARGET_NAME + "_printer.xml";
        FILE* pFile = fopen(printer_filename.c_str(), "w");
        if (pFile) {
            tinyxml2::XMLPrinter file_printer(pFile, fdp.ConsumeBool(), fdp.ConsumeIntegralInRange<int>(0, 10));
            doc.Accept(&file_printer);
            fclose(pFile);
            unlink(printer_filename.c_str());
        }
    }

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

    /*
     * BLOCKER-SPECIFIC LOGIC: The blocker is in `XMLDocument::LoadFile(FILE*)`
     * and is triggered when `ftell` returns -1. This can happen on a non-seekable
     * stream like a pipe. This logic creates a pipe, writes the existing XML data
     * to it, and calls LoadFile on the read end of the pipe. This is controlled by
     * fuzzer input and uses a separate XMLDocument object to avoid interfering
     * with the state of the main 'doc' object.
     */
    if (fdp.ConsumeBool()) {
        tinyxml2::XMLDocument pipe_doc;
        int pipefd[2];
        if (pipe(pipefd) == 0) {
            // Write the already-consumed xml_data to the pipe.
            ssize_t bytes_written = write(pipefd[1], xml_data.c_str(), xml_data.size());
            (void)bytes_written;
            close(pipefd[1]); // Close the write end.

            FILE* pipe_fp = fdopen(pipefd[0], "r");
            if (pipe_fp) {
                // This call to LoadFile on a pipe should trigger the blocker.
                pipe_doc.LoadFile(pipe_fp);
                fclose(pipe_fp); // This also closes pipefd[0].
            } else {
                close(pipefd[0]);
            }
        }
    }

    return 0;
}
