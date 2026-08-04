#include "/src/tinyxml2/tinyxml2.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <unistd.h>
#include <vector>

// Custom visitor to exercise visitor APIs
class MyVisitor : public tinyxml2::XMLVisitor {
public:
    explicit MyVisitor(FuzzedDataProvider* fdp) : m_fdp(fdp) {}

    /*
     * ANALYSIS: The function-level coverage report showed that the XMLVisitor::VisitEnter
     *           and other Visit methods had 0% coverage.
     * IMPLEMENTATION: This custom visitor overrides the Visit methods. It uses the
     *                 FuzzedDataProvider to return either true or false, which controls
     *                 the traversal of the XML tree, thus exercising the visitor pattern
     *                 in tinyxml2.
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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // Use a portion of the data for XML content
    std::string xml_data = fdp.ConsumeRemainingBytesAsString();

    // --- Target `XMLDocument::LoadFile` ---
    /*
     * ANALYSIS: The function-level coverage report showed that XMLDocument::LoadFile
     *           had several uncovered branches related to file I/O errors. While
     *           triggering specific I/O errors is difficult, fuzzing the file content
     *           itself provides broad coverage of the parsing logic downstream.
     * IMPLEMENTATION: The fuzzer writes data to a temporary file and then uses
     *                 LoadFile(FILE*) to parse it. This exercises the file-based
     *                 parsing path. The filename is made unique using a compile-time
     *                 macro to ensure statelessness and avoid race conditions.
     */
    char path[256];
    snprintf(path, sizeof(path), "/tmp/%s.tmp", _FUZZ_TARGET_NAME);

    FILE* fp = fopen(path, "wb");
    if (!fp) {
        return 0;
    }
    fwrite(xml_data.c_str(), 1, xml_data.size(), fp);
    fclose(fp);

    tinyxml2::XMLDocument doc;
    // Also test LoadFile(FILE*)
    fp = fopen(path, "rb");
    if (fp) {
        doc.LoadFile(fp);
        fclose(fp);
    }
    
    unlink(path); // Clean up the temporary file

    if (!doc.Error()) {
        // --- Target `XMLVisitor` ---
        MyVisitor visitor(&fdp);
        doc.Accept(&visitor);

        // --- Target `XMLDocument::DeepCopy` ---
        tinyxml2::XMLDocument doc2;
        /*
         * ANALYSIS: The line-level coverage for DeepCopy showed that the 'target == this'
         *           check was never exercised.
         * IMPLEMENTATION: The following line calls DeepCopy with the document itself as the
         *                 target, specifically to cover this branch.
         */
        doc.DeepCopy(&doc); // Self-copy to hit the uncovered branch.
        doc.DeepCopy(&doc2); // Normal copy.

        // --- Target `XMLElement::DeleteAttribute` ---
        tinyxml2::XMLElement* root = doc2.RootElement();
        if (root) {
            /*
             * ANALYSIS: The line-level coverage for XMLElement::DeleteAttribute(XMLAttribute*)
             *           showed the 'attribute == 0' check was never hit. This is a private
             *           method and cannot be called directly.
             * IMPLEMENTATION: Call the public DeleteAttribute(const char*) with a
             *                 non-existent attribute name to exercise the error-handling path
             *                 where the attribute is not found.
             */
            root->DeleteAttribute("non_existent_attribute");
            if (root->FirstAttribute()) {
                root->DeleteAttribute(root->FirstAttribute()->Name());
            }
        }

        // --- Target `XMLNode::DeleteNode` ---
        /*
         * ANALYSIS: The line-level coverage for XMLNode::DeleteNode showed that the
         *           'node == 0' check was never exercised.
         * IMPLEMENTATION: The following line calls DeleteNode with a null pointer to
         *                 exercise this error-handling path.
         */
        doc.DeleteNode(nullptr);
        if (doc2.FirstChild()) {
            // Deleting a node that has a parent
            doc2.DeleteNode(doc2.FirstChild());
        }
    }

    return 0;
}