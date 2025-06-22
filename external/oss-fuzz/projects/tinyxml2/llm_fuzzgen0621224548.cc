#include <fuzzer/FuzzedDataProvider.h>
#include "/src/tinyxml2/tinyxml2.h" // All headers provided
#include <string>
#include <vector>
#include <cstdio> // For FILE operations, specifically stdout
#include <memory> // For std::unique_ptr

// Define a custom visitor to exercise XMLDocument::Accept and XMLElement::Accept
// This also helps cover the virtual Visit functions in XMLVisitor.
class FuzzVisitor : public tinyxml2::XMLVisitor {
public:
    FuzzVisitor() = default;

    // Implement virtual functions to ensure they are called and to avoid pure virtual errors.
    // Returning true allows traversal to continue.
    bool VisitEnter(const tinyxml2::XMLDocument& /*doc*/) override { return true; }
    bool VisitExit(const tinyxml2::XMLDocument& /*doc*/) override { return true; }
    bool VisitEnter(const tinyxml2::XMLElement& /*element*/, const tinyxml2::XMLAttribute* /*firstAttribute*/) override { return true; }
    bool VisitExit(const tinyxml2::XMLElement& /*element*/) override { return true; }
    bool Visit(const tinyxml2::XMLDeclaration& /*declaration*/) override { return true; }
    bool Visit(const tinyxml2::XMLText& /*text*/) override { return true; }
    bool Visit(const tinyxml2::XMLComment& /*comment*/) override { return true; }
    bool Visit(const tinyxml2::XMLUnknown& /*unknown*/) override { return true; }
    // The original code had 'bool Visit(const tinyxml2::XMLAttribute& /*attribute*/) override { return true; }'
    // This was incorrect as XMLVisitor does not have a virtual Visit method for XMLAttribute.
    // XMLAttributes are typically visited as part of an XMLElement's VisitEnter.
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // Use std::unique_ptr for XMLDocument to ensure proper memory management (RAII).
    // The XMLDocument manages its own internal memory pools for nodes and attributes,
    // so all objects created via doc->New* methods are automatically freed when 'doc' is destroyed.
    // Replaced std::make_unique with direct new and unique_ptr constructor for broader C++ standard compatibility.
    std::unique_ptr<tinyxml2::XMLDocument> doc(new tinyxml2::XMLDocument());

    // Create a root element for the document to have some structure to print
    tinyxml2::XMLElement* root = doc->NewElement("root");
    doc->InsertFirstChild(root);

    // Add some fuzzed content to the root element to make the XML non-empty
    std::string elementName = fdp.ConsumeRandomLengthString(10);
    if (!elementName.empty()) {
        tinyxml2::XMLElement* child = doc->NewElement(elementName.c_str());
        root->InsertEndChild(child);

        std::string attributeName = fdp.ConsumeRandomLengthString(10);
        std::string attributeValue = fdp.ConsumeRandomLengthString(20);
        if (!attributeName.empty()) {
            child->SetAttribute(attributeName.c_str(), attributeValue.c_str());
        }

        std::string textContent = fdp.ConsumeRandomLengthString(50);
        if (!textContent.empty()) {
            tinyxml2::XMLText* textNode = doc->NewText(textContent.c_str());
            child->InsertEndChild(textNode);
        }
    }

    // --- 1. Fuzz tinyxml2::XMLPrinter ---
    // The 'Print' method of XMLPrinter that takes a format string is protected.
    // To exercise XMLPrinter's functionality, we use XMLDocument::Print,
    // which internally uses an XMLPrinter instance to serialize the document.

    // Case 1: Print to stdout (FILE* is not null)
    // Initialize XMLPrinter with stdout to exercise the '_fp' branch.
    tinyxml2::XMLPrinter printerStdout(stdout);
    doc->Print(&printerStdout); // Use doc->Print to exercise the printer

    // Case 2: Print to internal buffer (FILE* is null)
    // Initialize XMLPrinter with its default constructor to exercise the internal buffer path.
    tinyxml2::XMLPrinter printerBuffer;
    doc->Print(&printerBuffer); // Use doc->Print to exercise the printer
    // Access the internal buffer to ensure the Print call had an effect and potentially trigger more code.
    (void)printerBuffer.CStr(); // CStr() returns a pointer to the internal buffer, no memory to free here.

    // --- 2. Fuzz tinyxml2::XMLUtil::SetBoolSerialization(char const*, char const*) ---
    // Goal: Cover the branches where 'writeTrue' and 'writeFalse' parameters are nullptr.

    // Case 1: Both parameters are nullptr. This specifically targets the uncovered 'False' branches.
    tinyxml2::XMLUtil::SetBoolSerialization(nullptr, nullptr);

    // Case 2: Both parameters are valid strings.
    std::string trueStr = fdp.ConsumeRandomLengthString(10);
    std::string falseStr = fdp.ConsumeRandomLengthString(10);
    tinyxml2::XMLUtil::SetBoolSerialization(trueStr.c_str(), falseStr.c_str());

    // --- 3. Fuzz tinyxml2::XMLDocument::LoadFile(char const*) ---
    // Goal: Cover the 'XML_ERROR_FILE_NOT_FOUND' error path.

    // Generate a random filename that is highly unlikely to exist.
    std::string nonExistentFilename = fdp.ConsumeRandomLengthString(20) + ".xml";
    doc->LoadFile(nonExistentFilename.c_str());
    // The unique_ptr 'doc' will handle its own cleanup, including any internal buffers
    // allocated during the LoadFile attempt.
    (void)doc->ErrorID(); // Check the error code (optional, but good for verification).

    // --- 4. Fuzz tinyxml2::XMLText::ShallowClone(tinyxml2::XMLDocument*) const ---
    // Goal: Attempt to cover the 'if (clone)' false branch, which occurs if NewText returns nullptr.
    // This is achieved by trying to exhaust the document's internal memory pool.

    // Create a large number of XMLText nodes to put pressure on the memory allocator.
    // The number of nodes is fuzzed to explore different memory allocation scenarios.
    const int num_nodes_to_create = fdp.ConsumeIntegralInRange<int>(0, 1000);
    for (int i = 0; i < num_nodes_to_create; ++i) {
        std::string text_content = fdp.ConsumeRandomLengthString(10);
        // NewText allocates from the document's internal memory pool.
        // These nodes are owned by 'doc' and will be freed by its destructor.
        tinyxml2::XMLText* text_node = doc->NewText(text_content.c_str());
        // We don't need to store or explicitly delete 'text_node' as 'doc' owns it.
        (void)text_node; // Use to avoid unused variable warning.
    }

    // Create an XMLText object to attempt to clone.
    std::string original_text_content = fdp.ConsumeRandomLengthString(50);
    tinyxml2::XMLText* original_text = doc->NewText(original_text_content.c_str());

    if (original_text) {
        // Attempt to shallow clone the original_text.
        // ShallowClone returns a raw pointer to a newly allocated node from the document's memory pool.
        // This cloned node is also owned by 'doc' and will be freed by its destructor.
        tinyxml2::XMLText* cloned_text = original_text->ShallowClone(doc.get())->ToText();
        (void)cloned_text; // Use to avoid unused variable warning.
    }

    // --- Additional fuzzing for general coverage and robustness ---

    // Parse some XML input provided by the fuzzer.
    std::string xml_input = fdp.ConsumeRemainingBytesAsString();
    if (!xml_input.empty()) {
        doc->Parse(xml_input.c_str());
    }

    // Exercise XMLDocument::Accept with the custom FuzzVisitor.
    // This helps cover the XMLDocument::Accept function and the virtual Visit methods.
    FuzzVisitor visitor;
    doc->Accept(&visitor);

    return 0;
}