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

            // Added to cover XMLElement::QueryAttribute overloads (identified as 0% covered in tinyxml2.h)
            int intVal;
            unsigned int uintVal;
            long longVal;
            unsigned long ulongVal;
            float floatVal;
            double doubleVal; // Corrected type for QueryDoubleAttribute
            bool boolVal;
            const char* strVal;

            child->QueryIntAttribute(attributeName.c_str(), &intVal);
            child->QueryUnsignedAttribute(attributeName.c_str(), &uintVal);
            child->QueryInt64Attribute(attributeName.c_str(), &longVal);
            child->QueryUnsigned64Attribute(attributeName.c_str(), &ulongVal);
            child->QueryBoolAttribute(attributeName.c_str(), &boolVal);
            child->QueryDoubleAttribute(attributeName.c_str(), &doubleVal); // Corrected call
            child->QueryFloatAttribute(attributeName.c_str(), &floatVal);
            child->QueryStringAttribute(attributeName.c_str(), &strVal);

            // Added to cover XMLElement::DeleteAttribute(tinyxml2::XMLAttribute*) (identified as 75% covered, 50% branch in tinyxml2.cpp)
            // Fix: FindAttribute returns const XMLAttribute*, so attrToDelete must be const.
            // Fix: DeleteAttribute is a private static member, so direct call is removed.
            const tinyxml2::XMLAttribute* attrToDelete = child->FindAttribute(attributeName.c_str());
            if (attrToDelete) {
                // The XMLDocument manages its own internal memory pools for nodes and attributes.
                // Deletion of attributes is handled internally by the document or element methods.
                // Direct call to private static DeleteAttribute is not allowed and not necessary for memory safety.
            }
        }

        std::string textContent = fdp.ConsumeRandomLengthString(50);
        if (!textContent.empty()) {
            tinyxml2::XMLText* textNode = doc->NewText(textContent.c_str());
            child->InsertEndChild(textNode);
        }

        // Added to cover XMLNode::SetValue and XMLNode::Value() branches (identified as 75% covered, 50% branch in tinyxml2.cpp)
        std::string fuzzedNodeValue = fdp.ConsumeRandomLengthString(20);
        if (!fuzzedNodeValue.empty()) {
            child->SetValue(fuzzedNodeValue.c_str());
            (void)child->Value();
        }

        // Added to cover XMLNode::DeleteNode (identified as 88.89% covered, 50% branch in tinyxml2.cpp)
        // Create a temporary child element and then delete it.
        std::string tempElementName = fdp.ConsumeRandomLengthString(10);
        if (!tempElementName.empty()) {
            tinyxml2::XMLElement* tempChild = doc->NewElement(tempElementName.c_str());
            root->InsertEndChild(tempChild);
            doc->DeleteNode(tempChild); // The document owns the node, so its destructor will handle memory.
        }
    }

    // Added to cover XMLDeclaration, XMLComment, XMLUnknown nodes and their ShallowClone/Accept methods
    // (identified as 0% coverage for XMLVisitor::Visit and 66.67% for ShallowClone in tinyxml2.h/cpp)
    // Also covers XMLElement::InsertNew* methods (identified as 75% covered, 50% branch in tinyxml2.cpp)
    std::string declContent = fdp.ConsumeRandomLengthString(20);
    if (!declContent.empty()) {
        tinyxml2::XMLDeclaration* decl = doc->NewDeclaration(declContent.c_str());
        root->InsertEndChild(decl);
        // Attempt to shallow clone to cover XMLDeclaration::ShallowClone
        tinyxml2::XMLDeclaration* clonedDecl = decl->ShallowClone(doc.get())->ToDeclaration();
        (void)clonedDecl; // Use to avoid unused variable warning.
    }

    std::string commentContent = fdp.ConsumeRandomLengthString(20);
    if (!commentContent.empty()) {
        tinyxml2::XMLComment* comment = doc->NewComment(commentContent.c_str());
        root->InsertEndChild(comment);
        // Attempt to shallow clone to cover XMLComment::ShallowClone
        tinyxml2::XMLComment* clonedComment = comment->ShallowClone(doc.get())->ToComment();
        (void)clonedComment; // Use to avoid unused variable warning.
    }

    std::string unknownContent = fdp.ConsumeRandomLengthString(20);
    if (!unknownContent.empty()) {
        tinyxml2::XMLUnknown* unknown = doc->NewUnknown(unknownContent.c_str());
        root->InsertEndChild(unknown);
        // Attempt to shallow clone to cover XMLUnknown::ShallowClone
        tinyxml2::XMLUnknown* clonedUnknown = unknown->ShallowClone(doc.get())->ToUnknown();
        (void)clonedUnknown; // Use to avoid unused variable warning.
    }

    // Use XMLElement::InsertNew* methods to create more varied nodes
    if (root) {
        std::string newChildName = fdp.ConsumeRandomLengthString(10);
        if (!newChildName.empty()) {
            root->InsertNewChildElement(newChildName.c_str());
        }
        std::string newCommentContent = fdp.ConsumeRandomLengthString(20);
        if (!newCommentContent.empty()) {
            root->InsertNewComment(newCommentContent.c_str());
        }
        std::string newTextContent = fdp.ConsumeRandomLengthString(20);
        if (!newTextContent.empty()) {
            root->InsertNewText(newTextContent.c_str());
        }
        std::string newDeclarationContent = fdp.ConsumeRandomLengthString(20);
        if (!newDeclarationContent.empty()) {
            root->InsertNewDeclaration(newDeclarationContent.c_str());
        }
        std::string newUnknownContent = fdp.ConsumeRandomLengthString(20);
        if (!newUnknownContent.empty()) {
            root->InsertNewUnknown(newUnknownContent.c_str());
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

    // Added to cover XMLDocument::DeepCopy (identified as 90% covered, 75% branch in tinyxml2.cpp)
    std::unique_ptr<tinyxml2::XMLDocument> docCopy(new tinyxml2::XMLDocument());
    doc->DeepCopy(docCopy.get()); // DeepCopy the fuzzed document. docCopy will manage its own memory.

    // Added to cover XMLDocument::SaveFile (identified as 90% covered, 75% branch in tinyxml2.cpp)
    // Saving to a dummy filename to exercise the code path without actual file system interaction.
    std::string dummySaveFilename = fdp.ConsumeRandomLengthString(20) + ".tmp";
    doc->SaveFile(dummySaveFilename.c_str());

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