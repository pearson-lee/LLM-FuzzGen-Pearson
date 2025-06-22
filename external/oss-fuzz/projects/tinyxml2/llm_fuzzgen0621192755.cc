#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <memory> // For std::unique_ptr
#include <functional> // Required for std::function
#include <cstdio> // For FILE and vfprintf in XMLPrinter::Print
#include <fuzzer/FuzzedDataProvider.h>

// Always emit #include with the full project-relative path in quotes.
#include "/src/tinyxml2/tinyxml2.h"

// Define a helper to manage XMLDocument lifetime using RAII
struct XMLDocumentDeleter {
    void operator()(tinyxml2::XMLDocument* doc) const {
        if (doc) {
            doc->Clear(); // Clear any allocated memory within the document
            delete doc;
        }
    }
};

// A. Custom XMLVisitor to cover Visit methods
// This class overrides all virtual Visit and VisitEnter/Exit methods
// to ensure they are called when XMLDocument::Accept is invoked.
class TestVisitor : public tinyxml2::XMLVisitor {
public:
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

    // Use std::unique_ptr for automatic memory management of XMLDocument
    std::unique_ptr<tinyxml2::XMLDocument, XMLDocumentDeleter> doc_ptr(new tinyxml2::XMLDocument());
    tinyxml2::XMLDocument* doc = doc_ptr.get();

    // B. Cover tinyxml2::XMLDocument::SetBOM(bool)
    // This directly calls the SetBOM method which had 0% coverage.
    doc->SetBOM(fdp.ConsumeBool());

    // F. Cover tinyxml2::XMLUtil::SetBoolSerialization
    // This static utility function was uncovered. Calling it directly.
    tinyxml2::XMLUtil::SetBoolSerialization(fdp.ConsumeBool() ? "true" : "yes", fdp.ConsumeBool() ? "false" : "no");

    // I. Cover tinyxml2::StrPair::SetInternedStr(const char *)
    // This function had 0% coverage and is not called by other functions.
    // Directly calling it with a fuzzed string to improve coverage.
    {
        tinyxml2::StrPair str_pair;
        std::string interned_str = fdp.ConsumeRandomLengthString(32);
        str_pair.SetInternedStr(interned_str.c_str());
    }

    // J. Cover tinyxml2::StrPair::CollapseWhitespace()
    // This function had 0% coverage. It is called by StrPair::GetStr()
    // when the NEEDS_WHITESPACE_COLLAPSING flag is set.
    {
        tinyxml2::StrPair str_pair_collapse;
        std::string text_with_whitespace = fdp.ConsumeRandomLengthString(64);
        // Ensure the string has some whitespace to collapse
        text_with_whitespace += "   leading and trailing   ";
        text_with_whitespace += fdp.ConsumeRandomLengthString(64);
        text_with_whitespace += "   \t\n  middle   whitespace  ";
        text_with_whitespace += fdp.ConsumeRandomLengthString(64);

        // StrPair::Set needs a non-const char* and length.
        // We need to make a copy to ensure it's mutable and null-terminated.
        std::vector<char> buffer(text_with_whitespace.begin(), text_with_whitespace.end());
        buffer.push_back('\0'); // Null-terminate the string

        // Set the StrPair with the whitespace collapsing flag
        // The 'true' argument for 'collapse' sets the NEEDS_WHITESPACE_COLLAPSING flag internally.
        str_pair_collapse.Set(buffer.data(), buffer.data() + buffer.size() - 1, tinyxml2::StrPair::NEEDS_WHITESPACE_COLLAPSING);

        // Calling GetStr() will trigger CollapseWhitespace() if the flag is set.
        str_pair_collapse.GetStr();
    }


    // Fuzzing tinyxml2::XMLElement::FloatAttribute(const char *, float)
    {
        std::string element_name = fdp.ConsumeRandomLengthString(32);
        // The XMLElement is owned by the XMLDocument, so no deletion is needed.
        // The custom deleter is a no-op lambda.
        std::unique_ptr<tinyxml2::XMLElement, std::function<void(tinyxml2::XMLElement*)>> element_ptr(
            doc->NewElement(element_name.c_str()),
            [](tinyxml2::XMLElement*){ /* Owned by doc, no delete needed */ }
        );
        tinyxml2::XMLElement* element = element_ptr.get();
        if (element) {
            doc->InsertFirstChild(element); // Add to document to ensure proper context

            std::string attribute_name = fdp.ConsumeRandomLengthString(32);
            float default_float_value = fdp.ConsumeFloatingPoint<float>();

            // Case 1: Attribute does not exist (to hit XML_NO_ATTRIBUTE branch in QueryFloatAttribute)
            element->FloatAttribute(attribute_name.c_str(), default_float_value);

            // Case 2: Attribute exists with a valid float value
            if (fdp.ConsumeBool()) {
                std::string valid_float_str = std::to_string(fdp.ConsumeFloatingPoint<float>());
                element->SetAttribute(attribute_name.c_str(), valid_float_str.c_str());
                element->FloatAttribute(attribute_name.c_str(), default_float_value);
            }

            // Case 3: Attribute exists with a non-float value (to hit XML_CAN_NOT_CONVERT_TEXT branch)
            if (fdp.ConsumeBool()) {
                std::string non_float_str = fdp.ConsumeRandomLengthString(32);
                element->SetAttribute(attribute_name.c_str(), non_float_str.c_str());
                element->FloatAttribute(attribute_name.c_str(), default_float_value);
            }

            // D. Cover XMLElement::InsertNewComment/Declaration/Unknown
            // These methods for inserting new node types were uncovered.
            element->InsertNewComment(fdp.ConsumeRandomLengthString(32).c_str());
            element->InsertNewDeclaration(fdp.ConsumeRandomLengthString(32).c_str());
            element->InsertNewUnknown(fdp.ConsumeRandomLengthString(32).c_str());

            // H. Cover XMLAttribute value getters
            // These methods for retrieving attribute values of different types were uncovered.
            // We set attributes with various types and then attempt to retrieve them.
            if (fdp.ConsumeBool()) {
                std::string attr_name_int = fdp.ConsumeRandomLengthString(16);
                element->SetAttribute(attr_name_int.c_str(), fdp.ConsumeIntegral<int>());
                if (const tinyxml2::XMLAttribute* attr = element->FindAttribute(attr_name_int.c_str())) {
                    attr->IntValue();
                    attr->Int64Value();
                    attr->UnsignedValue();
                    attr->Unsigned64Value();
                    // Added to cover tinyxml2::XMLAttribute::GetLineNum() const
                    attr->GetLineNum();
                    // Added to cover tinyxml2::XMLElement::QueryAttribute overloads
                    int iVal; attr->QueryIntValue(&iVal);
                    unsigned int uVal; attr->QueryUnsignedValue(&uVal);
                    long lVal; attr->QueryInt64Value(&lVal);
                    unsigned long ulVal; attr->QueryUnsigned64Value(&ulVal);
                }
            }
            if (fdp.ConsumeBool()) {
                std::string attr_name_float = fdp.ConsumeRandomLengthString(16);
                element->SetAttribute(attr_name_float.c_str(), fdp.ConsumeFloatingPoint<float>());
                if (const tinyxml2::XMLAttribute* attr = element->FindAttribute(attr_name_float.c_str())) {
                    attr->FloatValue();
                    attr->DoubleValue();
                    // Added to cover tinyxml2::XMLAttribute::GetLineNum() const
                    attr->GetLineNum();
                    // Added to cover tinyxml2::XMLElement::QueryAttribute overloads
                    float fVal; attr->QueryFloatValue(&fVal);
                    double dVal; attr->QueryDoubleValue(&dVal);
                }
            }
            if (fdp.ConsumeBool()) {
                std::string attr_name_bool = fdp.ConsumeRandomLengthString(16);
                element->SetAttribute(attr_name_bool.c_str(), fdp.ConsumeBool());
                if (const tinyxml2::XMLAttribute* attr = element->FindAttribute(attr_name_bool.c_str())) {
                    attr->BoolValue();
                    // Added to cover tinyxml2::XMLAttribute::GetLineNum() const
                    attr->GetLineNum();
                    // Added to cover tinyxml2::XMLElement::QueryAttribute overloads
                    bool bVal; attr->QueryBoolValue(&bVal);
                }
            }
            // Added to cover QueryStringAttribute and its overload
            if (fdp.ConsumeBool()) {
                std::string attr_name_str = fdp.ConsumeRandomLengthString(16);
                std::string attr_val_str = fdp.ConsumeRandomLengthString(32);
                element->SetAttribute(attr_name_str.c_str(), attr_val_str.c_str());
                if (const tinyxml2::XMLAttribute* attr = element->FindAttribute(attr_name_str.c_str())) {
                    const char* sVal;
                    sVal = attr->Value(); // Fix: XMLAttribute does not have QueryStringValue. Use Value() directly.
                    // The internal QueryAttribute(char const*, char const**) const is called by QueryStringValue
                }
            }
        }
    }

    // Fuzzing tinyxml2::XMLElement::FloatText(float)
    {
        std::string element_name = fdp.ConsumeRandomLengthString(32);
        // The XMLElement is owned by the XMLDocument, so no deletion is needed.
        // The custom deleter is a no-op lambda.
        std::unique_ptr<tinyxml2::XMLElement, std::function<void(tinyxml2::XMLElement*)>> element_ptr(
            doc->NewElement(element_name.c_str()),
            [](tinyxml2::XMLElement*){ /* Owned by doc, no delete needed */ }
        );
        tinyxml2::XMLElement* element = element_ptr.get();
        if (element) {
            doc->InsertEndChild(element); // Add to document

            float default_float_value = fdp.ConsumeFloatingPoint<float>();

            // Case 1: Element with no text node (to hit XML_NO_TEXT_NODE branch)
            element->FloatText(default_float_value);

            // Case 2: Element with text that is not a valid float (to hit XML_CAN_NOT_CONVERT_TEXT branch)
            if (fdp.ConsumeBool()) {
                std::string non_float_text = fdp.ConsumeRandomLengthString(32);
                element->SetText(non_float_text.c_str());
                element->FloatText(default_float_value);
            }

            // Case 3: Element with valid float text
            if (fdp.ConsumeBool()) {
                std::string valid_float_text = std::to_string(fdp.ConsumeFloatingPoint<float>());
                element->SetText(valid_float_text.c_str());
                element->FloatText(default_float_value);
            }
        }
    }

    // Fuzzing tinyxml2::XMLElement::ShallowEqual(const XMLNode *)
    {
        std::string name1 = fdp.ConsumeRandomLengthString(32);
        std::string name2 = fdp.ConsumeRandomLengthString(32);

        // The XMLElement is owned by the XMLDocument, so no deletion is needed.
        // The custom deleter is a no-op lambda.
        std::unique_ptr<tinyxml2::XMLElement, std::function<void(tinyxml2::XMLElement*)>> elem1_ptr(
            doc->NewElement(name1.c_str()),
            [](tinyxml2::XMLElement*){ /* Owned by doc */ }
        );
        tinyxml2::XMLElement* elem1 = elem1_ptr.get();

        // The XMLElement is owned by the XMLDocument, so no deletion is needed.
        // The custom deleter is a no-op lambda.
        std::unique_ptr<tinyxml2::XMLElement, std::function<void(tinyxml2::XMLElement*)>> elem2_ptr(
            doc->NewElement(name2.c_str()),
            [](tinyxml2::XMLElement*){ /* Owned by doc */ }
        );
        tinyxml2::XMLElement* elem2 = elem2_ptr.get();

        if (elem1 && elem2) {
            // Test with different names
            elem1->ShallowEqual(elem2);

            // Make names equal
            elem2->SetName(name1.c_str());
            elem1->ShallowEqual(elem2);

            // Add attributes to elem1
            int num_attributes1 = fdp.ConsumeIntegralInRange<int>(0, 5);
            for (int i = 0; i < num_attributes1; ++i) {
                elem1->SetAttribute(fdp.ConsumeRandomLengthString(16).c_str(), fdp.ConsumeRandomLengthString(16).c_str());
            }

            // Add attributes to elem2
            int num_attributes2 = fdp.ConsumeIntegralInRange<int>(0, 5);
            for (int i = 0; i < num_attributes2; ++i) {
                elem2->SetAttribute(fdp.ConsumeRandomLengthString(16).c_str(), fdp.ConsumeRandomLengthString(16).c_str());
            }

            // Test with different attribute counts (if num_attributes1 != num_attributes2)
            elem1->ShallowEqual(elem2);

            // Try to make attribute counts equal and fuzz values
            if (num_attributes1 > 0 && num_attributes2 > 0) {
                // Clear existing attributes and set new ones to ensure matching counts for value fuzzing
                // Iterate and delete all attributes using the public DeleteAttribute(const char* name) method
                while (const tinyxml2::XMLAttribute* attr = elem1->FirstAttribute()) {
                    elem1->DeleteAttribute(attr->Name());
                }
                while (const tinyxml2::XMLAttribute* attr = elem2->FirstAttribute()) {
                    elem2->DeleteAttribute(attr->Name());
                }

                std::string attr_name = fdp.ConsumeRandomLengthString(16);
                std::string attr_val1 = fdp.ConsumeRandomLengthString(16);
                std::string attr_val2 = fdp.ConsumeRandomLengthString(16);

                elem1->SetAttribute(attr_name.c_str(), attr_val1.c_str());
                elem2->SetAttribute(attr_name.c_str(), attr_val2.c_str());

                // Test with same attribute count, same name, different values
                elem1->ShallowEqual(elem2);

                // Test with same attribute count, same name, same values
                elem2->SetAttribute(attr_name.c_str(), attr_val1.c_str());
                elem1->ShallowEqual(elem2);
            }
        }
    }

    // Fuzzing tinyxml2::XMLNode::PreviousSiblingElement(const char *)
    {
        std::string root_name = fdp.ConsumeRandomLengthString(32);
        // The XMLElement is owned by the XMLDocument, so no deletion is needed.
        // The custom deleter is a no-op lambda.
        std::unique_ptr<tinyxml2::XMLElement, std::function<void(tinyxml2::XMLElement*)>> root_ptr(
            doc->NewElement(root_name.c_str()),
            [](tinyxml2::XMLElement*){ /* Owned by doc */ }
        );
        tinyxml2::XMLElement* root = root_ptr.get();
        if (root) {
            doc->InsertEndChild(root);

            int num_siblings = fdp.ConsumeIntegralInRange<int>(0, 10);
            std::vector<tinyxml2::XMLElement*> siblings;
            for (int i = 0; i < num_siblings; ++i) {
                std::string sibling_name = fdp.ConsumeRandomLengthString(32);
                tinyxml2::XMLElement* sibling = doc->NewElement(sibling_name.c_str());
                if (sibling) {
                    root->InsertEndChild(sibling);
                    siblings.push_back(sibling);
                }
            }

            if (!siblings.empty()) {
                tinyxml2::XMLElement* target_sibling = siblings[fdp.ConsumeIntegralInRange<size_t>(0, siblings.size() - 1)];

                // Case 1: Search for an existing sibling by name
                if (fdp.ConsumeBool()) {
                    target_sibling->PreviousSiblingElement(target_sibling->Name());
                }

                // Case 2: Search for a non-existent sibling name
                if (fdp.ConsumeBool()) {
                    std::string non_existent_name = fdp.ConsumeRandomLengthString(32);
                    target_sibling->PreviousSiblingElement(non_existent_name.c_str());
                }

                // Case 3: Search with null name (should return the first previous sibling element)
                if (fdp.ConsumeBool()) {
                    target_sibling->PreviousSiblingElement(nullptr);
                }
            }
        }
    }

    // Fuzzing tinyxml2::XMLNode::LastChildElement(const char *)
    {
        std::string root_name = fdp.ConsumeRandomLengthString(32);
        // The XMLElement is owned by the XMLDocument, so no deletion is needed.
        // The custom deleter is a no-op lambda.
        std::unique_ptr<tinyxml2::XMLElement, std::function<void(tinyxml2::XMLElement*)>> root_ptr(
            doc->NewElement(root_name.c_str()),
            [](tinyxml2::XMLElement*){ /* Owned by doc */ }
        );
        tinyxml2::XMLElement* root = root_ptr.get();
        if (root) {
            doc->InsertEndChild(root);

            int num_children = fdp.ConsumeIntegralInRange<int>(0, 10);
            std::vector<tinyxml2::XMLElement*> children;
            for (int i = 0; i < num_children; ++i) {
                std::string child_name = fdp.ConsumeRandomLengthString(32);
                tinyxml2::XMLElement* child = doc->NewElement(child_name.c_str());
                if (child) {
                    root->InsertEndChild(child);
                    children.push_back(child);
                }
            }

            // Case 1: Search for an existing child by name
            if (!children.empty() && fdp.ConsumeBool()) {
                tinyxml2::XMLElement* target_child = children[fdp.ConsumeIntegralInRange<size_t>(0, children.size() - 1)];
                root->LastChildElement(target_child->Name());
            }

            // Case 2: Search for a non-existent child name
            if (fdp.ConsumeBool()) {
                std::string non_existent_name = fdp.ConsumeRandomLengthString(32);
                root->LastChildElement(non_existent_name.c_str());
            }

            // Case 3: Search with null name (should return the last child element)
            if (fdp.ConsumeBool()) {
                root->LastChildElement(nullptr);
            }
        }
    }

    // A. Call XMLVisitor methods
    // Instantiating and accepting a custom visitor to cover the virtual Visit methods.
    TestVisitor visitor;
    doc->Accept(&visitor);

    // C. Cover XMLDocument error reporting functions
    // Parsing a fuzzed string to induce potential errors, then calling error reporting methods.
    {
        std::unique_ptr<tinyxml2::XMLDocument, XMLDocumentDeleter> error_doc_ptr(new tinyxml2::XMLDocument());
        tinyxml2::XMLDocument* error_doc = error_doc_ptr.get();

        // Provide a malformed XML string to induce an error
        std::string malformed_xml = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange(1, 100));
        error_doc->Parse(malformed_xml.c_str());

        if (error_doc->Error()) { // Check if an error occurred
            error_doc->ErrorStr();
            error_doc->PrintError();
            error_doc->ErrorName();
            // Added to cover tinyxml2::XMLDocument::ErrorID() const and ErrorLineNum() const
            error_doc->ErrorID();
            error_doc->ErrorLineNum();
        }
    }

    // E. Cover XMLPrinter::Print and XMLDocument::Print
    // Using XMLPrinter to print fuzzed data and the document structure.
    {
        // XMLPrinter can print to a file or an internal buffer.
        // To avoid file I/O in fuzzing, we'll use the internal buffer.
        tinyxml2::XMLPrinter printer;

        // The XMLPrinter::Print method is protected and intended for internal use.
        // XMLDocument::Print(&printer) already exercises XMLPrinter's Visit methods
        // to print the document structure, which is the public API intended for printing.
        // Removed direct call to printer.Print as it's a protected member.

        // Call XMLDocument::Print to exercise XMLPrinter's Visit methods
        doc->Print(&printer);

        // Removed: printer.Print("Fuzzed string: %s, int: %d", fdp.ConsumeRandomLengthString(32).c_str(), fdp.ConsumeIntegral<int>());
        // This method is protected and cannot be called directly.

        // Added to cover tinyxml2::XMLPrinter::CStrSize() const and ClearBuffer(bool)
        printer.CStrSize();
        printer.ClearBuffer(fdp.ConsumeBool());
    }

    // G. Cover DeepClone/ShallowClone/ShallowEqual and other node methods
    {
        // XMLNode::DeepClone (called on XMLDocument, which is an XMLNode)
        // Creates a deep copy of the document. Memory is managed by unique_ptr.
        std::unique_ptr<tinyxml2::XMLDocument, XMLDocumentDeleter> clone_doc_ptr(new tinyxml2::XMLDocument());
        tinyxml2::XMLDocument* clone_doc = clone_doc_ptr.get();
        doc->DeepClone(clone_doc);

        // XMLDocument::DeepCopy
        // Creates a deep copy of the document. Memory is managed by unique_ptr.
        std::unique_ptr<tinyxml2::XMLDocument, XMLDocumentDeleter> copy_doc_ptr(new tinyxml2::XMLDocument());
        tinyxml2::XMLDocument* copy_doc = copy_doc_ptr.get();
        doc->DeepCopy(copy_doc);

        // Cover various XMLNode methods that were previously uncovered.
        if (doc->RootElement()) {
            const tinyxml2::XMLNode* node = doc->RootElement();
            node->GetDocument();
            node->GetLineNum();
            node->NoChildren();
            node->LastChild();
            node->PreviousSibling();
            node->NextSibling();

            tinyxml2::XMLNode* mutable_node = doc->RootElement();
            if (mutable_node) {
                mutable_node->Parent();
                mutable_node->PreviousSibling();
                mutable_node->NextSibling();
                mutable_node->NextSiblingElement(fdp.ConsumeRandomLengthString(32).c_str());
                mutable_node->SetUserData(nullptr); // SetUserData and GetUserData were uncovered.
                mutable_node->GetUserData();
            }

            // XMLNode::LinkEndChild
            // Links a newly created element as a child.
            std::string new_elem_name = fdp.ConsumeRandomLengthString(32);
            tinyxml2::XMLElement* new_elem = doc->NewElement(new_elem_name.c_str());
            if (new_elem) {
                doc->LinkEndChild(new_elem);
            }

            // Added to cover tinyxml2::XMLNode::InsertFirstChild and InsertAfterChild
            // Memory safety: new_first_child and new_after_child are owned by 'doc' after insertion.
            std::string first_child_name = fdp.ConsumeRandomLengthString(32);
            tinyxml2::XMLElement* new_first_child = doc->NewElement(first_child_name.c_str());
            if (new_first_child && doc->RootElement()) { // Check if allocation succeeded and root exists
                doc->RootElement()->InsertFirstChild(new_first_child);
            }

            std::string after_child_name = fdp.ConsumeRandomLengthString(32);
            tinyxml2::XMLElement* new_after_child = doc->NewElement(after_child_name.c_str());
            if (new_after_child && doc->RootElement() && doc->RootElement()->FirstChild()) { // Check allocations and if there's a child to insert after
                doc->RootElement()->InsertAfterChild(doc->RootElement()->FirstChild(), new_after_child);
            }
        }

        // XMLText::ShallowClone, XMLText::ShallowEqual
        // Creating and comparing XMLText nodes, and shallow cloning them.
        // ShallowClone returns a new node that needs to be explicitly deleted.
        std::string text_content1 = fdp.ConsumeRandomLengthString(32);
        std::string text_content2 = fdp.ConsumeRandomLengthString(32);
        tinyxml2::XMLText* text1 = doc->NewText(text_content1.c_str());
        tinyxml2::XMLText* text2 = doc->NewText(text_content2.c_str());
        if (text1 && text2) {
            std::unique_ptr<tinyxml2::XMLText, std::function<void(tinyxml2::XMLText*)>> cloned_text_ptr(
                text1->ShallowClone(doc)->ToText(),
                [](tinyxml2::XMLText* t){ if(t) t->GetDocument()->DeleteNode(t); } // Custom deleter for ShallowClone result
            );
            text1->ShallowEqual(text2);
        }

        // XMLComment::ShallowClone, XMLComment::ShallowEqual
        // Similar to XMLText, for XMLComment nodes.
        std::string comment_content1 = fdp.ConsumeRandomLengthString(32);
        std::string comment_content2 = fdp.ConsumeRandomLengthString(32);
        tinyxml2::XMLComment* comment1 = doc->NewComment(comment_content1.c_str());
        tinyxml2::XMLComment* comment2 = doc->NewComment(comment_content2.c_str());
        if (comment1 && comment2) {
            std::unique_ptr<tinyxml2::XMLComment, std::function<void(tinyxml2::XMLComment*)>> cloned_comment_ptr(
                comment1->ShallowClone(doc)->ToComment(),
                [](tinyxml2::XMLComment* c){ if(c) c->GetDocument()->DeleteNode(c); }
            );
            comment1->ShallowEqual(comment2);
            // Added to cover tinyxml2::XMLNode::ToComment() (non-const)
            tinyxml2::XMLNode* node_comment = comment1;
            if (node_comment) { // Check if node_comment is valid
                node_comment->ToComment();
            }
        }

        // XMLDeclaration::ShallowClone, XMLDeclaration::ShallowEqual
        // Similar for XMLDeclaration nodes.
        std::string decl_content1 = fdp.ConsumeRandomLengthString(32);
        std::string decl_content2 = fdp.ConsumeRandomLengthString(32);
        tinyxml2::XMLDeclaration* decl1 = doc->NewDeclaration(decl_content1.c_str());
        tinyxml2::XMLDeclaration* decl2 = doc->NewDeclaration(decl_content2.c_str());
        if (decl1 && decl2) {
            std::unique_ptr<tinyxml2::XMLDeclaration, std::function<void(tinyxml2::XMLDeclaration*)>> cloned_decl_ptr(
                decl1->ShallowClone(doc)->ToDeclaration(),
                [](tinyxml2::XMLDeclaration* d){ if(d) d->GetDocument()->DeleteNode(d); }
            );
            decl1->ShallowEqual(decl2);
        }

        // XMLUnknown::ShallowClone, XMLUnknown::ShallowEqual
        // Similar for XMLUnknown nodes.
        std::string unknown_content1 = fdp.ConsumeRandomLengthString(32);
        std::string unknown_content2 = fdp.ConsumeRandomLengthString(32);
        tinyxml2::XMLUnknown* unknown1 = doc->NewUnknown(unknown_content1.c_str());
        tinyxml2::XMLUnknown* unknown2 = doc->NewUnknown(unknown_content2.c_str());
        if (unknown1 && unknown2) {
            std::unique_ptr<tinyxml2::XMLUnknown, std::function<void(tinyxml2::XMLUnknown*)>> cloned_unknown_ptr(
                unknown1->ShallowClone(doc)->ToUnknown(),
                [](tinyxml2::XMLUnknown* u){ if(u) u->GetDocument()->DeleteNode(u); }
            );
            unknown1->ShallowEqual(unknown2);
        }

        // XMLHandle and XMLConstHandle constructors and operators
        // These handle classes and their methods were largely uncovered.
        // Modified to cover XMLHandle(XMLNode&) and operator=
        tinyxml2::XMLNode& doc_node_ref = *doc;
        tinyxml2::XMLHandle handle(doc_node_ref); // Covers XMLHandle(XMLNode&)
        tinyxml2::XMLHandle handle_copy = handle; // Covers copy constructor
        tinyxml2::XMLHandle handle_assign(nullptr); // Fix: XMLHandle does not have a default constructor
        handle_assign = handle; // Covers operator=

        handle.FirstChild();
        handle.FirstChildElement(fdp.ConsumeRandomLengthString(32).c_str());
        handle.LastChild();
        handle.LastChildElement(fdp.ConsumeRandomLengthString(32).c_str());
        handle.PreviousSibling();
        handle.PreviousSiblingElement(fdp.ConsumeRandomLengthString(32).c_str());
        handle.NextSibling();
        handle.NextSiblingElement(fdp.ConsumeRandomLengthString(32).c_str());
        handle.ToNode();
        handle.ToElement();
        handle.ToText();
        handle.ToUnknown();
        handle.ToDeclaration();

        // Modified to cover XMLConstHandle(XMLNode const&) and operator=
        const tinyxml2::XMLNode& const_doc_node_ref = *doc;
        tinyxml2::XMLConstHandle const_handle(const_doc_node_ref); // Covers XMLConstHandle(XMLNode const&)
        tinyxml2::XMLConstHandle const_handle_copy = const_handle; // Covers copy constructor
        tinyxml2::XMLConstHandle const_handle_assign(nullptr); // Fix: XMLConstHandle does not have a default constructor
        const_handle_assign = const_handle; // Covers operator=

        const_handle.FirstChild();
        const_handle.FirstChildElement(fdp.ConsumeRandomLengthString(32).c_str());
        const_handle.LastChild();
        const_handle.LastChildElement(fdp.ConsumeRandomLengthString(32).c_str());
        const_handle.PreviousSibling();
        const_handle.PreviousSiblingElement(fdp.ConsumeRandomLengthString(32).c_str());
        const_handle.NextSibling();
        const_handle.NextSiblingElement(fdp.ConsumeRandomLengthString(32).c_str());
        const_handle.ToNode();
        const_handle.ToElement();
        const_handle.ToText();
        const_handle.ToUnknown();
        const_handle.ToDeclaration();
    }

    return 0;
}