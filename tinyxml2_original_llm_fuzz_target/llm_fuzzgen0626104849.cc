#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <memory> // For std::unique_ptr
#include <fuzzer/FuzzedDataProvider.h>

// Include the necessary tinyxml2 header with the full project-relative path.
#include "/src/tinyxml2/tinyxml2.h"

// Define a custom deleter for XMLDocument to be used with std::unique_ptr.
// This ensures proper cleanup of the XMLDocument object and its associated memory.
struct XMLDocumentDeleter {
    void operator()(tinyxml2::XMLDocument* doc) const {
        if (doc) {
            doc->Clear(); // Clear all nodes and release memory
            delete doc;
        }
    }
};

// Custom XMLVisitor to cover the virtual Visit methods.
// These methods are called when traversing an XML document.
class MyXMLVisitor : public tinyxml2::XMLVisitor {
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

    // Use std::unique_ptr with a custom deleter for memory-safe management of XMLDocument.
    // The XMLDocument manages the memory for its nodes and attributes.
    std::unique_ptr<tinyxml2::XMLDocument, XMLDocumentDeleter> doc(new tinyxml2::XMLDocument());

    // --- Fuzzing tinyxml2::XMLDocument::Parse() ---
    // This function currently has 70% branch coverage, indicating missed paths.
    // Parsing raw fuzzed data will exercise many internal parsing routines.
    std::string xml_string = fdp.ConsumeRemainingBytesAsString();
    doc->Parse(xml_string.c_str(), xml_string.length());

    // Create a root element for the XML document if it doesn't exist or if parsing failed.
    // This ensures subsequent operations have a valid element to work with.
    tinyxml2::XMLElement* root = doc->RootElement();
    if (!root) {
        root = doc->NewElement("root");
        if (!root) {
            return 0; // Allocation failed, nothing to do.
        }
        doc->InsertFirstChild(root);
    }

    // --- Fuzzing tinyxml2::XMLVisitor methods ---
    // All XMLVisitor::Visit* methods currently have 0% runtime coverage.
    // Calling Accept() on the document will trigger these methods if nodes exist.
    MyXMLVisitor visitor;
    doc->Accept(&visitor);

    // --- Fuzzing tinyxml2::XMLElement::SetText and Query*Text overloads ---
    // Many SetText and Query*Text overloads currently have 0% runtime coverage.
    // This section aims to cover them by setting and querying various data types.
    std::string text_content = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange(0, 200));
    root->SetText(text_content.c_str()); // Existing coverage
    root->GetText(); // Existing coverage

    // Set and Query Text with various types
    int int_val = fdp.ConsumeIntegral<int>();
    root->SetText(int_val); // Added to cover tinyxml2::XMLElement::SetText(int) and related XMLUtil::ToStr
    int queried_int = 0;
    root->QueryIntText(&queried_int); // Added to cover tinyxml2::XMLElement::QueryIntText(int*)

    unsigned int uint_val = fdp.ConsumeIntegral<unsigned int>();
    root->SetText(uint_val); // Added to cover tinyxml2::XMLElement::SetText(unsigned int)
    unsigned int queried_uint = 0;
    root->QueryUnsignedText(&queried_uint); // Added to cover tinyxml2::XMLElement::QueryUnsignedText(unsigned int*)

    long long_val = fdp.ConsumeIntegral<long>();
    root->SetText(long_val); // Added to cover tinyxml2::XMLElement::SetText(long)
    long queried_long = 0;
    root->QueryInt64Text(&queried_long); // Added to cover tinyxml2::XMLElement::QueryInt64Text(long*)

    unsigned long ulong_val = fdp.ConsumeIntegral<unsigned long>();
    root->SetText(ulong_val); // Added to cover tinyxml2::XMLElement::SetText(unsigned long)
    unsigned long queried_ulong = 0;
    root->QueryUnsigned64Text(&queried_ulong); // Added to cover tinyxml2::XMLElement::QueryUnsigned64Text(unsigned long*)

    bool bool_val = fdp.ConsumeBool();
    root->SetText(bool_val); // Added to cover tinyxml2::XMLElement::SetText(bool)
    bool queried_bool = false;
    root->QueryBoolText(&queried_bool); // Added to cover tinyxml2::XMLElement::QueryBoolText(bool*)

    float float_val = fdp.ConsumeFloatingPoint<float>();
    root->SetText(float_val); // Added to cover tinyxml2::XMLElement::SetText(float)
    float queried_float = 0.0f;
    root->QueryFloatText(&queried_float); // Added to cover tinyxml2::XMLElement::QueryFloatText(float*)

    double double_val = fdp.ConsumeFloatingPoint<double>();
    root->SetText(double_val); // Added to cover tinyxml2::XMLElement::SetText(double)
    double queried_double = 0.0;
    root->QueryDoubleText(&queried_double); // Added to cover tinyxml2::XMLElement::QueryDoubleText(double*)

    // --- Fuzzing tinyxml2::XMLElement::SetAttribute and Query*Attribute overloads ---
    // Many SetAttribute and Query*Attribute overloads currently have 0% runtime coverage.
    // This section aims to cover them by setting and querying various data types.
    std::string existent_attr_name = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange(1, 50));
    bool attr_value_to_set = fdp.ConsumeBool();
    root->SetAttribute(existent_attr_name.c_str(), attr_value_to_set); // Existing coverage
    root->BoolAttribute(existent_attr_name.c_str(), fdp.ConsumeBool()); // Existing coverage

    // Set and Query Attribute with various types
    std::string attr_name_int = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange(1, 50));
    root->SetAttribute(attr_name_int.c_str(), int_val); // Added to cover tinyxml2::XMLElement::SetAttribute(char const*, int)
    root->QueryIntAttribute(attr_name_int.c_str(), &queried_int); // Added to cover tinyxml2::XMLElement::QueryIntAttribute(char const*, int*)

    std::string attr_name_uint = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange(1, 50));
    root->SetAttribute(attr_name_uint.c_str(), uint_val); // Added to cover tinyxml2::XMLElement::SetAttribute(char const*, unsigned int)
    root->QueryUnsignedAttribute(attr_name_uint.c_str(), &queried_uint); // Added to cover tinyxml2::XMLElement::QueryUnsignedAttribute(char const*, unsigned int*)

    std::string attr_name_long = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange(1, 50));
    root->SetAttribute(attr_name_long.c_str(), long_val); // Added to cover tinyxml2::XMLElement::SetAttribute(char const*, long)
    root->QueryInt64Attribute(attr_name_long.c_str(), &queried_long); // Added to cover tinyxml2::XMLElement::QueryInt64Attribute(char const*, long*)

    std::string attr_name_ulong = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange(1, 50));
    root->SetAttribute(attr_name_ulong.c_str(), ulong_val); // Added to cover tinyxml2::XMLElement::SetAttribute(char const*, unsigned long)
    root->QueryUnsigned64Attribute(attr_name_ulong.c_str(), &queried_ulong); // Added to cover tinyxml2::XMLElement::QueryUnsigned64Attribute(char const*, unsigned long*)

    std::string attr_name_float = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange(1, 50));
    root->SetAttribute(attr_name_float.c_str(), float_val); // Added to cover tinyxml2::XMLElement::SetAttribute(char const*, float)
    root->QueryFloatAttribute(attr_name_float.c_str(), &queried_float); // Added to cover tinyxml2::XMLElement::QueryFloatAttribute(char const*, float*)

    std::string attr_name_double = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange(1, 50));
    root->SetAttribute(attr_name_double.c_str(), double_val); // Added to cover tinyxml2::XMLElement::SetAttribute(char const*, double)
    root->QueryDoubleAttribute(attr_name_double.c_str(), &queried_double); // Added to cover tinyxml2::XMLElement::QueryDoubleAttribute(char const*, double*)

    // --- Fuzzing tinyxml2::XMLAttribute::SetAttribute overloads ---
    // These specific SetAttribute overloads on XMLAttribute objects currently have 0% runtime coverage.
    const tinyxml2::XMLAttribute* attribute_obj = root->FindAttribute(existent_attr_name.c_str());
    if (attribute_obj) {
        // Note: XMLAttribute::SetAttribute methods are non-const, so we need a non-const pointer.
        // FindAttribute returns const, so we cannot call SetAttribute on the returned pointer directly.
        // To cover these, we would need to obtain a non-const XMLAttribute pointer,
        // which is typically done when creating or modifying attributes directly, not querying existing ones.
        // For fuzzing purposes, we can cast away constness if we are certain it's safe and we own the memory,
        // but it's generally better to use the XMLElement::SetAttribute which handles creation/modification.
        // Since the goal is coverage and not necessarily modifying existing const attributes,
        // we will skip these specific calls on the const attribute_obj.
        // The XMLElement::SetAttribute calls above already cover the underlying XMLUtil::ToStr functions.
    }

    // --- Fuzzing tinyxml2::XMLPrinter::PushText and PushAttribute overloads ---
    // Many PushText and PushAttribute overloads currently have 0% runtime coverage.
    tinyxml2::XMLPrinter printer; // Existing coverage for bool overloads
    printer.PushText(long_val); // Added to cover tinyxml2::XMLPrinter::PushText(long)
    printer.PushText(ulong_val); // Added to cover tinyxml2::XMLPrinter::PushText(unsigned long)
    printer.PushText(int_val); // Added to cover tinyxml2::XMLPrinter::PushText(int)
    printer.PushText(uint_val); // Added to cover tinyxml2::XMLPrinter::PushText(unsigned int)
    printer.PushText(float_val); // Added to cover tinyxml2::XMLPrinter::PushText(float)
    printer.PushText(double_val); // Added to cover tinyxml2::XMLPrinter::PushText(double)

    std::string printer_attr_name_int = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange(1, 50));
    printer.PushAttribute(printer_attr_name_int.c_str(), int_val); // Added to cover tinyxml2::XMLPrinter::PushAttribute(char const*, int)

    std::string printer_attr_name_uint = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange(1, 50));
    printer.PushAttribute(printer_attr_name_uint.c_str(), uint_val); // Added to cover tinyxml2::XMLPrinter::PushAttribute(char const*, unsigned int)

    std::string printer_attr_name_long = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange(1, 50));
    printer.PushAttribute(printer_attr_name_long.c_str(), long_val); // Added to cover tinyxml2::XMLPrinter::PushAttribute(char const*, long)

    std::string printer_attr_name_ulong = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange(1, 50));
    printer.PushAttribute(printer_attr_name_ulong.c_str(), ulong_val); // Added to cover tinyxml2::XMLPrinter::PushAttribute(char const*, unsigned long)

    std::string printer_attr_name_double = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange(1, 50));
    printer.PushAttribute(printer_attr_name_double.c_str(), double_val); // Added to cover tinyxml2::XMLPrinter::PushAttribute(char const*, double)

    // --- Fuzzing tinyxml2::XMLNode::DeepClone ---
    // This function currently has 0% runtime coverage.
    tinyxml2::XMLNode* cloned_node = root->DeepClone(doc.get());
    // Memory safety: cloned_node is allocated by the document's memory pool and will be freed by doc's deleter.

    // --- Fuzzing tinyxml2::XMLNode::InsertAfterChild ---
    // This function currently has 0% runtime coverage.
    tinyxml2::XMLElement* child1 = doc->NewElement("child1");
    tinyxml2::XMLElement* child2 = doc->NewElement("child2");
    if (child1 && child2) {
        root->InsertEndChild(child1);
        root->InsertAfterChild(child1, child2);
    }
    // Memory safety: child1 and child2 are owned by the document and will be freed by doc's deleter.

    // --- Fuzzing tinyxml2::XMLElement::DeleteAttribute(char const*) ---
    // This function currently has 0% runtime coverage.
    std::string attr_to_delete_name = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange(1, 50));
    root->SetAttribute(attr_to_delete_name.c_str(), "value_to_delete");
    root->DeleteAttribute(attr_to_delete_name.c_str());

    // --- Fuzzing tinyxml2::XMLNode::LastChildElement(char const*) const and PreviousSiblingElement(char const*) const ---
    // These functions currently have 0% runtime coverage.
    // We need to create a structure that allows these to be called meaningfully.
    std::string specific_child_name = "specific_child";
    tinyxml2::XMLElement* prev_child = nullptr;
    for (int i = 0; i < 5; ++i) {
        std::string current_child_name = (i % 2 == 0) ? specific_child_name : fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange(1, 20));
        tinyxml2::XMLElement* child = doc->NewElement(current_child_name.c_str());
        if (child) {
            root->InsertEndChild(child);
            if (i == 3) { // Keep a reference to a middle child to test PreviousSiblingElement
                prev_child = child;
            }
        }
    }
    root->LastChildElement(specific_child_name.c_str()); // Added to cover tinyxml2::XMLNode::LastChildElement(char const*) const
    if (prev_child) {
        prev_child->PreviousSiblingElement(specific_child_name.c_str()); // Added to cover tinyxml2::XMLNode::PreviousSiblingElement(char const*) const
    }

    // The XMLDocument and its associated nodes/attributes are automatically
    // deallocated when 'doc' goes out of scope due to std::unique_ptr.
    // The XMLPrinter's internal buffer is managed by its destructor.

    return 0;
}