#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include <cstdio> // For FILE, tmpfile, fclose
#include <memory> // For std::unique_ptr (though we will remove it for tinyxml2 nodes)

#include "/src/tinyxml2/tinyxml2.h"

// Custom XMLVisitor to exercise XMLVisitor virtual functions and their calls in Accept
// This helps cover the 0% coverage on XMLVisitor::Visit* functions.
class FuzzVisitor : public tinyxml2::XMLVisitor {
public:
    // Optional: Pass an XMLPrinter to also exercise XMLPrinter::Visit* functions
    FuzzVisitor(tinyxml2::XMLPrinter* printer = nullptr) : _printer(printer) {}

    bool VisitEnter(const tinyxml2::XMLDocument& doc) override {
        if (_printer) _printer->VisitEnter(doc);
        return true;
    }
    bool VisitExit(const tinyxml2::XMLDocument& doc) override {
        if (_printer) _printer->VisitExit(doc);
        return true;
    }
    bool VisitEnter(const tinyxml2::XMLElement& element, const tinyxml2::XMLAttribute* firstAttribute) override {
        if (_printer) _printer->VisitEnter(element, firstAttribute);
        return true;
    }
    bool VisitExit(const tinyxml2::XMLElement& element) override {
        if (_printer) _printer->VisitExit(element);
        return true;
    }
    bool Visit(const tinyxml2::XMLDeclaration& declaration) override {
        if (_printer) _printer->Visit(declaration);
        return true;
    }
    bool Visit(const tinyxml2::XMLText& text) override {
        if (_printer) _printer->Visit(text);
        return true;
    }
    bool Visit(const tinyxml2::XMLComment& comment) override {
        if (_printer) _printer->Visit(comment);
        return true;
    }
    bool Visit(const tinyxml2::XMLUnknown& unknown) override {
        if (_printer) _printer->Visit(unknown);
        return true;
    }
    // Removed: bool Visit(const tinyxml2::XMLAttribute& attribute) override
    // tinyxml2::XMLVisitor does not have a virtual Visit for XMLAttribute.
    // XMLPrinter does not have a corresponding Visit for XMLAttribute, so no _printer call here.
    // This function was causing the "only virtual member functions can be marked 'override'" error.

private:
    tinyxml2::XMLPrinter* _printer;
};


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // 1. Fuzz XMLDocument::Parse and related parsing functions
    // This covers many internal parsing functions like XMLNode::ParseDeep,
    // XMLElement::ParseDeep, XMLAttribute::ParseDeep, etc.
    std::string xml_string = fdp.ConsumeRemainingBytesAsString();
    tinyxml2::XMLDocument doc;
    doc.Parse(xml_string.c_str());

    // 2. Fuzz XMLPrinter::Print(const char*, ...) and TIXML_VSCPRINTF
    // Create an XMLPrinter without a FILE* to force it to use its internal buffer,
    // which then calls TIXML_VSCPRINTF and TIXML_VSNPRINTF.
    tinyxml2::XMLPrinter printer;
    // Removed direct calls to printer.Print(format_string.c_str(), ...);
    // These were causing "Print is a protected member" errors.
    // XMLDocument::Print(&printer) will exercise the printer's internal logic.

    // Also call XMLDocument::Print with the printer to exercise that path.
    doc.Print(&printer);

    // Call XMLDocument::Print with nullptr to cover the 'else' branch where it creates its own printer.
    doc.Print(nullptr);

    // 3. Fuzz XMLNode::InsertAfterChild(tinyxml2::XMLNode*, tinyxml2::XMLNode*)
    // This function had low coverage, especially for its core insertion logic.
    if (doc.RootElement()) {
        tinyxml2::XMLElement* root = doc.RootElement();

        // Replaced std::unique_ptr with raw pointers.
        // tinyxml2::XMLDocument manages the memory for nodes created with NewElement
        // and inserted into the document. Using unique_ptr with a private destructor
        // causes compilation errors.
        tinyxml2::XMLElement* new_element1 = doc.NewElement("new_node_1");
        tinyxml2::XMLElement* new_element2 = doc.NewElement("new_node_2");
        tinyxml2::XMLElement* new_element3 = doc.NewElement("new_node_3");

        // Scenario 1: Insert after an existing child or as first child.
        // This avoids passing nullptr to afterThis, which caused a SEGV.
        if (root->FirstChildElement()) {
            root->InsertAfterChild(root->FirstChildElement(), new_element1);
        } else {
            root->InsertFirstChild(new_element1);
        }

        // Scenario 2: Removed the call to InsertAfterChild with nullptr for addThis,
        // as tinyxml2 asserts on a null addThis.
        // Ensure new_element3 is also owned by the document to prevent leak.
        root->InsertEndChild(new_element3);


        // Scenario 3: Insert a child that already has a parent
        // This covers the `addThis->Parent()` branch (line 1366).
        if (root->FirstChildElement()) {
            tinyxml2::XMLElement* existing_child = root->FirstChildElement();
            root->InsertEndChild(new_element2); // Add new_element2 to root, giving it a parent
            root->InsertAfterChild(existing_child, new_element2); // new_element2 now has a parent
        } else {
            root->InsertEndChild(new_element2); // Ensure new_element2 is added if no children exist
        }

        // Scenario 4: Insert after an existing child, covering the core insertion logic
        // Add multiple children to ensure the while loop in InsertAfterChild is exercised.
        tinyxml2::XMLElement* child_a = doc.NewElement("child_A");
        tinyxml2::XMLElement* child_b = doc.NewElement("child_B");
        tinyxml2::XMLElement* child_c = doc.NewElement("child_C");
        root->InsertEndChild(child_a);
        root->InsertEndChild(child_b);
        root->InsertEndChild(child_c);

        tinyxml2::XMLElement* insert_me = doc.NewElement("insert_me");
        // Insert 'insert_me' after 'child_b'. This should hit the `node == afterThis` branch (line 1376).
        root->InsertAfterChild(root->FirstChildElement("child_B"), insert_me);

        // Scenario 5: Insert after the last child to cover `addThis->_next == nullptr` (line 1380 else branch).
        tinyxml2::XMLElement* insert_last = doc.NewElement("insert_last");
        root->InsertAfterChild(root->LastChildElement(), insert_last);
    }

    // 4. Fuzz XMLDocument::LoadFile(_IO_FILE*)
    // This function had low branch coverage, especially for error paths and empty files.
    // Create a temporary file and write fuzzed data to it.
    FILE* tmp = tmpfile(); // tmpfile() creates a temporary file that is automatically deleted on close or program exit.
    if (tmp) {
        std::string file_content = fdp.ConsumeRandomLengthString(1024);
        fwrite(file_content.c_str(), 1, file_content.length(), tmp);
        fseek(tmp, 0, SEEK_SET); // Rewind to the beginning of the file

        tinyxml2::XMLDocument doc_file;
        doc_file.LoadFile(tmp); // This will exercise the fread loop and Parse calls.

        // Try with an empty file to cover the `n == 0` branch (line 2296) and `XML_SUCCESS` return (line 2297).
        FILE* empty_tmp = tmpfile();
        if (empty_tmp) {
            fseek(empty_tmp, 0, SEEK_SET); // Ensure it's empty
            tinyxml2::XMLDocument doc_empty;
            doc_empty.LoadFile(empty_tmp);
            fclose(empty_tmp); // Close the empty temporary file
        }

        // Try with malformed XML to trigger Parse errors within LoadFile,
        // covering the `error != XML_SUCCESS` branch (line 2287).
        FILE* malformed_tmp = tmpfile();
        if (malformed_tmp) {
            std::string malformed_xml = "<root><unclosed_tag>"; // Malformed XML
            fwrite(malformed_xml.c_str(), 1, malformed_xml.length(), malformed_tmp);
            fseek(malformed_tmp, 0, SEEK_SET);
            tinyxml2::XMLDocument doc_malformed;
            doc_malformed.LoadFile(malformed_tmp);
            fclose(malformed_tmp); // Close the malformed temporary file
        }

        fclose(tmp); // Close the main temporary file
    }

    // 5. Fuzz DynArray::EnsureCapacity(unsigned long)
    // This function had very low coverage (26.67% line, 25.00% branch).
    // It's an internal utility, so we trigger it indirectly.
    // XMLPrinter's internal stack (`_stack`) is a `DynArray<char const*, 10ul>`.
    // We can trigger `EnsureCapacity` by creating a deeply nested XML structure
    // and then printing it, which will cause the printer to push many elements
    // onto its stack, forcing reallocation.
    tinyxml2::XMLDocument nested_doc;
    tinyxml2::XMLElement* current_element = nested_doc.NewElement("root");
    nested_doc.InsertFirstChild(current_element);
    // Push more than the initial capacity (10) to force reallocation.
    for (int i = 0; i < 15; ++i) {
        std::string tag_name = "level_" + std::to_string(i);
        tinyxml2::XMLElement* new_child = nested_doc.NewElement(tag_name.c_str());
        current_element->InsertEndChild(new_child);
        current_element = new_child;
    }
    // Printing this deeply nested document will exercise the printer's stack and its DynArray.
    tinyxml2::XMLPrinter nested_printer;
    nested_doc.Print(&nested_printer);

    // Fuzz XMLVisitor functions (0% coverage) and XMLDocument::Accept
    // Create a document with various node types to ensure all Visit functions are called.
    tinyxml2::XMLDocument visitor_doc;
    visitor_doc.Parse("<root><element attribute=\"value\"><text>some text</text></element><!--comment--><![CDATA[cdata_section]]><?unknown_instruction?><!DOCTYPE doc>");
    
    // Test with a basic FuzzVisitor
    FuzzVisitor visitor;
    visitor_doc.Accept(&visitor);

    // Test with a FuzzVisitor that also passes calls to an XMLPrinter
    tinyxml2::XMLPrinter visitor_printer;
    FuzzVisitor printer_visitor(&visitor_printer);
    visitor_doc.Accept(&printer_visitor);

    return 0;
}