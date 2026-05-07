#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <memory> // For std::unique_ptr

#include "/src/tinyxml2/tinyxml2.h"
#include <fuzzer/FuzzedDataProvider.h>

// Define a helper to manage XMLDocument lifetime using a smart pointer
using XMLDocumentPtr = std::unique_ptr<tinyxml2::XMLDocument>;

// Custom XMLVisitor to cover the virtual Visit methods
class MyVisitor : public tinyxml2::XMLVisitor {
public:
  // Implement the virtual methods. We don't need complex logic,
  // just ensure they are called to register coverage.
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

  // Create an XMLDocument using a unique_ptr for automatic memory management.
  // This ensures the document and all nodes/attributes created by it are
  // properly cleaned up when the unique_ptr goes out of scope.
  XMLDocumentPtr doc(new tinyxml2::XMLDocument());

  // Consume data to drive different operations on the tinyxml2 library.
  while (fdp.remaining_bytes() > 0) {
    // Use a small integer to select which API to fuzz in this iteration.
    // Increased modulo to include new fuzzing cases.
    uint8_t operation = fdp.ConsumeIntegral<uint8_t>();

    switch (operation % 7) { // Select up to 7 diverse operations
      case 0: { // Fuzz tinyxml2::XMLDocument::Parse
        if (fdp.remaining_bytes() > 0) {
          std::string xml_string = fdp.ConsumeRemainingBytesAsString();
          // Parse the XML string. The document will manage the memory.
          doc->Parse(xml_string.c_str(), xml_string.size());
        }
        break;
      }
      case 1: { // Fuzz tinyxml2::XMLPrinter (Enhanced)
        // Create a simple document structure to print.
        tinyxml2::XMLElement* root = doc->NewElement("root_to_print");
        if (root) {
            doc->LinkEndChild(root);
            root->SetAttribute("attr_print", "value_print");
            tinyxml2::XMLElement* child = doc->NewElement("child_to_print");
            if (child) {
                root->LinkEndChild(child);
            }

            // Add other node types based on fuzzer data to improve XMLPrinter coverage
            uint8_t node_type_to_add = fdp.ConsumeIntegral<uint8_t>();
            if (node_type_to_add % 4 == 0) {
                // Add a Declaration
                tinyxml2::XMLDeclaration* decl = doc->NewDeclaration("xml version=\"1.0\"");
                if (decl) doc->LinkEndChild(decl);
            } else if (node_type_to_add % 4 == 1) {
                // Add a Comment
                tinyxml2::XMLComment* comment = doc->NewComment("a comment");
                if (comment) doc->LinkEndChild(comment);
            } else if (node_type_to_add % 4 == 2) {
                // Add an Unknown node (e.g., processing instruction)
                tinyxml2::XMLUnknown* unknown = doc->NewUnknown("<?proc_inst data?>");
                if (unknown) doc->LinkEndChild(unknown);
            }
        }

        // Create an XMLPrinter. Use fuzzer data to select compact mode.
        bool compact_mode = fdp.ConsumeBool(); // Added fuzzer data for compact mode
        tinyxml2::XMLPrinter printer(nullptr, compact_mode, 0);

        // Print the document using the printer.
        if (doc) {
            doc->Print(&printer);
        }

        // Nodes created (root, child, decl, comment, unknown) are owned by 'doc' and cleaned up by its destructor.
        break;
      }
      case 2: { // Fuzz tinyxml2::XMLNode::InsertAfterChild and InsertFirstChild (Corrected)
        // Create a parent node and link it to the document.
        tinyxml2::XMLElement* root = doc->NewElement("root");
        if (!root) break;
        doc->LinkEndChild(root);

        // Create some initial children
        tinyxml2::XMLNode* child1 = doc->NewElement("child1");
        tinyxml2::XMLNode* child2 = doc->NewElement("child2");
        if (child1) root->LinkEndChild(child1);
        if (child2) root->LinkEndChild(child2);

        // Create the new node to be inserted.
        tinyxml2::XMLNode* new_child_node = nullptr;
        uint8_t new_child_type = fdp.ConsumeIntegral<uint8_t>();
        if (new_child_type % 3 == 0) new_child_node = doc->NewElement("new_element");
        else if (new_child_type % 3 == 1) new_child_node = doc->NewComment("new comment");
        else if (new_child_type % 3 == 2) new_child_node = doc->NewText("new text");

        // Only proceed if the node to be inserted was successfully created.
        if (new_child_node) {
            // Use fuzzer data to select the insertion method
            uint8_t insert_method = fdp.ConsumeIntegral<uint8_t>();
            tinyxml2::XMLNode* inserted_node = nullptr;

            if (insert_method % 3 == 0 && child1) {
                // Insert after the first child (if child1 exists)
                inserted_node = root->InsertAfterChild(child1, new_child_node);
            } else if (insert_method % 3 == 1 && child2) {
                // Insert after the last child (if child2 exists)
                inserted_node = root->InsertAfterChild(child2, new_child_node);
            } else {
                // Insert as the first child
                inserted_node = root->InsertFirstChild(new_child_node);
            }

            // Cleanup: If new_child_node was created but not inserted (Parent() is still null), delete it.
            // This happens if the insertion method failed (e.g., child1/child2 didn't exist for InsertAfterChild)
            // or if InsertFirstChild failed (less likely but possible).
            // Check if the node was created by this document before attempting to delete
            if (new_child_node->GetDocument() == doc.get() && !new_child_node->Parent()) {
                 doc->DeleteNode(new_child_node);
            }
        }
        break;
      }
      case 3: { // Fuzz tinyxml2::XMLElement::DeleteAttribute by name (keep as is)
        if (fdp.remaining_bytes() > 0) {
          tinyxml2::XMLElement* element = doc->NewElement("element");
          if (element) { // Check if element creation was successful
              doc->LinkEndChild(element); // Link element immediately

              // Add some attributes to the element using fuzzer data for values.
              element->SetAttribute("attr1", "value1");
              element->SetAttribute("attr2", fdp.ConsumeRandomLengthString(16).c_str());
              element->SetAttribute("attr3", fdp.ConsumeIntegral<int>());

              // Collect the names (const char*) of the attributes into a vector.
              std::vector<const char*> attribute_names;
              for (const tinyxml2::XMLAttribute* attr = element->FirstAttribute(); attr; attr = attr->Next()) {
                  attribute_names.push_back(attr->Name()); // Store the name (const char*)
              }

              // If there are attributes, consume data to select one by index and delete it by name.
              if (!attribute_names.empty()) {
                  size_t attr_index = fdp.ConsumeIntegralInRange<size_t>(0, attribute_names.size() - 1);
                  const char* name_to_delete = attribute_names[attr_index];

                  // Delete the selected attribute by name using the public API.
                  element->DeleteAttribute(name_to_delete);
              }
          }
        }
        break;
      }
      case 4: { // Fuzz tinyxml2::XMLUtil::ConvertUTF32ToUTF8 (keep as is)
        if (fdp.remaining_bytes() >= sizeof(unsigned long)) {
          unsigned long utf32_char = fdp.ConsumeIntegral<unsigned long>();
          char utf8_buffer[5] = {0};
          int bytes_written = 0;
          tinyxml2::XMLUtil::ConvertUTF32ToUTF8(utf32_char, utf8_buffer, &bytes_written);
        }
        break;
      }
      case 5: { // Fuzz tinyxml2::XMLDocument::Accept with XMLVisitor
        // Added this case to cover the XMLVisitor virtual methods and Accept calls.
        MyVisitor visitor;
        if (doc) {
            doc->Accept(&visitor);
        }
        // Create a simple element and accept the visitor to cover XMLElement::Accept
        tinyxml2::XMLElement* element_for_visitor = doc->NewElement("visitor_element");
        if (element_for_visitor) {
            doc->LinkEndChild(element_for_visitor);
            element_for_visitor->Accept(&visitor);
        }
        break;
      }
      case 6: { // Fuzz tinyxml2::DeleteNode and XMLElement::DeleteAttribute by name (corrected)
        tinyxml2::XMLElement* element = doc->NewElement("element_to_delete");
        if (element) {
            doc->LinkEndChild(element);

            // Add attributes using public APIs
            element->SetAttribute("attr_to_delete", "value"); // Use public SetAttribute
            // Get pointer using public FindAttribute to use its Name() later
            // Corrected type to const tinyxml2::XMLAttribute* to match FindAttribute return type
            const tinyxml2::XMLAttribute* attr_to_delete = element->FindAttribute("attr_to_delete");

            // Add a child node
            tinyxml2::XMLComment* comment_to_delete = doc->NewComment("comment_to_delete");
            if (comment_to_delete) {
                element->LinkEndChild(comment_to_delete);
            }

            // Use fuzzer data to decide what to delete
            uint8_t delete_type = fdp.ConsumeIntegral<uint8_t>();
            if (delete_type % 3 == 0 && attr_to_delete) {
                // Delete attribute by name (using the name from the pointer)
                element->DeleteAttribute(attr_to_delete->Name()); // Use public DeleteAttribute(const char*)
                 // attr_to_delete is now invalid, set to nullptr
                attr_to_delete = nullptr; // Safety measure
            } else if (delete_type % 3 == 1 && comment_to_delete) {
                // Delete node by pointer (child of element)
                doc->DeleteNode(comment_to_delete);
                // comment_to_delete is now invalid, set to nullptr
                comment_to_delete = nullptr; // Safety measure
            } else if (delete_type % 3 == 2 && element) {
                // Delete the element itself by pointer
                doc->DeleteNode(element);
                // element is now invalid, set to nullptr
                element = nullptr; // Safety measure
            }
        }
        break;
      }
    }
  }

  // The unique_ptr 'doc' goes out of scope here, automatically calling the
  // XMLDocument destructor, which cleans up all owned nodes and attributes.

  return 0;
}