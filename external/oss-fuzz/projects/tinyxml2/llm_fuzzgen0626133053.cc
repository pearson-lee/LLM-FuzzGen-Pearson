#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <memory> // For std::unique_ptr

#include "/src/tinyxml2/tinyxml2.h"
#include <fuzzer/FuzzedDataProvider.h>

// Define a helper to manage XMLDocument lifetime using a smart pointer
using XMLDocumentPtr = std::unique_ptr<tinyxml2::XMLDocument>;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  FuzzedDataProvider fdp(Data, Size);

  // Create an XMLDocument using a unique_ptr for automatic memory management.
  // This ensures the document and all nodes/attributes created by it are
  // properly cleaned up when the unique_ptr goes out of scope.
  XMLDocumentPtr doc(new tinyxml2::XMLDocument());

  // Consume data to drive different operations on the tinyxml2 library.
  while (fdp.remaining_bytes() > 0) {
    // Use a small integer to select which API to fuzz in this iteration.
    uint8_t operation = fdp.ConsumeIntegral<uint8_t>();

    switch (operation % 5) { // Select up to 5 diverse operations
      case 0: { // Fuzz tinyxml2::XMLDocument::Parse
        if (fdp.remaining_bytes() > 0) {
          std::string xml_string = fdp.ConsumeRemainingBytesAsString();
          // Parse the XML string. The document will manage the memory.
          doc->Parse(xml_string.c_str(), xml_string.size());
        }
        break;
      }
      case 1: { // Fuzz tinyxml2::XMLPrinter
        // Create a simple document structure to print.
        tinyxml2::XMLElement* root = doc->NewElement("root_to_print");
        if (root) {
            doc->LinkEndChild(root);
            root->SetAttribute("attr_print", "value_print");
            tinyxml2::XMLElement* child = doc->NewElement("child_to_print");
            if (child) {
                root->LinkEndChild(child);
            }
        }

        // Create an XMLPrinter. Using a buffer printer.
        // The printer's internal buffer is managed by its destructor.
        tinyxml2::XMLPrinter printer(nullptr, false, 0);

        // Print the document using the printer. This is the correct public API usage.
        // Check if doc is valid before printing (unique_ptr ensures it is, but good practice).
        if (doc) {
            doc->Print(&printer);
            // Optionally, access the printed string via printer.CStr()
            // const char* printed_xml = printer.CStr();
            // We don't need to do anything with the string for fuzzing purposes.
        }

        // Nodes created (root, child) are owned by 'doc' and cleaned up by its destructor.
        break;
      }
      case 2: { // Fuzz tinyxml2::XMLNode::InsertAfterChild
        // Create a parent node and link it to the document.
        tinyxml2::XMLElement* root = doc->NewElement("root");
        if (!root) break; // Cannot proceed if root creation fails
        doc->LinkEndChild(root); // Link root immediately

        // Create an existing child to insert after. This node MUST be valid and linked.
        tinyxml2::XMLNode* existing_child_node = doc->NewElement("existing_child");
        if (!existing_child_node) {
            // If existing child creation fails, we cannot call InsertAfterChild with a valid afterThis.
            // The root is already linked and will be cleaned up by the document.
            break;
        }
        root->LinkEndChild(existing_child_node); // Link existing child - MUST succeed to be a valid afterThis

        // Create the new node to be inserted.
        tinyxml2::XMLNode* new_child_node = nullptr;
        uint8_t new_child_type = fdp.ConsumeIntegral<uint8_t>();
        if (new_child_type % 3 == 0) new_child_node = doc->NewElement("new_element");
        else if (new_child_type % 3 == 1) new_child_node = doc->NewComment("new comment");
        else if (new_child_type % 3 == 2) new_child_node = doc->NewText("new text");

        // Attempt to insert the new child.
        // We now guarantee root and existing_child_node are valid and linked.
        // new_child_node might be null if creation failed. InsertAfterChild handles null addThis.
        tinyxml2::XMLNode* inserted_node = nullptr;
        if (root && existing_child_node) { // root and existing_child_node are guaranteed valid here
            inserted_node = root->InsertAfterChild(existing_child_node, new_child_node);
        }

        // Cleanup: If new_child_node was created but not inserted (Parent() is still null), delete it.
        // This happens if new_child_node was null when passed to InsertAfterChild,
        // or if InsertAfterChild failed internally (though the latter is less likely for null addThis).
        if (new_child_node && !new_child_node->Parent()) {
            doc->DeleteNode(new_child_node);
        }

        break;
      }
      case 3: { // Fuzz tinyxml2::XMLElement::DeleteAttribute
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
      case 4: { // Fuzz tinyxml2::XMLUtil::ConvertUTF32ToUTF8
        if (fdp.remaining_bytes() >= sizeof(unsigned long)) {
          unsigned long utf32_char = fdp.ConsumeIntegral<unsigned long>();
          char utf8_buffer[5] = {0};
          int bytes_written = 0;
          tinyxml2::XMLUtil::ConvertUTF32ToUTF8(utf32_char, utf8_buffer, &bytes_written);
        }
        break;
      }
    }
  }

  // The unique_ptr 'doc' goes out of scope here, automatically calling the
  // XMLDocument destructor, which cleans up all owned nodes and attributes.

  return 0;
}