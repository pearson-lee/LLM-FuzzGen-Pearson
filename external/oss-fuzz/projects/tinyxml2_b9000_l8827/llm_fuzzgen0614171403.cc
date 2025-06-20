#include <fuzzer/FuzzedDataProvider.h>
#include "/src/tinyxml2/tinyxml2.h" // Include the main tinyxml2 header

#include <string>
#include <vector>
#include <memory> // For std::unique_ptr, though not strictly needed for tinyxml2 objects here

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  FuzzedDataProvider fdp(Data, Size);

  // All tinyxml2 objects (XMLDocument, XMLElement, XMLAttribute, XMLNode, etc.)
  // are designed to be managed by the XMLDocument's internal memory pool.
  // By creating an XMLDocument instance on the stack, all nodes and attributes
  // created via its `New*` methods will be automatically deallocated when
  // the `doc` object goes out of scope at the end of this function.
  // This ensures comprehensive memory safety and prevents leaks.
  tinyxml2::XMLDocument doc;

  // Use a switch to diversify the API calls based on fuzzer input.
  // This strategy ensures that different code paths within the selected APIs
  // are exercised during fuzzing, maximizing coverage.
  int api_choice = fdp.ConsumeIntegralInRange<int>(0, 4);

  switch (api_choice) {
    case 0: {
      // Fuzzing: XMLDocument::Parse(const char* xml, size_t len)
      // This function parses the content of an XML document.
      // It's the primary entry point for parsing XML.

      // Consume a random length string from the fuzzer data to serve as the XML content.
      std::string xml_content = fdp.ConsumeRandomLengthString(fdp.remaining_bytes());
      if (xml_content.empty()) {
        break; // Skip if input is empty to avoid issues with empty buffers.
      }

      // Parse the XML content. The XMLDocument will manage the memory for parsed elements.
      doc.Parse(xml_content.c_str(), xml_content.length());
      break;
    }
    case 1: {
      // Fuzzing: XMLElement::SetAttribute(const char* name, const char* value)
      // This function sets an attribute for an XMLElement.
      // It's crucial for testing attribute creation and value setting logic.

      // Consume a random length string for the attribute value.
      std::string attr_content = fdp.ConsumeRandomLengthString(fdp.remaining_bytes());
      if (attr_content.empty()) {
        break; // Skip if input is empty.
      }

      // Create an XMLElement to associate the attribute with.
      tinyxml2::XMLElement* element = doc.NewElement("fuzzElementWithAttr");
      doc.InsertFirstChild(element); // Add to document to ensure proper context and cleanup.

      // Set the attribute. This handles creation and setting the value.
      element->SetAttribute("fuzzAttr", attr_content.c_str());
      break;
    }
    case 2: {
      // Fuzzing: XMLElement * XMLElement::InsertNewChildElement(const char* name)
      // This function creates a new XMLElement and inserts it as a child of the current element.
      // Fuzzing this tests node creation, linking, and potential issues with element names.

      // Consume a random length string for the new child element's name.
      std::string element_name = fdp.ConsumeRandomLengthString(fdp.remaining_bytes());
      if (element_name.empty()) {
        break; // Skip if name is empty.
      }

      // Create a parent element to insert the new child into.
      tinyxml2::XMLElement* parent_element = doc.NewElement("parentElement");
      doc.InsertFirstChild(parent_element); // Add to document.

      // Call the target API to insert a new child element.
      // The returned `new_child` is owned by the `doc` through `parent_element`.
      tinyxml2::XMLElement* new_child = parent_element->InsertNewChildElement(element_name.c_str());

      // Optionally, add more data to the new child to increase coverage of its internal state.
      if (new_child && fdp.ConsumeBool()) {
          new_child->SetAttribute("fuzz_attr", fdp.ConsumeRandomLengthString(10).c_str());
          new_child->SetText(fdp.ConsumeRandomLengthString(20).c_str());
      }
      break;
    }
    case 3: {
      // Fuzzing: void XMLNode::DeleteChild( XMLNode* node )
      // This function removes a specified child node from the current node and deallocates it.
      // This is critical for testing memory management and tree manipulation.

      // Create a parent element.
      tinyxml2::XMLElement* parent_element = doc.NewElement("parentElement");
      doc.InsertFirstChild(parent_element); // Add to document.

      // Create a vector to hold pointers to child nodes.
      std::vector<tinyxml2::XMLNode*> children;
      // Create a fuzzed number of child elements (up to 5) and add them to the parent.
      for (int i = 0; i < fdp.ConsumeIntegralInRange<int>(0, 5); ++i) {
        std::string child_name = fdp.ConsumeRandomLengthString(10);
        tinyxml2::XMLElement* child = doc.NewElement(child_name.c_str());
        parent_element->InsertEndChild(child); // Add child to parent.
        children.push_back(child); // Store pointer for later deletion.
      }

      // If there are children, randomly select one to delete.
      if (!children.empty()) {
        size_t index_to_delete = fdp.ConsumeIntegralInRange<size_t>(0, children.size() - 1);
        // Call the target API to delete the selected child.
        // This function is responsible for deallocating the child node's memory.
        parent_element->DeleteChild(children[index_to_delete]);
      }
      break;
    }
    case 4: {
      // Fuzzing: XMLError XMLElement::QueryDoubleText( double* dval ) const
      // This function attempts to parse the text content of an XMLElement as a double.
      // It's useful for uncovering issues with numerical parsing, boundary conditions,
      // and malformed number strings.

      // Consume a random length string to be used as the element's text content.
      std::string text_content = fdp.ConsumeRandomLengthString(fdp.remaining_bytes());

      // Create an XMLElement and set its text content.
      tinyxml2::XMLElement* element = doc.NewElement("fuzzDoubleElement");
      doc.InsertFirstChild(element); // Add to document.
      element->SetText(text_content.c_str());

      double dval = 0.0; // Initialize a double variable to store the parsed value.
      // Call the target API. The return value indicates success or failure of parsing.
      element->QueryDoubleText(&dval);
      // The value of `dval` can be inspected in a debugger during fuzzing to see parsed results.
      break;
    }
  }

  // All tinyxml2 objects created via `doc.New*()` methods are automatically
  // cleaned up when `doc` (the tinyxml2::XMLDocument instance) goes out of scope.
  // This ensures that no memory leaks occur from tinyxml2's internal allocations.
  // Stack-allocated variables like `xml_buffer`, `attr_buffer`, `parentEndTag`,
  // `curLineNum`, `dval`, and `children` are also automatically deallocated.

  return 0; // Indicate successful execution of the fuzzer.
}