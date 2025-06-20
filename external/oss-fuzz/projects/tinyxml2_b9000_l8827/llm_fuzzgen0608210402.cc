#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <memory> // Required for std::unique_ptr
#include <algorithm> // Required for std::min and std::max

// Include the tinyxml2 header with its full project-relative path.
#include "/src/tinyxml2/tinyxml2.h"
// Include the FuzzedDataProvider header for generating fuzzer inputs.
#include <fuzzer/FuzzedDataProvider.h>

// LLVMFuzzerTestOneInput is the entry point for the fuzzer.
// It takes raw fuzzer input data and its size.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  // Initialize FuzzedDataProvider to consume bytes from the input data.
  FuzzedDataProvider fdp(Data, Size);

  // Create a tinyxml2::XMLDocument object.
  // Using std::unique_ptr ensures that the XMLDocument and all XMLNodes
  // (XMLElement, XMLText, XMLAttribute, etc.) associated with it are
  // automatically deallocated when 'doc' goes out of scope, preventing memory leaks.
  std::unique_ptr<tinyxml2::XMLDocument> doc(new tinyxml2::XMLDocument());

  // A vector to keep track of created XMLElements.
  // These pointers are owned by the 'doc' object, so we do not manage their
  // memory directly; their lifetimes are tied to the XMLDocument.
  std::vector<tinyxml2::XMLElement*> elements;

  // Determine a random number of elements to create, limiting to a reasonable maximum
  // to prevent excessive memory usage or timeouts during fuzzing.
  const int num_elements = fdp.ConsumeIntegralInRange<int>(0, 50); // Fuzz up to 50 elements

  for (int i = 0; i < num_elements; ++i) {
    // Consume a string for the element name.
    // The length is fuzzed between 1 and 128 characters to test various name lengths.
    std::string element_name = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(1, 128));

    // API Call: XMLElement * tinyxml2::XMLDocument::NewElement(const char *)
    // Creates a new XMLElement. The XMLDocument takes ownership of this element.
    tinyxml2::XMLElement* element = doc->NewElement(element_name.c_str());
    if (!element) {
      // If element creation fails (e.g., due to memory allocation issues),
      // gracefully exit the loop to prevent further errors.
      break;
    }

    // Strategically insert the new element into the XML tree.
    // If no elements exist yet, or randomly (50% chance), insert it as a direct child of the document.
    // Otherwise, insert it as a child of a randomly selected existing element to build a deeper tree.
    // API Call: XMLNode * tinyxml2::XMLNode::InsertEndChild(XMLNode *)
    if (elements.empty() || fdp.ConsumeBool()) {
      doc->InsertEndChild(element);
    } else {
      // Select a random existing element to be the parent.
      // Ensure there's at least one element in the vector before accessing.
      tinyxml2::XMLElement* parent_element = elements[fdp.ConsumeIntegralInRange<size_t>(0, elements.size() - 1)];
      parent_element->InsertEndChild(element);
    }
    // Add the newly created element to our tracking vector.
    elements.push_back(element);

    // Fuzzing element text content.
    // Randomly decide whether to set text for the current element.
    if (fdp.ConsumeBool()) {
      // Consume a string for the element's text content.
      // Length fuzzed between 0 and 256 characters.
      std::string text_content = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 256));
      // API Call: void tinyxml2::XMLElement::SetText(const char *)
      element->SetText(text_content.c_str());
    }

    // Fuzzing element attributes.
    // Determine a random number of attributes to add to the current element.
    const int num_attributes = fdp.ConsumeIntegralInRange<int>(0, 10); // Fuzz up to 10 attributes per element
    for (int j = 0; j < num_attributes; ++j) {
      // Consume strings for the attribute name and value.
      // Name length fuzzed between 1 and 64, value length between 0 and 128.
      std::string attr_name = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(1, 64));
      std::string attr_value = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 128));
      // API Call: void tinyxml2::XMLElement::SetAttribute(const char *, const char *)
      element->SetAttribute(attr_name.c_str(), attr_value.c_str());
    }
  }

  // Fuzzing document serialization.
  // Create an XMLPrinter object. This object manages its own internal buffer
  // for the printed XML string, and its destructor will automatically free it.
  tinyxml2::XMLPrinter printer;
  // API Call: void tinyxml2::XMLDocument::Print(XMLPrinter *)
  // This call serializes the XMLDocument into the printer's internal buffer.
  doc->Print(&printer);

  // Access the printed string to ensure the serialization process completes
  // without crashes or errors. No need to free this string, as it's owned
  // by the 'printer' object which will clean up automatically.
  const char* printed_xml_output = printer.CStr();
  (void)printed_xml_output; // Cast to void to suppress unused variable warning.

  // All resources allocated by tinyxml2 through the XMLDocument are
  // automatically released when 'doc' (std::unique_ptr) goes out of scope.
  // The 'printer' object also cleans up its resources automatically.
  return 0;
}