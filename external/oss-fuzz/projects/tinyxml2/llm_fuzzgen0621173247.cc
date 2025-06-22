#include <cstddef>
#include <cstdint>
#include <string>
#include <memory> // For std::unique_ptr
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/tinyxml2/tinyxml2.h" // Required header for tinyxml2 library

// Define the fuzz target function. This function will be called repeatedly by the fuzzer
// with different inputs.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  // Initialize FuzzedDataProvider to consume bytes from the input data.
  FuzzedDataProvider fdp(Data, Size);

  // Create an XMLDocument using std::unique_ptr for automatic memory management.
  // This ensures that the document and all its allocated nodes are properly
  // deallocated when the unique_ptr goes out of scope, preventing memory leaks.
  // Replaced std::make_unique with direct new allocation for compatibility.
  std::unique_ptr<tinyxml2::XMLDocument> doc(new tinyxml2::XMLDocument());

  // Create an XMLElement. This element will be managed by the XMLDocument's
  // internal memory pool.
  tinyxml2::XMLElement* element = doc->NewElement("FuzzElement");
  // Insert the element into the document. This transfers ownership to the document,
  // so when 'doc' is destroyed, 'element' and its children will also be destroyed.
  doc->InsertFirstChild(element);

  // Consume an integral to decide which of the five target API functions to call.
  // This ensures diversity in API calls.
  // Increased range to include QueryUnsignedText.
  uint8_t func_choice = fdp.ConsumeIntegralInRange<uint8_t>(0, 5); // 0-5 for 6 functions

  // Consume an integral to decide the type of text content for the element.
  // 0: No text node (to cover XML_NO_TEXT_NODE path)
  // 1: Invalid text (to cover XML_CAN_NOT_CONVERT_TEXT path)
  // 2: Valid text (to cover XML_SUCCESS path)
  uint8_t content_type = fdp.ConsumeIntegralInRange<uint8_t>(0, 2);

  // Variables to hold the results of the Query*Text calls.
  bool bool_val = false;
  int64_t int64_val = 0;
  uint64_t uint64_val = 0;
  float float_val = 0.0f;
  double double_val = 0.0;
  unsigned int uint_val = 0; // Added for QueryUnsignedText

  // Apply text content based on the fuzzed input, if the element exists.
  // The element is guaranteed to exist here as it's created above.
  if (content_type == 1) { // Invalid text scenario
    // Generate a random string that is unlikely to be a valid number/boolean.
    std::string invalid_text = fdp.ConsumeRandomLengthString(fdp.remaining_bytes());
    element->SetText(invalid_text.c_str());
  } else if (content_type == 2) { // Valid text scenario
    // Set text based on the chosen function type to ensure valid conversion.
    switch (func_choice) {
      case 0: // QueryBoolText: Set "true" or "false"
        element->SetText(fdp.ConsumeBool() ? "true" : "false");
        break;
      case 1: // QueryInt64Text: Set a random int64_t as text
        element->SetText(fdp.ConsumeIntegral<int64_t>());
        break;
      case 2: // QueryUnsigned64Text: Set a random uint64_t as text
        element->SetText(fdp.ConsumeIntegral<uint64_t>());
        break;
      case 3: // QueryFloatText: Set a random float as text
        element->SetText(fdp.ConsumeFloatingPoint<float>());
        break;
      case 4: // QueryDoubleText: Set a random double as text
        element->SetText(fdp.ConsumeFloatingPoint<double>());
        break;
      case 5: // QueryUnsignedText: Set a random unsigned int as text
        element->SetText(fdp.ConsumeIntegral<unsigned int>());
        break;
    }
  }
  // If content_type is 0, no text is set, which covers the XML_NO_TEXT_NODE path.

  // Call the target API function based on the fuzzed choice.
  switch (func_choice) {
    case 0: // Target: tinyxml2::XMLElement::QueryBoolText(bool *)
      element->QueryBoolText(&bool_val);
      break;
    case 1: // Target: tinyxml2::XMLElement::QueryInt64Text(int64_t *)
      element->QueryInt64Text(&int64_val);
      break;
    case 2: // Target: tinyxml2::XMLElement::QueryUnsigned64Text(uint64_t *)
      element->QueryUnsigned64Text(&uint64_val);
      break;
    case 3: // Target: tinyxml2::XMLElement::QueryFloatText(float *)
      element->QueryFloatText(&float_val);
      break;
    case 4: // Target: tinyxml2::XMLElement::QueryDoubleText(double *)
      element->QueryDoubleText(&double_val);
      break;
    case 5: // Target: tinyxml2::XMLElement::QueryUnsignedText(unsigned int *)
      // Added to cover tinyxml2::XMLElement::QueryUnsignedText which had 0% coverage.
      element->QueryUnsignedText(&uint_val);
      break;
  }

  // All memory allocated by tinyxml2::XMLDocument (including 'element' and its text node)
  // is automatically freed when 'doc' (a unique_ptr) goes out of scope at the end of this function.
  return 0;
}