#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fstream>
#include <cstdio> // For remove()
#include <memory> // For std::unique_ptr
#include <fuzzer/FuzzedDataProvider.h> // Required for FuzzedDataProvider

#include "/src/tinyxml2/tinyxml2.h" // Always emit #include with the full project-relative path

// Define a unique temporary file name for LoadFile fuzzing
// This is a simple approach; in a real fuzzer, you might use a more robust temp file creation.
// For this exercise, a fixed name is acceptable as the fuzzer runs in an isolated environment.
const char* kTempFilename = "fuzz_temp_tinyxml2.xml";

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  FuzzedDataProvider fdp(Data, Size);

  // 1. Fuzzing tinyxml2::XMLDocument::LoadFile(const char *)
  // This function requires a file path, so we write the fuzzed data to a temporary file.
  std::string xml_content = fdp.ConsumeRemainingBytesAsString();

  // Write fuzzed data to a temporary file
  std::ofstream temp_file(kTempFilename, std::ios::binary);
  if (temp_file.is_open()) {
    temp_file.write(xml_content.data(), xml_content.size());
    temp_file.close();

    // Create an XMLDocument object. Its destructor will handle memory cleanup.
    tinyxml2::XMLDocument doc;
    // Load the fuzzed content from the temporary file
    doc.LoadFile(kTempFilename);

    // Remove the temporary file immediately after loading
    std::remove(kTempFilename);

    // Proceed with other API calls only if the document was at least partially loaded
    // (i.e., not a critical error preventing any further operations)
    if (!doc.Error()) {
      // 2. Fuzzing tinyxml2::XMLElement::SetAttribute(const char *, const char *)
      // 3. Fuzzing tinyxml2::XMLElement::FindOrCreateAttribute(const char *)
      // These functions require an XMLElement. We'll try to get the root element.
      tinyxml2::XMLElement* root_element = doc.RootElement();
      if (root_element) {
        // Generate fuzzed attribute name and value
        std::string attr_name = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange(0, 64));
        std::string attr_value = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange(0, 128));

        // Call SetAttribute
        root_element->SetAttribute(attr_name.c_str(), attr_value.c_str());

        // Removed the call to FindOrCreateAttribute as it is a private member.
        // The SetAttribute call already covers attribute creation/modification.
      }

      // 4. Fuzzing tinyxml2::XMLNode::DeepClone(XMLDocument *)
      // This function creates a deep copy of an XMLNode into a target XMLDocument.
      // We create a new XMLDocument to hold the cloned content.
      tinyxml2::XMLDocument cloned_doc;
      // DeepClone the main document into the new document.
      // The cloned_doc's destructor will manage the memory of the cloned nodes.
      doc.DeepClone(&cloned_doc);

      // 5. Fuzzing tinyxml2::XMLDocument::Print(XMLPrinter *)
      // This function serializes the XML document.
      // We use a default XMLPrinter which prints to stdout, exercising the serialization logic.
      tinyxml2::XMLPrinter printer;
      doc.Print(&printer);

      // Optionally, print the cloned document as well to exercise more paths
      if (!cloned_doc.Error()) {
        tinyxml2::XMLPrinter cloned_printer;
        cloned_doc.Print(&cloned_printer);
      }
    }
  } else {
    // If the temporary file could not be opened, report an error or handle gracefully.
    // For fuzzing, we can just return, as this is an environment issue, not a tinyxml2 bug.
    return 0;
  }

  // All tinyxml2 objects (doc, cloned_doc, printer) are stack-allocated or managed by
  // tinyxml2's internal memory pools associated with XMLDocument, ensuring proper cleanup
  // when they go out of scope. No explicit delete calls are needed for these objects.

  return 0;
}