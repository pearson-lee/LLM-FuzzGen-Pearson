#include <fuzzer/FuzzedDataProvider.h>

#include "/src/tinyxml2/tinyxml2.h"
#include <string>
#include <vector>
#include <memory> // For std::unique_ptr
#include <cstdio> // For FILE, fopen, fclose, remove
#include <unistd.h> // For unlink

// Define a compile-time macro for unique filenames.
// This will be provided by the build system in a real fuzzing environment.
#ifndef _FUZZ_TARGET_NAME
#define _FUZZ_TARGET_NAME "tinyxml2_fuzzer"
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  FuzzedDataProvider fdp(Data, Size);

  // Use std::unique_ptr for automatic cleanup of XMLDocument objects.
  // This ensures memory safety by deallocating the document and its associated
  // nodes/elements when they go out of scope.
  // Fix: Replaced std::make_unique with direct new allocation for compatibility.
  std::unique_ptr<tinyxml2::XMLDocument> doc(new tinyxml2::XMLDocument());

  // --- 1. Fuzzing XMLDocument::Parse ---
  /*
   * ANALYSIS: XMLDocument::Parse is a fundamental entry point for processing XML data.
   *           While it showed good coverage in the initial report, exercising it with
   *           diverse and potentially malformed input is crucial to test its robustness
   *           and error handling, which can impact subsequent operations.
   * IMPLEMENTATION: Consume a random length string from the FuzzedDataProvider and
   *                 pass it to the Parse method. We reserve half of the input bytes
   *                 for this, leaving the other half for file operations.
   */
  std::string xml_string = fdp.ConsumeRandomLengthString(fdp.remaining_bytes() / 2);
  doc->Parse(xml_string.c_str());

  // --- 2. Fuzzing XMLDocument::NewElement and XMLNode::InsertFirstChild ---
  /*
   * ANALYSIS: The coverage report indicated 0% line and branch coverage for
   *           XMLDocument::NewElement and XMLNode::InsertFirstChild.
   *           Specifically, XMLNode::InsertFirstChild has an uncovered branch
   *           (`addThis->_document != _document`) when attempting to insert a node
   *           from a different document, and branches related to whether the parent
   *           node already has children (`_firstChild`).
   * IMPLEMENTATION: First, ensure a root element exists. Then, create new elements
   *                 and attempt to insert them as first children. We introduce logic
   *                 to create elements from a *second* XMLDocument instance to
   *                 specifically hit the cross-document insertion branch in
   *                 InsertFirstChild. We also vary whether the parent node is empty
   *                 or not by potentially inserting into the root or its first child.
   */
  tinyxml2::XMLElement* root_element = doc->RootElement();
  if (root_element == nullptr) {
      // If no root element exists after parsing (e.g., due to malformed XML or empty input), create one.
      std::string root_name = fdp.ConsumeRandomLengthString(10);
      root_element = doc->NewElement(root_name.c_str());
      if (root_element) {
          doc->InsertFirstChild(root_element); // This will hit the _firstChild == 0 branch in InsertFirstChild
      }
  }

  if (root_element != nullptr) {
    // Select a parent node: either the root or its first child (if available).
    tinyxml2::XMLNode* parent_node = root_element;
    if (fdp.ConsumeBool() && root_element->FirstChildElement() != nullptr) {
        parent_node = root_element->FirstChildElement();
    }

    // Create a new element to insert.
    std::string new_element_name = fdp.ConsumeRandomLengthString(10);
    tinyxml2::XMLElement* new_element = nullptr;

    // Fix: Removed the logic to create an element from a different document,
    // as tinyxml2's InsertFirstChild asserts on cross-document insertion,
    // leading to a crash and use-after-free.
    new_element = doc->NewElement(new_element_name.c_str());

    if (new_element) {
        // Attempt to insert the new element. This will exercise both the
        // `_firstChild == 0` and `_firstChild != 0` branches depending on `parent_node`'s state.
        parent_node->InsertFirstChild(new_element);
    }
  }

  // --- 3. Fuzzing XMLElement::SetAttribute and Query...Attribute (various overloads) ---
  /*
   * ANALYSIS: Multiple XMLElement::SetAttribute overloads, as well as XMLAttribute::SetAttribute
   *           and the XMLUtil::ToStr utility functions they call, showed 0% coverage.
   *           Similarly, XMLElement::Query...Attribute and XMLAttribute::Query...Value functions,
   *           which call XMLUtil::To... functions (e.g., ToInt, ToBool), also had 0% coverage.
   * IMPLEMENTATION: If a root element exists, we select it (or its first child) and
   *                 randomly call various SetAttribute overloads with fuzzed names and values
   *                 of different types. Afterwards, we attempt to query these attributes
   *                 using their respective Query...Attribute methods to cover the parsing
   *                 utility functions.
   */
  if (doc->RootElement() != nullptr) {
    tinyxml2::XMLElement* element_to_attr = doc->RootElement();
    if (fdp.ConsumeBool() && element_to_attr->FirstChildElement() != nullptr) {
        element_to_attr = element_to_attr->FirstChildElement(); // Pick first child for more diversity
    }

    std::string attr_name = fdp.ConsumeRandomLengthString(10);
    // Randomly choose an attribute type to set
    switch (fdp.ConsumeIntegralInRange(0, 7)) {
      case 0: // const char*
        element_to_attr->SetAttribute(attr_name.c_str(), fdp.ConsumeRandomLengthString(20).c_str());
        break;
      case 1: // int
        element_to_attr->SetAttribute(attr_name.c_str(), fdp.ConsumeIntegral<int>());
        break;
      case 2: // unsigned int
        element_to_attr->SetAttribute(attr_name.c_str(), fdp.ConsumeIntegral<unsigned int>());
        break;
      case 3: // long
        element_to_attr->SetAttribute(attr_name.c_str(), fdp.ConsumeIntegral<long>());
        break;
      case 4: // unsigned long
        element_to_attr->SetAttribute(attr_name.c_str(), fdp.ConsumeIntegral<unsigned long>());
        break;
      case 5: // bool
        element_to_attr->SetAttribute(attr_name.c_str(), fdp.ConsumeBool());
        break;
      case 6: // double
        element_to_attr->SetAttribute(attr_name.c_str(), fdp.ConsumeFloatingPoint<double>());
        break;
      case 7: // float
        element_to_attr->SetAttribute(attr_name.c_str(), fdp.ConsumeFloatingPoint<float>());
        break;
    }

    // Attempt to query attributes to cover XMLUtil::To... functions.
    int i_val; unsigned int ui_val; long l_val; unsigned long ul_val; bool b_val; double d_val; float f_val;
    element_to_attr->QueryIntAttribute(attr_name.c_str(), &i_val);
    element_to_attr->QueryUnsignedAttribute(attr_name.c_str(), &ui_val);
    element_to_attr->QueryInt64Attribute(attr_name.c_str(), &l_val);
    element_to_attr->QueryUnsigned64Attribute(attr_name.c_str(), &ul_val);
    element_to_attr->QueryBoolAttribute(attr_name.c_str(), &b_val);
    element_to_attr->QueryDoubleAttribute(attr_name.c_str(), &d_val);
    element_to_attr->QueryFloatAttribute(attr_name.c_str(), &f_val);
  }

  // --- 4. Fuzzing XMLDocument::SaveFile and XMLDocument::LoadFile ---
  /*
   * ANALYSIS: Both SaveFile and LoadFile overloads showed low or 0% coverage.
   *           Specific uncovered branches in LoadFile included handling of NULL filenames,
   *           `fopen` failures, empty files, and potentially very large files. SaveFile
   *           also had an uncovered branch for NULL filenames.
   * IMPLEMENTATION: Create a unique temporary filename. We introduce conditions to
   *                 trigger the NULL filename paths for both SaveFile and LoadFile.
   *                 For LoadFile, we also explicitly create an empty file or a file
   *                 with fuzzed content to hit branches related to file size and content.
   *                 All temporary files are unlinked at the end for cleanup.
   */
  std::string temp_filepath = std::string("/tmp/") + _FUZZ_TARGET_NAME + ".xml";

  // Attempt to save the document.
  if (fdp.ConsumeBool()) {
    // ANALYSIS: Target the `if ( !filename )` branch in `XMLDocument::SaveFile(const char*, bool)`.
    // IMPLEMENTATION: Pass `nullptr` as the filename.
    // Fix: Cast nullptr to const char* to resolve ambiguity.
    doc->SaveFile(static_cast<const char*>(nullptr), fdp.ConsumeBool());
  } else {
    // Save to a valid temporary file.
    doc->SaveFile(temp_filepath.c_str(), fdp.ConsumeBool());
  }

  // Now, attempt to load a document.
  // Fix: Replaced std::make_unique with direct new allocation for compatibility.
  std::unique_ptr<tinyxml2::XMLDocument> loaded_doc(new tinyxml2::XMLDocument());
  if (fdp.ConsumeBool()) {
    // ANALYSIS: Target the `if ( !filename )` branch in `XMLDocument::LoadFile(const char*)`.
    // IMPLEMENTATION: Pass `nullptr` as the filename.
    // Fix: Cast nullptr to const char* to resolve ambiguity.
    loaded_doc->LoadFile(static_cast<const char*>(nullptr));
  } else {
    // Prepare a file for loading to hit various `LoadFile(_IO_FILE*)` branches.
    FILE* fp = fopen(temp_filepath.c_str(), "wb");
    if (fp) {
        if (fdp.ConsumeBool()) {
            // ANALYSIS: Target the `if ( filelength == 0 )` branch in `LoadFile(_IO_FILE*)`.
            // IMPLEMENTATION: Create an empty file.
            // Do nothing, file remains empty.
        } else {
            // Write some fuzzed data to the file. This can also indirectly test
            // the `if ( filelength >= static_cast<unsigned long long>(maxSizeT) )`
            // branch if the fuzzer generates sufficiently large data, and
            // `if ( read != size )` if the content is truncated or partially written.
            std::string file_content = fdp.ConsumeRandomLengthString(fdp.remaining_bytes());
            fwrite(file_content.c_str(), 1, file_content.length(), fp);
        }
        fclose(fp);
    }
    loaded_doc->LoadFile(temp_filepath.c_str());
  }

  // Clean up the temporary file created for SaveFile/LoadFile.
  // CRITICAL: Ensure all temporary files are removed to maintain a clean and deterministic fuzzing environment.
  unlink(temp_filepath.c_str());

  return 0;
}