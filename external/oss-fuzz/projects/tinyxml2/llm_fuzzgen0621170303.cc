#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <memory> // Required for std::unique_ptr
#include <fuzzer/FuzzedDataProvider.h>

// Include the tinyxml2 header with its full project-relative path
#include "/src/tinyxml2/tinyxml2.h"

// Define a constant for buffer size, as used in tinyxml2's internal ToStr functions
#ifndef BUF_SIZE
#define BUF_SIZE 256
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  FuzzedDataProvider fdp(Data, Size);

  // Use a unique_ptr for XMLDocument to ensure proper memory management (RAII)
  // The XMLDocument manages the memory of nodes created through its New* methods.
  // Replaced std::make_unique with direct new and unique_ptr constructor for C++11 compatibility.
  std::unique_ptr<tinyxml2::XMLDocument> doc(new tinyxml2::XMLDocument());

  // Fuzzing tinyxml2::XMLElement::InsertNewChildElement(const char *)
  // This function creates a new element and inserts it as a child.
  // We need a root element to insert children into.
  std::string root_element_name = fdp.ConsumeRandomLengthString(32);
  tinyxml2::XMLElement* root_element = doc->NewElement(root_element_name.c_str());
  doc->InsertFirstChild(root_element);

  if (root_element) {
    std::string child_element_name = fdp.ConsumeRandomLengthString(32);
    // Call the target function
    tinyxml2::XMLElement* new_child = root_element->InsertNewChildElement(child_element_name.c_str());
    (void)new_child; // Suppress unused variable warning if not used further
  }

  // Fuzzing tinyxml2::XMLElement::QueryIntText(int *)
  // This function attempts to parse the text content of an element as an integer.
  // We need an element and set its text content.
  std::string text_element_name = fdp.ConsumeRandomLengthString(32);
  tinyxml2::XMLElement* text_element = doc->NewElement(text_element_name.c_str());
  if (root_element) {
    root_element->InsertEndChild(text_element);
  } else {
    doc->InsertFirstChild(text_element);
  }

  if (text_element) {
    // Generate text that is sometimes a valid integer, sometimes not.
    if (fdp.ConsumeBool()) {
      text_element->SetText(fdp.ConsumeIntegral<int>()); // Valid integer
    } else {
      text_element->SetText(fdp.ConsumeRandomLengthString(64).c_str()); // Random string, potentially invalid integer
    }
    int int_value = 0;
    // Call the target function
    doc->ClearError(); // Clear any previous errors before calling
    tinyxml2::XMLError error = text_element->QueryIntText(&int_value);
    (void)error; // Suppress unused variable warning
  }

  // Fuzzing tinyxml2::XMLElement::BoolAttribute(const char *, bool)
  // This function retrieves a boolean attribute, using a default value if not found.
  std::string attr_element_name = fdp.ConsumeRandomLengthString(32);
  tinyxml2::XMLElement* attr_element = doc->NewElement(attr_element_name.c_str());
  if (root_element) {
    root_element->InsertEndChild(attr_element);
  } else {
    doc->InsertFirstChild(attr_element);
  }

  if (attr_element) {
    std::string attribute_name = fdp.ConsumeRandomLengthString(32);
    bool default_bool_value = fdp.ConsumeBool();

    // Sometimes set the attribute, sometimes don't, to cover both branches in QueryBoolAttribute
    if (fdp.ConsumeBool()) {
      attr_element->SetAttribute(attribute_name.c_str(), fdp.ConsumeBool());
    }

    // Call the target function
    bool retrieved_bool = attr_element->BoolAttribute(attribute_name.c_str(), default_bool_value);
    (void)retrieved_bool; // Suppress unused variable warning
  }

  // Fuzzing tinyxml2::XMLPrinter::PushAttribute(const char *, bool)
  // This function adds a boolean attribute to the current element being printed.
  // XMLPrinter manages its own buffer, which is cleared on destruction.
  tinyxml2::XMLPrinter printer;

  std::string printer_element_name = fdp.ConsumeRandomLengthString(32);
  printer.OpenElement(printer_element_name.c_str());

  std::string printer_attr_name = fdp.ConsumeRandomLengthString(32);
  bool printer_attr_value = fdp.ConsumeBool();
  // Call the target function
  printer.PushAttribute(printer_attr_name.c_str(), printer_attr_value);

  printer.CloseElement();
  (void)printer.CStr(); // Access CStr to ensure the buffer is finalized, if needed.

  // Fuzzing tinyxml2::XMLNode::ChildElementCount(const char *)
  // This function counts child elements with a specific name.
  std::string count_element_name = fdp.ConsumeRandomLengthString(32);
  tinyxml2::XMLElement* count_parent_element = doc->NewElement(count_element_name.c_str());
  if (root_element) {
    root_element->InsertEndChild(count_parent_element);
  } else {
    doc->InsertFirstChild(count_parent_element);
  }

  if (count_parent_element) {
    std::string target_child_name = fdp.ConsumeRandomLengthString(32);
    // Add a varying number of children, some matching the target name, some not.
    size_t num_children = fdp.ConsumeIntegralInRange<size_t>(0, 10);
    for (size_t i = 0; i < num_children; ++i) {
      std::string child_name;
      if (fdp.ConsumeBool()) {
        child_name = target_child_name; // Matching name
      } else {
        child_name = fdp.ConsumeRandomLengthString(32); // Non-matching name
      }
      tinyxml2::XMLElement* child = doc->NewElement(child_name.c_str());
      count_parent_element->InsertEndChild(child);
    }

    // Call the target function
    int count = count_parent_element->ChildElementCount(target_child_name.c_str());
    (void)count; // Suppress unused variable warning
  }

  // The unique_ptr 'doc' will automatically delete the XMLDocument and all its associated nodes
  // when it goes out of scope, ensuring memory safety.
  // The XMLPrinter 'printer' also cleans up its internal buffer on destruction.

  return 0;
}