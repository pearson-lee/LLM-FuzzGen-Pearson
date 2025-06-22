#include <cstddef>
#include <cstdint>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>

// Include the tinyxml2 header with its full project-relative path.
#include "/src/tinyxml2/tinyxml2.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  FuzzedDataProvider fdp(Data, Size);

  // Create a tinyxml2 document. This manages its own memory for nodes.
  tinyxml2::XMLDocument doc;

  // Consume data for various operations
  std::string root_element_name = fdp.ConsumeRandomLengthString(32);
  if (root_element_name.empty()) {
    root_element_name = "root"; // Ensure a non-empty name
  }

  // Create a root element
  tinyxml2::XMLElement* root = doc.NewElement(root_element_name.c_str());
  doc.InsertFirstChild(root);

  // Fuzzing tinyxml2::XMLElement::UnsignedAttribute and DoubleAttribute
  // These functions call QueryUnsignedAttribute/QueryDoubleAttribute, which in turn
  // call FindAttribute. We want to test cases where the attribute exists and
  // where it does not exist (to hit the XML_NO_ATTRIBUTE branch).
  std::string attr_name_unsigned = fdp.ConsumeRandomLengthString(32);
  std::string attr_name_double = fdp.ConsumeRandomLengthString(32);
  unsigned int default_unsigned_val = fdp.ConsumeIntegral<unsigned int>();
  double default_double_val = fdp.ConsumeFloatingPoint<double>();

  // Decide if we should add the attributes to cover both branches (attribute found/not found)
  bool add_unsigned_attr = fdp.ConsumeBool();
  bool add_double_attr = fdp.ConsumeBool();

  if (add_unsigned_attr) {
    // Add a valid unsigned integer attribute
    root->SetAttribute(attr_name_unsigned.c_str(), fdp.ConsumeIntegral<unsigned int>());
  }
  if (add_double_attr) {
    // Add a valid double attribute
    root->SetAttribute(attr_name_double.c_str(), fdp.ConsumeFloatingPoint<double>());
  }

  // Call the target functions. If the attribute doesn't exist, it should return the default value,
  // covering the XML_NO_ATTRIBUTE branch in QueryUnsignedAttribute/QueryDoubleAttribute.
  root->UnsignedAttribute(attr_name_unsigned.c_str(), default_unsigned_val);
  root->DoubleAttribute(attr_name_double.c_str(), default_double_val);


  // Fuzzing tinyxml2::XMLElement::UnsignedText and DoubleText
  // These functions call QueryUnsignedText/QueryDoubleText. We want to test:
  // 1. No text node (FirstChild() is null or not a text node)
  // 2. Text node exists, but conversion fails
  // 3. Text node exists, and conversion succeeds
  std::string text_content = fdp.ConsumeRandomLengthString(64);
  unsigned int default_unsigned_text_val = fdp.ConsumeIntegral<unsigned int>();
  double default_double_text_val = fdp.ConsumeFloatingPoint<double>();

  // Decide what kind of child to add to cover different branches in Query*Text
  enum ChildType { NO_CHILD, ELEMENT_CHILD, TEXT_CHILD, kMaxValue = TEXT_CHILD };
  ChildType child_type = fdp.ConsumeEnum<ChildType>();

  switch (child_type) {
    case NO_CHILD:
      // No child, so FirstChild() will be null, covering XML_NO_TEXT_NODE
      break;
    case ELEMENT_CHILD: {
      // Add an element child, so FirstChild() exists but ToText() is null
      std::string child_element_name = fdp.ConsumeRandomLengthString(32);
      if (child_element_name.empty()) {
        child_element_name = "child";
      }
      root->InsertNewChildElement(child_element_name.c_str());
      break;
    }
    case TEXT_CHILD: {
      // Add a text child. The content will determine if conversion succeeds/fails.
      root->SetText(text_content.c_str());
      break;
    }
  }

  // Call the target functions
  root->UnsignedText(default_unsigned_text_val);
  root->DoubleText(default_double_text_val);


  // Fuzzing tinyxml2::XMLElement::InsertNewText
  // This function calls _document->NewText and then InsertEndChild.
  // We want to ensure InsertEndChild's success/failure branches are covered.
  // InsertEndChild can fail if the node is null or already linked.
  // NewText should always return a valid node, so we focus on InsertEndChild's behavior.
  // By inserting a fuzzed string, we ensure varied text node creation.
  std::string new_text_content = fdp.ConsumeRandomLengthString(128);
  root->InsertNewText(new_text_content.c_str());

  // The XMLDocument destructor will handle all memory cleanup, ensuring memory safety.
  return 0;
}