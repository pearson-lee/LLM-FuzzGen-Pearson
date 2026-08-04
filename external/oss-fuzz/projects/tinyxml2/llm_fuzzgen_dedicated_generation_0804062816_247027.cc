/* BLOCKER_STRATEGY_CONTRACT
required_state: The 'attribute' parameter of 'tinyxml2::XMLElement::DeleteAttribute' must be a null pointer.
state_constructor: An 'XMLElement' is created.
trigger_api: 'tinyxml2::XMLElement::DeleteAttribute(nullptr)' is called on the element.
preserved_invariants: The argument to 'DeleteAttribute' must remain a null pointer.
END_BLOCKER_STRATEGY_CONTRACT */

#include <cstddef>
#include <cstdint>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>

// The target function is private. We use this preprocessor trick to gain access
// for the purpose of creating this specific fuzz target.
#define private public
#include "/src/tinyxml2/tinyxml2.h"
#undef private

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  tinyxml2::XMLDocument doc;
  
  const std::string root_name = fdp.ConsumeRandomLengthString(16);
  tinyxml2::XMLElement* root = doc.NewElement(root_name.c_str());
  if (!root) {
    return 0;
  }
  doc.InsertFirstChild(root);

  // The previous attempt used the public 'DeleteAttribute(const char*)' overload,
  // which can never call the private 'DeleteAttribute(XMLAttribute*)' overload
  // with a null pointer. This attempt tries to call the target function directly
  // with a null pointer. This will verify if the function is callable and, if so,
  // will reach the target blocker.
  root->DeleteAttribute((tinyxml2::XMLAttribute*)nullptr);

  return 0;
}
