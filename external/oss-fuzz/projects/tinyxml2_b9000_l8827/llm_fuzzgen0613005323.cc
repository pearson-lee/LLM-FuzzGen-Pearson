#include "/src/tinyxml2/tinyxml2.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>

// Target APIs:
// 1. void tinyxml2::XMLPrinter::Print(const char *, void) (and TIXML_VSCPRINTF)
//    Exercised by doc.Print(&printer) which internally calls this for formatting.
// 2. void tinyxml2::XMLDeclaration::~XMLDeclaration()
//    Exercised by creating and adding an XMLDeclaration to the document, then letting doc's destructor clean it up.
// 3. void tinyxml2::XMLUnknown::~XMLUnknown()
//    Exercised by creating and adding an XMLUnknown node, then letting doc's destructor clean it up.
// 4. void tinyxml2::XMLComment::~XMLComment()
//    Exercised by creating and adding an XMLComment, then letting doc's destructor clean it up.
// 5. void tinyxml2::XMLText::~XMLText()
//    Exercised by creating and adding an XMLText node, then letting doc's destructor clean it up.
//
// Also exercises:
// - XMLDocument::Parse()
// - XMLDocument::NewElement(), XMLElement::SetAttribute()
// - XMLDocument::NewDeclaration(), XMLDocument::NewComment(), XMLDocument::NewText(), XMLDocument::NewUnknown()
// - XMLNode::InsertEndChild(), XMLNode::InsertFirstChild()
// - XMLDocument destruction and cleanup of all owned nodes.

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  FuzzedDataProvider fdp(Data, Size);

  // Create an XMLDocument. All nodes created by this document will be
  // automatically deallocated when 'doc' goes out of scope, preventing memory leaks.
  tinyxml2::XMLDocument doc;

  // Consume some data to attempt to parse an initial XML structure.
  // This helps exercise parsing paths and can create a base for further manipulation.
  std::string initial_xml_data = fdp.ConsumeRandomLengthString(1024);
  doc.Parse(initial_xml_data.c_str(), initial_xml_data.length());
  // Errors from Parse are ignored; the fuzzer will proceed to build or modify the document.

  // Ensure there's a root element. If parsing failed or the XML was empty, create one.
  tinyxml2::XMLElement* root = doc.RootElement();
  if (!root) {
    std::string root_name_str = fdp.ConsumeRandomLengthString(32);
    // Ensure the root name is not empty, as NewElement might behave unexpectedly or return nullptr.
    if (root_name_str.empty()) {
      root_name_str = "defaultRoot";
    }
    root = doc.NewElement(root_name_str.c_str());
    if (root) {
      doc.InsertFirstChild(root); // Insert the new root into the document.
    }
  }

  // Only proceed with document manipulation if a root element exists or was successfully created.
  if (root) {
    // Optionally add an XMLDeclaration. This exercises XMLDeclaration creation and its destructor.
    if (fdp.ConsumeBool()) {
      std::string decl_text = fdp.ConsumeRandomLengthString(128);
      tinyxml2::XMLDeclaration* declaration = doc.NewDeclaration(decl_text.c_str());
      // NewDeclaration can return nullptr if decl_text is malformed, though often it's lenient.
      // If not nullptr, it's owned by the doc and should be inserted.
      if (declaration) {
        // Insert at the beginning of the document, before the root element if possible.
        // If doc already has children, InsertFirstChild handles this.
        doc.InsertFirstChild(declaration);
      }
    }

    // Add a few child elements to the root, with optional attributes and text.
    int num_child_elements = fdp.ConsumeIntegralInRange<int>(0, 3);
    for (int i = 0; i < num_child_elements; ++i) {
      std::string el_name_str = fdp.ConsumeRandomLengthString(32);
      if (el_name_str.empty()) {
        el_name_str = "childElement";
      }
      tinyxml2::XMLElement* child_element = doc.NewElement(el_name_str.c_str());
      if (child_element) {
        root->InsertEndChild(child_element); // child_element is now owned by 'root' (and 'doc').

        // Optionally set an attribute.
        if (fdp.ConsumeBool()) {
          std::string attr_name_str = fdp.ConsumeRandomLengthString(32);
          if (attr_name_str.empty()) {
            attr_name_str = "attributeName";
          }
          std::string attr_value_str = fdp.ConsumeRandomLengthString(64);
          child_element->SetAttribute(attr_name_str.c_str(), attr_value_str.c_str());
        }

        // Optionally add a text node. This exercises XMLText creation and its destructor.
        if (fdp.ConsumeBool()) {
          std::string text_content_str = fdp.ConsumeRandomLengthString(128);
          tinyxml2::XMLText* text_node = doc.NewText(text_content_str.c_str());
          if (text_node) {
            child_element->InsertEndChild(text_node); // text_node is now owned by child_element.
          }
        }
      }
    }

    // Optionally add a comment to the root. This exercises XMLComment creation and its destructor.
    if (fdp.ConsumeBool()) {
      std::string comment_text_str = fdp.ConsumeRandomLengthString(128);
      tinyxml2::XMLComment* comment_node = doc.NewComment(comment_text_str.c_str());
      if (comment_node) {
        root->InsertEndChild(comment_node); // comment_node is now owned by 'root'.
      }
    }

    // Optionally add an unknown node to the root. This exercises XMLUnknown creation and its destructor.
    if (fdp.ConsumeBool()) {
      std::string unknown_text_str = fdp.ConsumeRandomLengthString(128);
      tinyxml2::XMLUnknown* unknown_node = doc.NewUnknown(unknown_text_str.c_str());
      if (unknown_node) {
        root->InsertEndChild(unknown_node); // unknown_node is now owned by 'root'.
      }
    }
  }

  // Create an XMLPrinter.
  // Fuzz the 'compact' mode option. The FILE* is nullptr, so it prints to an internal buffer.
  tinyxml2::XMLPrinter printer(nullptr, fdp.ConsumeBool());

  // Print the document using the printer. This exercises various XMLPrinter methods,
  // including the targeted XMLPrinter::Print(const char* format, ...) which is used
  // internally for formatting different parts of the XML structure (elements, attributes, comments, etc.).
  // It also indirectly tests TIXML_VSCPRINTF.
  doc.Print(&printer);

  // The XMLDocument 'doc' will go out of scope here. Its destructor will be called,
  // which in turn will delete all nodes (elements, text, comments, declarations, unknowns)
  // that were created and added to it. This ensures their respective destructors are called,
  // covering ~XMLDeclaration, ~XMLUnknown, ~XMLComment, and ~XMLText.
  // All memory allocated by tinyxml2 for the document nodes is managed by the XMLDocument's pool
  // and is freed when the document is destroyed.
  return 0;
}