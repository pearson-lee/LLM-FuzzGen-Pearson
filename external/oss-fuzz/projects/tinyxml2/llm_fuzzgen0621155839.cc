#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/tinyxml2/tinyxml2.h" // All headers are provided with full project-relative path

// For SaveFile to a temporary file
#include <cstdio>
#include <memory> // For std::unique_ptr
#include <unistd.h> // For close() and mkstemp()

// Define a custom deleter for FILE* to use with std::unique_ptr
struct FileCloser {
    void operator()(FILE* f) const {
        if (f) {
            fclose(f);
        }
    }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  FuzzedDataProvider fdp(Data, Size);

  // Use a unique_ptr for XMLDocument to ensure it's always deleted, preventing memory leaks.
  // The XMLDocument manages the memory of its child nodes and attributes.
  // Replaced std::make_unique with direct new and unique_ptr constructor for C++11 compatibility.
  std::unique_ptr<tinyxml2::XMLDocument> doc(new tinyxml2::XMLDocument());

  // Consume data for various operations
  std::string elementName = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(1, 32));
  std::string attributeName = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(1, 32));
  std::string attributeValue = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(1, 64));
  bool compactMode = fdp.ConsumeBool();

  // 1. Exercise tinyxml2::XMLElement::SetAttribute(const char *, const char *)
  // This also exercises tinyxml2::XMLElement::FindOrCreateAttribute(const char *)
  {
    tinyxml2::XMLElement* element = doc->NewElement(elementName.c_str());
    if (element) {
      doc->InsertFirstChild(element); // Link to document to ensure proper memory management by doc
      element->SetAttribute(attributeName.c_str(), attributeValue.c_str());

      // Also test other SetAttribute overloads to maximize coverage
      element->SetAttribute("int_attr", fdp.ConsumeIntegral<int>());
      element->SetAttribute("uint_attr", fdp.ConsumeIntegral<unsigned int>());
      element->SetAttribute("long_attr", fdp.ConsumeIntegral<long>());
      element->SetAttribute("ulong_attr", fdp.ConsumeIntegral<unsigned long>());
      element->SetAttribute("bool_attr", fdp.ConsumeBool());
      element->SetAttribute("double_attr", fdp.ConsumeFloatingPoint<double>());
      element->SetAttribute("float_attr", fdp.ConsumeFloatingPoint<float>());
    }
  }

  // 2. Exercise tinyxml2::XMLDocument::SaveFile(const char *, bool)
  {
    // Create a temporary file name for SaveFile(const char*, bool)
    char temp_filename[] = "/tmp/fuzz_tinyxml2_XXXXXX";
    int fd = mkstemp(temp_filename);
    if (fd != -1) {
        close(fd); // Close the file descriptor, we just need the name
        doc->SaveFile(temp_filename, compactMode);
        remove(temp_filename); // Clean up the temporary file
    }

    // Test with nullptr filename to hit the 'if (!filename)' branch in SaveFile(const char*, bool)
    // Explicitly cast nullptr to const char* to resolve ambiguity.
    doc->SaveFile(static_cast<const char*>(nullptr), compactMode);

    // Test SaveFile(_IO_FILE*, bool)
    // Re-create a temporary file for FILE* operations
    int fd_fp = mkstemp(temp_filename);
    if (fd_fp != -1) {
        // Use std::unique_ptr with a custom deleter to ensure fclose is called
        std::unique_ptr<FILE, FileCloser> fp(fdopen(fd_fp, "w"));
        if (fp) {
            doc->SaveFile(fp.get(), compactMode);
        }
        remove(temp_filename); // Clean up
    }
  }

  // 3. Exercise tinyxml2::XMLElement::ShallowClone(XMLDocument *)
  {
    tinyxml2::XMLElement* originalElement = doc->NewElement("Original");
    if (originalElement) {
      doc->InsertEndChild(originalElement);
      originalElement->SetAttribute("clone_attr_name", "clone_attr_value");
      originalElement->SetText("Original Text");

      // Test with doc = nullptr to hit the 'if (!doc)' branch in ShallowClone
      tinyxml2::XMLNode* clonedNodeNullDoc = originalElement->ShallowClone(nullptr);
      // The cloned node is owned by the original document if doc is nullptr.
      // No explicit deletion needed here as 'doc' (unique_ptr) will clean it up.

      // Test with a new document to ensure the cloned node is owned by the new document
      // Replaced std::make_unique with direct new and unique_ptr constructor for C++11 compatibility.
      std::unique_ptr<tinyxml2::XMLDocument> newDoc(new tinyxml2::XMLDocument());
      tinyxml2::XMLNode* clonedNodeNewDoc = originalElement->ShallowClone(newDoc.get());
      // The cloned node is owned by 'newDoc'. 'newDoc' will be destroyed at the end of this scope,
      // cleaning up 'clonedNodeNewDoc'.
    }
  }

  // 4. Exercise tinyxml2::XMLPrinter::VisitEnter(const XMLElement &, const XMLAttribute *)
  // This function is part of the XMLVisitor interface and is called by XMLDocument::Print.
  {
    // Create an XMLPrinter. We use a null FILE* as the primary goal is to exercise the VisitEnter logic
    // and not necessarily perform actual file I/O for this specific test.
    // The XMLPrinter constructor takes a FILE*, a bool for compact mode, and an int for depth.
    tinyxml2::XMLPrinter printer(nullptr, compactMode, 0);
    doc->Print(&printer); // This will trigger calls to VisitEnter for elements and attributes
  }

  // 5. Exercise tinyxml2::XMLElement::QueryBoolAttribute(const char *, bool *)
  {
    tinyxml2::XMLElement* queryElement = doc->NewElement("QueryElement");
    if (queryElement) {
      doc->InsertEndChild(queryElement);

      // Test various boolean string values for attributes to cover parsing logic
      queryElement->SetAttribute("bool_true", "true");
      queryElement->SetAttribute("bool_false", "false");
      queryElement->SetAttribute("bool_1", "1");
      queryElement->SetAttribute("bool_0", "0");
      queryElement->SetAttribute("bool_TRUE", "TRUE");
      queryElement->SetAttribute("bool_FALSE", "FALSE");
      queryElement->SetAttribute("bool_invalid", "not_a_bool"); // Test invalid input

      bool result;
      tinyxml2::XMLError error;

      // Call QueryBoolAttribute with different attribute names
      error = queryElement->QueryBoolAttribute("bool_true", &result);
      error = queryElement->QueryBoolAttribute("bool_false", &result);
      error = queryElement->QueryBoolAttribute("bool_1", &result);
      error = queryElement->QueryBoolAttribute("bool_0", &result);
      error = queryElement->QueryBoolAttribute("bool_TRUE", &result);
      error = queryElement->QueryBoolAttribute("bool_FALSE", &result);
      error = queryElement->QueryBoolAttribute("bool_invalid", &result);
      error = queryElement->QueryBoolAttribute(attributeName.c_str(), &result); // Use a fuzzed attribute name
    }
  }

  // The unique_ptr 'doc' will automatically delete the XMLDocument and all its owned nodes
  // when it goes out of scope, ensuring memory safety and preventing leaks.

  return 0;
}