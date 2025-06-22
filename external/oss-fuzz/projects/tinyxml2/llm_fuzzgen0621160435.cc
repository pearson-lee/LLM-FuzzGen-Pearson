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
#include <cstring> // For strcpy

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
  std::string textValue = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(1, 64));
  std::string commentValue = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(1, 64));
  std::string declarationValue = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(1, 64));
  std::string unknownValue = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(1, 64));


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

      // Added to cover tinyxml2::XMLElement::DeleteAttribute(char const*)
      element->DeleteAttribute(attributeName.c_str());
    }
  }

  // 2. Exercise tinyxml2::XMLDocument::SaveFile(const char *, bool) and LoadFile
  {
    // Create a temporary file name for SaveFile(const char*, bool)
    char temp_filename[] = "/tmp/fuzz_tinyxml2_XXXXXX";
    int fd = mkstemp(temp_filename);
    if (fd != -1) {
        close(fd); // Close the file descriptor, we just need the name
        doc->SaveFile(temp_filename, compactMode);

        // Added to cover tinyxml2::XMLDocument::LoadFile(const char*)
        std::unique_ptr<tinyxml2::XMLDocument> loadedDoc(new tinyxml2::XMLDocument());
        loadedDoc->LoadFile(temp_filename);

        remove(temp_filename); // Clean up the temporary file
    }

    // Test with nullptr filename to hit the 'if (!filename)' branch in SaveFile(const char*, bool)
    // Explicitly cast nullptr to const char* to resolve ambiguity.
    doc->SaveFile(static_cast<const char*>(nullptr), compactMode);

    // Test SaveFile(_IO_FILE*, bool)
    // Re-create a temporary file for FILE* operations.
    // Re-initialize temp_filename to ensure mkstemp can generate a new unique name.
    // This addresses the uncovered branch at line 73 in the fuzz target coverage report.
    strcpy(temp_filename, "/tmp/fuzz_tinyxml2_XXXXXX");
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

    // Added to cover tinyxml2::XMLDocument::NewComment, NewDeclaration, NewUnknown
    // and their corresponding XMLPrinter::Visit methods.
    tinyxml2::XMLComment* comment = doc->NewComment(commentValue.c_str());
    if (comment) {
        doc->InsertEndChild(comment);
    }
    tinyxml2::XMLDeclaration* declaration = doc->NewDeclaration(declarationValue.c_str());
    if (declaration) {
        doc->InsertEndChild(declaration);
    }
    tinyxml2::XMLUnknown* unknown = doc->NewUnknown(unknownValue.c_str());
    if (unknown) {
        doc->InsertEndChild(unknown);
    }

    doc->Print(&printer); // This will trigger calls to VisitEnter for elements and attributes,
                          // and Visit for comment, declaration, unknown nodes.
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

      // Added to cover other Query...Attribute overloads for XMLElement
      int intResult;
      queryElement->SetAttribute("int_val", fdp.ConsumeIntegral<int>());
      queryElement->QueryIntAttribute("int_val", &intResult);
      unsigned int uintResult;
      queryElement->SetAttribute("uint_val", fdp.ConsumeIntegral<unsigned int>());
      queryElement->QueryUnsignedAttribute("uint_val", &uintResult);
      long longResult;
      queryElement->SetAttribute("long_val", fdp.ConsumeIntegral<long>());
      queryElement->QueryInt64Attribute("long_val", &longResult);
      unsigned long ulongResult;
      queryElement->SetAttribute("ulong_val", fdp.ConsumeIntegral<unsigned long>());
      queryElement->QueryUnsigned64Attribute("ulong_val", &ulongResult);
      double doubleResult;
      queryElement->SetAttribute("double_val", fdp.ConsumeFloatingPoint<double>());
      queryElement->QueryDoubleAttribute("double_val", &doubleResult);
      float floatResult;
      queryElement->SetAttribute("float_val", fdp.ConsumeFloatingPoint<float>());
      queryElement->QueryFloatAttribute("float_val", &floatResult);

      // Added to cover Query...Value overloads for XMLAttribute
      // Fix: Changed type to const tinyxml2::XMLAttribute* to match return type of FirstAttribute()
      const tinyxml2::XMLAttribute* attr = queryElement->FirstAttribute();
      if (attr) {
          attr->QueryIntValue(&intResult);
          attr->QueryUnsignedValue(&uintResult);
          attr->QueryInt64Value(&longResult);
          attr->QueryUnsigned64Value(&ulongResult);
          attr->QueryBoolValue(&result);
          attr->QueryDoubleValue(&doubleResult);
          attr->QueryFloatValue(&floatResult);
      }

      // Added to cover XMLElement::GetText() and SetText overloads
      queryElement->SetText(textValue.c_str());
      const char* retrievedText = queryElement->GetText();
      queryElement->SetText(fdp.ConsumeIntegral<int>());
      queryElement->SetText(fdp.ConsumeIntegral<unsigned int>());
      queryElement->SetText(fdp.ConsumeIntegral<long>());
      queryElement->SetText(fdp.ConsumeIntegral<unsigned long>());
      queryElement->SetText(fdp.ConsumeBool());
      queryElement->SetText(fdp.ConsumeFloatingPoint<float>());
      queryElement->SetText(fdp.ConsumeFloatingPoint<double>());
    }
  }

  // 6. Added to cover tinyxml2::XMLNode::InsertAfterChild(tinyxml2::XMLNode*, tinyxml2::XMLNode*)
  {
    tinyxml2::XMLElement* firstElement = doc->NewElement("First");
    tinyxml2::XMLElement* middleElement = doc->NewElement("Middle");
    tinyxml2::XMLElement* lastElement = doc->NewElement("Last");

    if (firstElement && middleElement && lastElement) {
      doc->InsertEndChild(firstElement);
      doc->InsertEndChild(lastElement); // Insert 'last' after 'first'

      // Now insert 'middle' after 'first'
      doc->InsertAfterChild(firstElement, middleElement);
    }
  }

  // The unique_ptr 'doc' will automatically delete the XMLDocument and all its owned nodes
  // when it goes out of scope, ensuring memory safety and preventing leaks.

  return 0;
}