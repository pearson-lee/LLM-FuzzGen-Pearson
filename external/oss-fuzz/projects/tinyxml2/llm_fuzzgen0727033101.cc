#include <cstddef>
#include <cstdint>
#include <string>
#include <unistd.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/tinyxml2/tinyxml2.h"
#include <cstdio> // For FILE*

// Compile-time macro for unique temporary filenames
#ifndef _FUZZ_TARGET_NAME
#define _FUZZ_TARGET_NAME "fuzz_target"
#endif

/*
 * ANALYSIS: The function-level coverage report showed that the XMLVisitor virtual
 *           methods had 0% coverage.
 * IMPLEMENTATION: The following class implements the XMLVisitor interface. An
 *                 instance of it is later used with doc.Accept() to exercise this
 *                 uncovered API.
 */
class MyVisitor : public tinyxml2::XMLVisitor {
public:
    bool VisitEnter(const tinyxml2::XMLElement&, const tinyxml2::XMLAttribute*) override { return true; }
    bool VisitExit(const tinyxml2::XMLElement&) override { return true; }
    bool Visit(const tinyxml2::XMLDeclaration&) override { return true; }
    bool Visit(const tinyxml2::XMLText&) override { return true; }
    bool Visit(const tinyxml2::XMLComment&) override { return true; }
    bool Visit(const tinyxml2::XMLUnknown&) override { return true; }
};

// Helper class to expose the protected Print method for fuzzing
class PublicPrinter : public tinyxml2::XMLPrinter {
public:
    using tinyxml2::XMLPrinter::Print;
};


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Use a unique filename for each fuzzer instance to avoid race conditions
  std::string temp_filename = std::string("/tmp/") + _FUZZ_TARGET_NAME + ".xml";

  tinyxml2::XMLDocument doc;

  // Consume a string from the fuzzer input to use for our operations
  std::string xml_data = fdp.ConsumeRandomLengthString(1024);

  // Load the XML data into the document
  doc.Parse(xml_data.c_str());

  // Create two elements to test ShallowEqual
  tinyxml2::XMLElement *elem1 = doc.NewElement(fdp.ConsumeRandomLengthString(16).c_str());
  tinyxml2::XMLElement *elem2 = doc.NewElement(fdp.ConsumeRandomLengthString(16).c_str());

  // Add attributes to the elements to test the attribute comparison in ShallowEqual
  if (elem1 && fdp.ConsumeBool()) {
    const std::string attr_name = fdp.ConsumeRandomLengthString(16);
    elem1->SetAttribute(attr_name.c_str(), fdp.ConsumeRandomLengthString(16).c_str());

    /*
     * ANALYSIS: The function-level coverage report showed that the various
     *           XMLElement::Query...Attribute functions had 0% coverage.
     * IMPLEMENTATION: The following code calls these functions on an element
     *                 that has had an attribute set on it. This exercises the
     *                 logic for finding and querying attributes.
     */
    int i;
    double d;
    bool b;
    const char* s;
    elem1->QueryIntAttribute(attr_name.c_str(), &i);
    elem1->QueryDoubleAttribute(attr_name.c_str(), &d);
    elem1->QueryBoolAttribute(attr_name.c_str(), &b);
    elem1->QueryStringAttribute(attr_name.c_str(), &s);
  }
  if (elem2 && fdp.ConsumeBool()) {
    elem2->SetAttribute(fdp.ConsumeRandomLengthString(16).c_str(), fdp.ConsumeRandomLengthString(16).c_str());
  }

  /*
   * ANALYSIS: The function-level coverage report showed XMLElement::ShallowEqual had low
   *           branch coverage. The line-level report confirmed this was due to the
   *           attribute comparison loop not being exercised.
   * IMPLEMENTATION: The following code block calls ShallowEqual on two XMLElement objects
   *                 that have had attributes set on them, to exercise the attribute
   *                 comparison logic.
   */
  if (elem1 && elem2) {
    elem1->ShallowEqual(elem2);
  }

  if (elem1) {
    /*
     * ANALYSIS: The function-level coverage report showed XMLElement::GetText had low
     *           coverage because it was never called on an element with a text child.
     * IMPLEMENTATION: The following code calls SetText to create and attach a text
     *                 node, and then calls GetText to exercise the previously
     *                 uncovered code path for retrieving that text.
     */
    if (fdp.ConsumeBool()) {
        elem1->SetText(fdp.ConsumeRandomLengthString(32).c_str());
        elem1->GetText();
    }
    doc.InsertFirstChild(elem1);
  }
  if (elem1 && elem2) {
    elem1->InsertFirstChild(elem2);
  }

  /*
   * ANALYSIS: The function-level coverage report showed XMLNode::InsertAfterChild had
   *           low coverage (60%).
   * IMPLEMENTATION: The following code block creates a third element and inserts it
   *                 after an existing child to exercise the logic in InsertAfterChild.
   *                 The new element is allocated from the document and will be freed
   *                 when the document is destroyed.
   */
  tinyxml2::XMLElement *elem3 = doc.NewElement(fdp.ConsumeRandomLengthString(16).c_str());
  if (elem2 && elem2->Parent() && elem3) {
      elem2->Parent()->InsertAfterChild(elem2, elem3);
  }

  /*
   * ANALYSIS: The function-level coverage report showed that XMLDocument::SaveFile and
   *           XMLDocument::LoadFile had low coverage. The line-level report showed that
   *           the error handling for null filenames and non-existent files was not
   *           being exercised.
   * IMPLEMENTATION: The following code blocks call SaveFile and LoadFile with a null
   *                 filename and a non-existent file path to exercise these error
   *                 handling paths.
   */
  if (fdp.ConsumeBool()) {
    // Exercise the null filename error path
    doc.SaveFile(static_cast<const char*>(nullptr));
  }
  if (fdp.ConsumeBool()) {
    // Exercise the file-not-found error path
    doc.LoadFile("/a/b/c/d/e/f/g/i/j/k.xml");
  }

  // Save the document to a temporary file
  doc.SaveFile(temp_filename.c_str());

  /*
   * ANALYSIS: The function-level coverage report showed XMLDocument::LoadFile(FILE*)
   *           had low coverage, as only the LoadFile(const char*) overload was being called.
   * IMPLEMENTATION: The following code opens the temporary file to get a FILE* handle
   *                 and passes it to the LoadFile(FILE*) overload. This ensures the
   *                 logic for loading from a file stream is exercised. The FILE* is
   *                 safely closed afterward.
   */
  if (fdp.ConsumeBool()) {
    FILE* fp = fopen(temp_filename.c_str(), "r");
    if (fp) {
        doc.LoadFile(fp);
        fclose(fp);
    }
  }

  // Load the document from the temporary file
  doc.LoadFile(temp_filename.c_str());

  /*
   * ANALYSIS: The function-level coverage report showed that XMLDocument::Print had low
   *           coverage. The line-level report showed that the else branch where a
   *           stdoutStreamer is created was never taken.
   * IMPLEMENTATION: The following code block calls Print with a nullptr argument to
   *                 exercise this uncovered code path.
   */
  if (fdp.ConsumeBool()) {
    doc.Print(nullptr);
  }

  // Create a printer and print the document to it
  PublicPrinter printer;
  doc.Print(&printer);

  /*
   * ANALYSIS: The function-level coverage report showed that XMLPrinter::Print(const char*, ...)
   *           and TIXML_VSCPRINTF had 0% coverage.
   * IMPLEMENTATION: The following code block calls Print with a format string and
   *                 fuzzed arguments to exercise the logic within this function, which in turn
   *                 calls TIXML_VSCPRINTF.
   */
  if (fdp.ConsumeBool()) {
    printer.Print("fuzz_int=%d fuzz_str=%s", fdp.ConsumeIntegral<int>(), fdp.ConsumeRandomLengthString(16).c_str());
  }

  if (fdp.ConsumeBool()) {
    printer.PushText(fdp.ConsumeRandomLengthString(16).c_str());
  }

  /*
   * ANALYSIS: The function-level coverage report showed that the XMLVisitor virtual
   *           methods had 0% coverage.
   * IMPLEMENTATION: The following code calls doc.Accept() with the custom visitor to
   *                 exercise the visitor interface and all its virtual methods.
   */
  MyVisitor visitor;
  doc.Accept(&visitor);

  // Clean up the temporary file
  unlink(temp_filename.c_str());

  return 0;
}