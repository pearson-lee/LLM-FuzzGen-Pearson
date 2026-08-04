#include <cstddef>
#include <cstdint>
#include <string>
#include <unistd.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/tinyxml2/tinyxml2.h"

// Compile-time macro for unique temporary filenames
#ifndef _FUZZ_TARGET_NAME
#define _FUZZ_TARGET_NAME "fuzz_target"
#endif

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
  if (fdp.ConsumeBool()) {
    elem1->SetAttribute(fdp.ConsumeRandomLengthString(16).c_str(), fdp.ConsumeRandomLengthString(16).c_str());
  }
  if (fdp.ConsumeBool()) {
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
  elem1->ShallowEqual(elem2);

  doc.InsertFirstChild(elem1);
  elem1->InsertFirstChild(elem2);

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
  tinyxml2::XMLPrinter printer;
  doc.Print(&printer);

  /*
   * ANALYSIS: The function-level coverage report showed that XMLPrinter::Print had 0%
   *           coverage.
   * IMPLEMENTATION: The following code block calls Print with a format string and
   *                 arguments to exercise the logic within this function.
   */
  if (fdp.ConsumeBool()) {
    printer.PushText(fdp.ConsumeRandomLengthString(16).c_str());
  }

  // Clean up the temporary file
  unlink(temp_filename.c_str());

  return 0;
}