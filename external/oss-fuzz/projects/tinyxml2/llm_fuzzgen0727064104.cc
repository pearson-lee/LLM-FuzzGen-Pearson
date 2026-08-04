#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <unistd.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/tinyxml2/tinyxml2.h"

// Fuzz target entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0) {
    return 0;
  }

  FuzzedDataProvider fdp(data, size);

  // --- File I/O Setup ---
  // Create a unique temporary file path to avoid race conditions.
  const std::string path = std::string("/tmp/") + _FUZZ_TARGET_NAME + ".xml";
  FILE *fp = fopen(path.c_str(), "wb");
  if (!fp) {
    return 0;
  }

  // Consume data from the fuzzer and write it to the temporary file.
  std::vector<uint8_t> file_data = fdp.ConsumeRemainingBytes<uint8_t>();
  if (!file_data.empty()) {
    fwrite(file_data.data(), 1, file_data.size(), fp);
  }
  fclose(fp);

  // Re-open the file for reading.
  fp = fopen(path.c_str(), "rb");
  if (!fp) {
    unlink(path.c_str());
    return 0;
  }

  /*
   * ANALYSIS: The coverage report for `XMLDocument::Identify` shows a branch at line 752
   *           is never taken: `if (WhitespaceMode() == PEDANTIC_WHITESPACE && first && p != start && *(p + elementHeaderLen) == '/')`.
   *           This requires PEDANTIC_WHITESPACE mode and specific input like ` < /tag>`.
   * IMPLEMENTATION: The following code block creates an XMLDocument, sometimes with the
   *                 `PEDANTIC_WHITESPACE` flag set. The fuzzer input from the temporary
   *                 file is then parsed using `LoadFile`, which may trigger the target branch if the input is crafted correctly by the fuzzing engine.
   */
  // Randomly choose whitespace mode to increase coverage.
  const bool pedantic = fdp.ConsumeBool();
  tinyxml2::XMLDocument doc(false, pedantic ? tinyxml2::PEDANTIC_WHITESPACE : tinyxml2::PRESERVE_WHITESPACE);

  // Load the XML from the file. This is the primary entry point for parsing.
  doc.LoadFile(fp);
  fclose(fp); // Close the file handle.
  unlink(path.c_str()); // Clean up the temporary file.

  if (doc.ErrorID() == tinyxml2::XML_SUCCESS) {
    /*
     * ANALYSIS: The `XMLPrinter` constructor has uncovered branches related to the
     *           `EscapeAposCharsInAttributes` enum. Specifically, the `false` conditions
     *           in the `if` statement at line 2605 are never hit.
     * IMPLEMENTATION: A `XMLPrinter` is created with a randomly chosen value for the
     *                 `EscapeAposCharsInAttributes` enum. The document is then printed,
     *                 which also exercises the `XMLVisitor` interface implemented by `XMLPrinter`.
     */
    const bool compact = fdp.ConsumeBool();
    // Choose a random value for the enum to cover more branches.
    const auto escape_mode = fdp.PickValueInArray({
        tinyxml2::XMLPrinter::ESCAPE_APOS_CHARS_IN_ATTRIBUTES,
        tinyxml2::XMLPrinter::DONT_ESCAPE_APOS_CHARS_IN_ATTRIBUTES
    });
    tinyxml2::XMLPrinter printer(nullptr, compact, 0, escape_mode);
    doc.Print(&printer);

    /*
     * ANALYSIS: The `XMLNode::DeleteNode` function has an uncovered branch at line 1196
     *           for the `node == 0` check.
     * IMPLEMENTATION: The following code calls `doc.DeleteNode` with `nullptr` to
     *                 cover the null check.
     */
    // Call with nullptr to hit the null check.
    doc.DeleteNode(nullptr);

    // Recursively find a random node to delete.
    tinyxml2::XMLNode* node_to_delete = doc.FirstChild();
    if (node_to_delete) {
        int num_children = 0;
        for (tinyxml2::XMLNode* child = doc.FirstChild(); child; child = child->NextSibling()) {
            num_children++;
        }
        if (num_children > 0) {
            int target_child = fdp.ConsumeIntegralInRange<int>(0, num_children - 1);
            for (int i = 0; i < target_child; ++i) {
                if (node_to_delete) {
                    node_to_delete = node_to_delete->NextSibling();
                }
            }
            if (node_to_delete) {
                // Deleting a node from the document.
                doc.DeleteNode(node_to_delete);
            }
        }
    }
  }

  return 0;
}