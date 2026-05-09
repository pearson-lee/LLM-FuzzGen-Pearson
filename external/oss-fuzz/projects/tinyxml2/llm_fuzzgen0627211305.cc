#include "/src/tinyxml2/tinyxml2.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>
#include <cstdio> // For fmemopen, fclose
#include <cstdarg> // For va_list, va_start, va_end (used internally by XMLPrinter::Print)

// Custom XMLVisitor to get coverage on virtual visit methods.
// These methods are called during XML document traversal.
class FuzzVisitor : public tinyxml2::XMLVisitor {
public:
    // VisitEnter and VisitExit for XMLDocument
    bool VisitEnter(const tinyxml2::XMLDocument& /*doc*/) override { return true; }
    bool VisitExit(const tinyxml2::XMLDocument& /*doc*/) override { return true; }

    // VisitEnter and VisitExit for XMLElement
    bool VisitEnter(const tinyxml2::XMLElement& /*element*/, const tinyxml2::XMLAttribute* /*firstAttribute*/) override { return true; }
    bool VisitExit(const tinyxml2::XMLElement& /*element*/) override { return true; }

    // Visit methods for various XML node types
    bool Visit(const tinyxml2::XMLDeclaration& /*declaration*/) override { return true; }
    bool Visit(const tinyxml2::XMLText& /*text*/) override { return true; }
    bool Visit(const tinyxml2::XMLComment& /*comment*/) override { return true; }
    bool Visit(const tinyxml2::XMLUnknown& /*unknown*/) override { return true; }
};

// Custom XMLPrinter to expose the protected Print method for fuzzing.
class FuzzPrinter : public tinyxml2::XMLPrinter {
public:
    // Inherit constructors
    using tinyxml2::XMLPrinter::XMLPrinter;

    // Expose the protected Print method
    using tinyxml2::XMLPrinter::Print;
};


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // Part 1: Fuzzing tinyxml2::XMLPrinter::Print and its internal helper TIXML_VSCPRINTF.
    // XMLPrinter::Print is a variadic function. We'll exercise it in two ways:
    // 1. With a FILE* to hit the vfprintf path.
    // 2. Without a FILE* (nullptr) to hit the TIXML_VSCPRINTF path.

    // Instance 1: XMLPrinter with a memory-backed FILE*
    // This buffer will capture output from the printer.
    char print_buffer_file[1024];
    // fmemopen creates a FILE* stream that writes to our buffer.
    FILE* temp_file = fmemopen(print_buffer_file, sizeof(print_buffer_file), "w");
    if (!temp_file) {
        // In a fuzzer, this indicates a critical issue or resource exhaustion.
        return 0;
    }

    // Construct FuzzPrinter with the file, random compact mode, and depth.
    FuzzPrinter printer_file(temp_file, fdp.ConsumeBool(), fdp.ConsumeIntegralInRange<int>(0, 10));

    // Choose a print scenario for printer_file to ensure type-safe variadic arguments.
    int scenario_file = fdp.ConsumeIntegralInRange<int>(0, 3);
    if (scenario_file == 0) {
        printer_file.Print("No arguments here.");
    } else if (scenario_file == 1) {
        std::string s_arg = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 50));
        printer_file.Print("String arg: %s", s_arg.c_str());
    } else if (scenario_file == 2) {
        int d_arg = fdp.ConsumeIntegral<int>();
        printer_file.Print("Int arg: %d", d_arg);
    } else { // scenario_file == 3
        std::string s_arg = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 50));
        int d_arg = fdp.ConsumeIntegral<int>();
        printer_file.Print("String: %s, Int: %d", s_arg.c_str(), d_arg);
    }

    // Close the fmemopen file stream. This flushes the buffer and cleans up resources.
    fclose(temp_file);

    // Instance 2: XMLPrinter without a FILE* (nullptr)
    // This forces XMLPrinter::Print to use its internal buffer and call TIXML_VSCPRINTF.
    FuzzPrinter printer_no_file(nullptr, fdp.ConsumeBool(), fdp.ConsumeIntegralInRange<int>(0, 10));

    // Choose a print scenario for printer_no_file to ensure type-safe variadic arguments.
    int scenario_no_file = fdp.ConsumeIntegralInRange<int>(0, 3);
    if (scenario_no_file == 0) {
        printer_no_file.Print("No arguments here (no file).");
    } else if (scenario_no_file == 1) {
        std::string s_arg = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 50));
        printer_no_file.Print("String arg (no file): %s", s_arg.c_str());
    } else if (scenario_no_file == 2) {
        int d_arg = fdp.ConsumeIntegral<int>();
        printer_no_file.Print("Int arg (no file): %d", d_arg);
    } else { // scenario_no_file == 3
        std::string s_arg = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 50));
        int d_arg = fdp.ConsumeIntegral<int>();
        printer_no_file.Print("String (no file): %s, Int (no file): %d", s_arg.c_str(), d_arg);
    }
    // The internal buffer of 'printer_no_file' is automatically managed and freed
    // when 'printer_no_file' goes out of scope (RAII).

    // Part 2: Fuzzing XMLVisitor methods by traversing a fuzzed XML document.
    // This aims to hit all the Visit and VisitEnter/VisitExit methods of the XMLVisitor interface.
    tinyxml2::XMLDocument doc; // XMLDocument uses RAII for its internal memory pools.

    // Consume the remaining fuzzed data as an XML string.
    std::string xml_input = fdp.ConsumeRemainingBytesAsString();

    // Parse the fuzzed XML string. This can trigger various parsing logic and error paths.
    doc.Parse(xml_input.c_str());

    // Create an instance of our custom FuzzVisitor.
    FuzzVisitor visitor;

    // Accept the visitor to traverse the document. This call will dispatch to the
    // appropriate Visit methods in our FuzzVisitor based on the document's structure.
    doc.Accept(&visitor);

    // All objects (doc, printer_file, printer_no_file, visitor) are stack-allocated
    // or use RAII, ensuring proper memory management and preventing leaks.

    return 0;
}