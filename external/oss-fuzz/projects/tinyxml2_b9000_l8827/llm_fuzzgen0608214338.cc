#include "/src/tinyxml2/tinyxml2.h" // Required for tinyxml2 library
#include <fuzzer/FuzzedDataProvider.h> // Required for FuzzedDataProvider
#include <string>      // Required for std::string
#include <cstdio>      // Required for remove()
#include <cstddef>     // Required for size_t
#include <cstdint>     // Required for uint8_t, int types

// Define a maximum length for strings consumed from FuzzedDataProvider
// to prevent excessively large allocations or performance issues.
const size_t kMaxStringLength = 256;

// Target APIs from the 0% coverage list (and one complementary):
// 1. tinyxml2::XMLElement::InsertNewChildElement(const char *)
// 2. void tinyxml2::XMLElement::SetText(int)
// 3. void tinyxml2::XMLElement::SetText(bool) (also 0% coverage, complements SetText(int))
// 4. DW_TAG_enumeration_typeXMLError tinyxml2::XMLElement::QueryIntAttribute(const char *, int *)
// 5. void tinyxml2::XMLElement::DeleteAttribute(const char *)
// 6. DW_TAG_enumeration_typeXMLError tinyxml2::XMLDocument::SaveFile(const char *, bool)

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // Create an XMLDocument. It manages the memory of all its nodes and attributes.
    // When 'doc' goes out of scope at the end of this function, its destructor
    // will be called, automatically deallocating all XML nodes and attributes it owns.
    // This RAII pattern is crucial for preventing memory leaks with tinyxml2.
    tinyxml2::XMLDocument doc;

    // Create a root element. Its memory is managed by 'doc'.
    std::string rootElementName = fdp.ConsumeRandomLengthString(kMaxStringLength);
    if (rootElementName.empty()) { // Ensure element names are not empty for robustness
        rootElementName = "defaultRoot";
    }
    tinyxml2::XMLElement* root = doc.NewElement(rootElementName.c_str());
    if (!root) {
        // If NewElement fails (e.g., due to internal memory allocation issues),
        // there's nothing further to test.
        return 0;
    }
    doc.InsertFirstChild(root); // Add the root element to the document.

    tinyxml2::XMLElement* currentElement = root;

    // Perform a variable number of operations to build a more complex XML structure
    // and exercise APIs in different states.
    int num_operations = fdp.ConsumeIntegralInRange<int>(1, 10); 

    for (int i = 0; i < num_operations; ++i) {
        if (!currentElement) { // Safety check: if currentElement somehow became null, reset to root.
            currentElement = root; // Attempt to recover by resetting to the root element.
            if (!currentElement) return 0; // Should not happen if root creation was successful.
        }

        // Randomly choose an API to call or an action to perform.
        // This helps in exploring different sequences and combinations of API calls.
        uint8_t choice = fdp.ConsumeIntegralInRange<uint8_t>(0, 5); 

        switch (choice) {
            case 0: {
                // Target API: tinyxml2::XMLElement::InsertNewChildElement(const char *)
                // This function creates a new XML element as a child of currentElement.
                // The memory for the new child is managed by the XMLDocument via its parent.
                std::string childName = fdp.ConsumeRandomLengthString(kMaxStringLength);
                if (childName.empty()) {
                    childName = "defaultChild";
                }
                tinyxml2::XMLElement* newChild = currentElement->InsertNewChildElement(childName.c_str());
                
                if (newChild && fdp.ConsumeBool()) {
                    // Optionally change the context to the newly created child element
                    // for subsequent operations, allowing for nested structures.
                    currentElement = newChild;
                }
                break;
            }
            case 1: {
                // Target API: void tinyxml2::XMLElement::SetText(int)
                // Sets the text content of the currentElement using an integer.
                // TinyXML2 will convert the integer to its string representation.
                currentElement->SetText(fdp.ConsumeIntegral<int>());
                break;
            }
            case 2: {
                // Target API (complementary): void tinyxml2::XMLElement::SetText(bool)
                // Sets the text content of the currentElement using a boolean.
                // TinyXML2 will convert the boolean to "true" or "false" (or custom representations).
                currentElement->SetText(fdp.ConsumeBool());
                break;
            }
            case 3: {
                // Target API: DW_TAG_enumeration_typeXMLError tinyxml2::XMLElement::QueryIntAttribute(const char *, int *)
                // Attempts to retrieve an integer attribute from currentElement.
                std::string attrName = fdp.ConsumeRandomLengthString(kMaxStringLength);
                if (attrName.empty()) {
                    attrName = "defaultAttr";
                }
                int val = 0; // Initialize to a default value.

                // To make QueryIntAttribute more effective, sometimes set the attribute first.
                // This tests both successful queries and queries for non-existent or wrongly-typed attributes.
                if (fdp.ConsumeBool()) {
                    currentElement->SetAttribute(attrName.c_str(), fdp.ConsumeIntegral<int>());
                }
                currentElement->QueryIntAttribute(attrName.c_str(), &val);
                // The return value (XMLError) could be checked for specific error conditions,
                // but for fuzzing, exercising the code path is the primary goal.
                break;
            }
            case 4: {
                // Target API: void tinyxml2::XMLElement::DeleteAttribute(const char *)
                // Deletes an attribute from currentElement by its name.
                std::string attrNameToDelete = fdp.ConsumeRandomLengthString(kMaxStringLength);
                if (attrNameToDelete.empty()) {
                    attrNameToDelete = "attrToDelete";
                }

                // To make DeleteAttribute more effective, sometimes set the attribute first.
                // This tests both successful deletions and attempts to delete non-existent attributes.
                if (fdp.ConsumeBool()) {
                    // The actual value or type of the attribute doesn't matter for deletion by name.
                    currentElement->SetAttribute(attrNameToDelete.c_str(), "someValue");
                }
                currentElement->DeleteAttribute(attrNameToDelete.c_str());
                break;
            }
            case 5: {
                // Navigate up to the parent element if not already at the root.
                // This allows the fuzzer to modify different parts of the XML tree,
                // rather than only appending deeper and deeper.
                if (currentElement != root && currentElement->Parent()) {
                    tinyxml2::XMLElement* parentElement = currentElement->Parent()->ToElement();
                    if (parentElement) { // Ensure parent is indeed an XMLElement
                        currentElement = parentElement;
                    }
                }
                break;
            }
        }
    }

    // Target API: DW_TAG_enumeration_typeXMLError tinyxml2::XMLDocument::SaveFile(const char *, bool)
    // Saves the entire XML document (potentially modified by the operations above) to a file.
    // This involves file system interaction. A temporary, fixed-name file is used.
    const char* tempFilename = "fuzz_output.xml"; 
    bool compactMode = fdp.ConsumeBool(); // Test both compact and expanded XML output formats.
    doc.SaveFile(tempFilename, compactMode);

    // Attempt to clean up the temporary file created by SaveFile.
    // This is best-effort cleanup. In many fuzzing environments, the OS or 
    // fuzzing harness handles cleanup of temporary files created in scratch directories.
    remove(tempFilename);

    // The XMLDocument 'doc' and all its created nodes (elements, text, attributes)
    // will be automatically deallocated when 'doc' goes out of scope here.
    // This is handled by tinyxml2's internal memory management and RAII design,
    // ensuring no memory leaks from the XML data structures.
    return 0;
}