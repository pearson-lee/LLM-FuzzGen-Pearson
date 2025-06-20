#include "/src/tinyxml2/tinyxml2.h" // Using project-relative path for tinyxml2 header

#include <cstddef> // For size_t
#include <cstdint> // For uint8_t
#include <string>  // For std::string
// No <vector> needed for this specific fuzzer

// FuzzedDataProvider for consuming fuzzer input
#include <fuzzer/FuzzedDataProvider.h>

// Using namespace for TinyXML2 for brevity in the fuzzer logic
using namespace tinyxml2;

// Target 5 APIs with 0% coverage, focusing on diversity.
// Selected APIs:
// 1. tinyxml2::XMLElement::InsertNewComment(const char *comment)
// 2. tinyxml2::XMLElement::SetText(unsigned int value)
// 3. tinyxml2::XMLElement::QueryDoubleAttribute(const char *name, double *value)
// 4. const XMLElement * tinyxml2::XMLNode::NextSiblingElement(const char *name)
// 5. bool tinyxml2::XMLUtil::ToBool(const char *str, bool *outBool)

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // XMLDocument is the main container. It handles memory for all its nodes.
    // When 'doc' goes out of scope, all associated XML nodes are automatically deleted,
    // preventing memory leaks. This is a key RAII pattern in TinyXML2.
    XMLDocument doc;

    // Create a root element. Most operations require an existing element.
    // Consume a string for the root element's name. Max length 32.
    std::string rootNameStr = fdp.ConsumeRandomLengthString(32);
    // doc.NewElement() allocates an XMLElement.
    XMLElement* rootElement = doc.NewElement(rootNameStr.c_str());
    
    if (!rootElement) {
        // If rootElement couldn't be created (e.g., out of memory, though NewElement is robust),
        // we can't proceed with operations that depend on it.
        return 0; 
    }
    // Insert the rootElement into the document. Now 'doc' owns 'rootElement'
    // and will manage its memory.
    doc.InsertFirstChild(rootElement);

    // API 1: tinyxml2::XMLElement::InsertNewComment(const char *comment)
    // This function creates a new XMLComment node and inserts it as a child of 'rootElement'.
    // The memory for the new comment node is managed by its parent ('rootElement'),
    // and ultimately by 'doc'.
    std::string commentText = fdp.ConsumeRandomLengthString(128); // Max length 128 for comment.
    // The returned XMLComment* is managed by the document; no manual deletion needed.
    // We cast to void to indicate the return value is intentionally not used.
    (void)rootElement->InsertNewComment(commentText.c_str());

    // API 2: tinyxml2::XMLElement::SetText(unsigned int value)
    // This function sets the text content of an element using an unsigned integer.
    // It may create or replace an XMLText node child within the element.
    // Create a new child element to test this specific API.
    std::string childNameForSetText = fdp.ConsumeRandomLengthString(32);
    XMLElement* setTextElement = doc.NewElement(childNameForSetText.c_str());
    if (setTextElement) {
        rootElement->InsertEndChild(setTextElement); // 'setTextElement' is now owned by 'rootElement'.
        unsigned int uintVal = fdp.ConsumeIntegral<unsigned int>();
        setTextElement->SetText(uintVal);
        // Any internal XMLText node created by SetText is managed by 'setTextElement'.
    }

    // API 3: tinyxml2::XMLElement::QueryDoubleAttribute(const char *name, double *value)
    // This function queries an attribute of an element and attempts to parse its value as a double.
    // Create another child element for this test.
    std::string childNameForQueryAttr = fdp.ConsumeRandomLengthString(32);
    XMLElement* queryAttrElement = doc.NewElement(childNameForQueryAttr.c_str());
    if (queryAttrElement) {
        rootElement->InsertEndChild(queryAttrElement); // 'queryAttrElement' is owned by 'rootElement'.

        std::string attrName = fdp.ConsumeRandomLengthString(32); // Attribute name.
        
        // Optionally set the attribute first to test a successful query scenario.
        // XMLElement::SetAttribute has an overload for double.
        if (fdp.ConsumeBool()) {
            double doubleAttrVal = fdp.ConsumeFloatingPoint<double>();
            queryAttrElement->SetAttribute(attrName.c_str(), doubleAttrVal);
        }

        double queryDoubleResult = 0.0;
        // Query the attribute. It may or may not exist, or may not be a valid double.
        // The return value 'error' can be checked (e.g., XML_SUCCESS, XML_NO_ATTRIBUTE, XML_WRONG_ATTRIBUTE_TYPE).
        // Cast to void as we are not checking the error code in this fuzzer.
        (void)queryAttrElement->QueryDoubleAttribute(attrName.c_str(), &queryDoubleResult);
    }

    // API 4: const XMLElement * tinyxml2::XMLNode::NextSiblingElement(const char *name)
    // This function finds the next sibling element, optionally matching a specific name.
    // 'setTextElement' and 'queryAttrElement', if created, are siblings under 'rootElement'.
    if (setTextElement) { // Check if the first potential sibling exists.
        // Call NextSiblingElement() to get the immediate next sibling element, regardless of its name.
        // Cast to void as the returned element is not used further.
        (void)setTextElement->NextSiblingElement();

        // Call NextSiblingElement(const char* name) to find the next sibling with a specific name.
        std::string searchName;
        // Decide whether to search for the actual name of 'queryAttrElement' or a random name.
        if (queryAttrElement && !childNameForQueryAttr.empty() && fdp.ConsumeBool()) {
            searchName = childNameForQueryAttr; // Name of the second element we created.
        } else {
            searchName = fdp.ConsumeRandomLengthString(32); // Search for a potentially non-existent name.
        }
        // If searchName is empty, NextSiblingElement(name) behaves like NextSiblingElement().
        // Cast to void as the returned element is not used further.
        (void)setTextElement->NextSiblingElement(searchName.c_str());
    }


    // API 5: bool tinyxml2::XMLUtil::ToBool(const char *str, bool *outBool)
    // This is a static utility function for converting a string representation to a boolean value.
    // It's useful for parsing boolean values from text, often used internally by attribute/text parsers.
    std::string boolStr = fdp.ConsumeRandomLengthString(10); // e.g., "true", "false", "1", "0", or random junk.
    bool outBoolVal = false; // Variable to store the parsed boolean result.
    // The function returns true on successful parsing, false otherwise.
    // Cast to void as we are not checking the conversion success in this fuzzer.
    (void)XMLUtil::ToBool(boolStr.c_str(), &outBoolVal);

    // All XML nodes (rootElement, setTextElement, queryAttrElement, any inserted comments,
    // and internal text nodes created by SetText) are part of the 'doc' object's hierarchy.
    // The XMLDocument's destructor, called when 'doc' goes out of scope, will traverse
    // this hierarchy and deallocate all associated memory, ensuring no leaks.
    return 0;
}