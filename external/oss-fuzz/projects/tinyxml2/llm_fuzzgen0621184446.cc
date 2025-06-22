#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <memory> // For std::unique_ptr
#include <functional> // Required for std::function
#include <fuzzer/FuzzedDataProvider.h>

// Always emit #include with the full project-relative path in quotes.
#include "/src/tinyxml2/tinyxml2.h"

// Define a helper to manage XMLDocument lifetime using RAII
struct XMLDocumentDeleter {
    void operator()(tinyxml2::XMLDocument* doc) const {
        if (doc) {
            doc->Clear(); // Clear any allocated memory within the document
            delete doc;
        }
    }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // Use std::unique_ptr for automatic memory management of XMLDocument
    std::unique_ptr<tinyxml2::XMLDocument, XMLDocumentDeleter> doc_ptr(new tinyxml2::XMLDocument());
    tinyxml2::XMLDocument* doc = doc_ptr.get();

    // Fuzzing tinyxml2::XMLElement::FloatAttribute(const char *, float)
    {
        std::string element_name = fdp.ConsumeRandomLengthString(32);
        // The XMLElement is owned by the XMLDocument, so no deletion is needed.
        // The custom deleter is a no-op lambda.
        std::unique_ptr<tinyxml2::XMLElement, std::function<void(tinyxml2::XMLElement*)>> element_ptr(
            doc->NewElement(element_name.c_str()),
            [](tinyxml2::XMLElement*){ /* Owned by doc, no delete needed */ }
        );
        tinyxml2::XMLElement* element = element_ptr.get();
        if (element) {
            doc->InsertFirstChild(element); // Add to document to ensure proper context

            std::string attribute_name = fdp.ConsumeRandomLengthString(32);
            float default_float_value = fdp.ConsumeFloatingPoint<float>();

            // Case 1: Attribute does not exist (to hit XML_NO_ATTRIBUTE branch in QueryFloatAttribute)
            element->FloatAttribute(attribute_name.c_str(), default_float_value);

            // Case 2: Attribute exists with a valid float value
            if (fdp.ConsumeBool()) {
                std::string valid_float_str = std::to_string(fdp.ConsumeFloatingPoint<float>());
                element->SetAttribute(attribute_name.c_str(), valid_float_str.c_str());
                element->FloatAttribute(attribute_name.c_str(), default_float_value);
            }

            // Case 3: Attribute exists with a non-float value (to hit XML_CAN_NOT_CONVERT_TEXT branch)
            if (fdp.ConsumeBool()) {
                std::string non_float_str = fdp.ConsumeRandomLengthString(32);
                element->SetAttribute(attribute_name.c_str(), non_float_str.c_str());
                element->FloatAttribute(attribute_name.c_str(), default_float_value);
            }
        }
    }

    // Fuzzing tinyxml2::XMLElement::FloatText(float)
    {
        std::string element_name = fdp.ConsumeRandomLengthString(32);
        // The XMLElement is owned by the XMLDocument, so no deletion is needed.
        // The custom deleter is a no-op lambda.
        std::unique_ptr<tinyxml2::XMLElement, std::function<void(tinyxml2::XMLElement*)>> element_ptr(
            doc->NewElement(element_name.c_str()),
            [](tinyxml2::XMLElement*){ /* Owned by doc, no delete needed */ }
        );
        tinyxml2::XMLElement* element = element_ptr.get();
        if (element) {
            doc->InsertEndChild(element); // Add to document

            float default_float_value = fdp.ConsumeFloatingPoint<float>();

            // Case 1: Element with no text node (to hit XML_NO_TEXT_NODE branch)
            element->FloatText(default_float_value);

            // Case 2: Element with text that is not a valid float (to hit XML_CAN_NOT_CONVERT_TEXT branch)
            if (fdp.ConsumeBool()) {
                std::string non_float_text = fdp.ConsumeRandomLengthString(32);
                element->SetText(non_float_text.c_str());
                element->FloatText(default_float_value);
            }

            // Case 3: Element with valid float text
            if (fdp.ConsumeBool()) {
                std::string valid_float_text = std::to_string(fdp.ConsumeFloatingPoint<float>());
                element->SetText(valid_float_text.c_str());
                element->FloatText(default_float_value);
            }
        }
    }

    // Fuzzing tinyxml2::XMLElement::ShallowEqual(const XMLNode *)
    {
        std::string name1 = fdp.ConsumeRandomLengthString(32);
        std::string name2 = fdp.ConsumeRandomLengthString(32);

        // The XMLElement is owned by the XMLDocument, so no deletion is needed.
        // The custom deleter is a no-op lambda.
        std::unique_ptr<tinyxml2::XMLElement, std::function<void(tinyxml2::XMLElement*)>> elem1_ptr(
            doc->NewElement(name1.c_str()),
            [](tinyxml2::XMLElement*){ /* Owned by doc */ }
        );
        tinyxml2::XMLElement* elem1 = elem1_ptr.get();

        // The XMLElement is owned by the XMLDocument, so no deletion is needed.
        // The custom deleter is a no-op lambda.
        std::unique_ptr<tinyxml2::XMLElement, std::function<void(tinyxml2::XMLElement*)>> elem2_ptr(
            doc->NewElement(name2.c_str()),
            [](tinyxml2::XMLElement*){ /* Owned by doc */ }
        );
        tinyxml2::XMLElement* elem2 = elem2_ptr.get();

        if (elem1 && elem2) {
            // Test with different names
            elem1->ShallowEqual(elem2);

            // Make names equal
            elem2->SetName(name1.c_str());
            elem1->ShallowEqual(elem2);

            // Add attributes to elem1
            int num_attributes1 = fdp.ConsumeIntegralInRange<int>(0, 5);
            for (int i = 0; i < num_attributes1; ++i) {
                elem1->SetAttribute(fdp.ConsumeRandomLengthString(16).c_str(), fdp.ConsumeRandomLengthString(16).c_str());
            }

            // Add attributes to elem2
            int num_attributes2 = fdp.ConsumeIntegralInRange<int>(0, 5);
            for (int i = 0; i < num_attributes2; ++i) {
                elem2->SetAttribute(fdp.ConsumeRandomLengthString(16).c_str(), fdp.ConsumeRandomLengthString(16).c_str());
            }

            // Test with different attribute counts (if num_attributes1 != num_attributes2)
            elem1->ShallowEqual(elem2);

            // Try to make attribute counts equal and fuzz values
            if (num_attributes1 > 0 && num_attributes2 > 0) {
                // Clear existing attributes and set new ones to ensure matching counts for value fuzzing
                // Iterate and delete all attributes using the public DeleteAttribute(const char* name) method
                while (const tinyxml2::XMLAttribute* attr = elem1->FirstAttribute()) {
                    elem1->DeleteAttribute(attr->Name());
                }
                while (const tinyxml2::XMLAttribute* attr = elem2->FirstAttribute()) {
                    elem2->DeleteAttribute(attr->Name());
                }

                std::string attr_name = fdp.ConsumeRandomLengthString(16);
                std::string attr_val1 = fdp.ConsumeRandomLengthString(16);
                std::string attr_val2 = fdp.ConsumeRandomLengthString(16);

                elem1->SetAttribute(attr_name.c_str(), attr_val1.c_str());
                elem2->SetAttribute(attr_name.c_str(), attr_val2.c_str());

                // Test with same attribute count, same name, different values
                elem1->ShallowEqual(elem2);

                // Test with same attribute count, same name, same values
                elem2->SetAttribute(attr_name.c_str(), attr_val1.c_str());
                elem1->ShallowEqual(elem2);
            }
        }
    }

    // Fuzzing tinyxml2::XMLNode::PreviousSiblingElement(const char *)
    {
        std::string root_name = fdp.ConsumeRandomLengthString(32);
        // The XMLElement is owned by the XMLDocument, so no deletion is needed.
        // The custom deleter is a no-op lambda.
        std::unique_ptr<tinyxml2::XMLElement, std::function<void(tinyxml2::XMLElement*)>> root_ptr(
            doc->NewElement(root_name.c_str()),
            [](tinyxml2::XMLElement*){ /* Owned by doc */ }
        );
        tinyxml2::XMLElement* root = root_ptr.get();
        if (root) {
            doc->InsertEndChild(root);

            int num_siblings = fdp.ConsumeIntegralInRange<int>(0, 10);
            std::vector<tinyxml2::XMLElement*> siblings;
            for (int i = 0; i < num_siblings; ++i) {
                std::string sibling_name = fdp.ConsumeRandomLengthString(32);
                tinyxml2::XMLElement* sibling = doc->NewElement(sibling_name.c_str());
                if (sibling) {
                    root->InsertEndChild(sibling);
                    siblings.push_back(sibling);
                }
            }

            if (!siblings.empty()) {
                tinyxml2::XMLElement* target_sibling = siblings[fdp.ConsumeIntegralInRange<size_t>(0, siblings.size() - 1)];

                // Case 1: Search for an existing sibling by name
                if (fdp.ConsumeBool()) {
                    target_sibling->PreviousSiblingElement(target_sibling->Name());
                }

                // Case 2: Search for a non-existent sibling name
                if (fdp.ConsumeBool()) {
                    std::string non_existent_name = fdp.ConsumeRandomLengthString(32);
                    target_sibling->PreviousSiblingElement(non_existent_name.c_str());
                }

                // Case 3: Search with null name (should return the first previous sibling element)
                if (fdp.ConsumeBool()) {
                    target_sibling->PreviousSiblingElement(nullptr);
                }
            }
        }
    }

    // Fuzzing tinyxml2::XMLNode::LastChildElement(const char *)
    {
        std::string root_name = fdp.ConsumeRandomLengthString(32);
        // The XMLElement is owned by the XMLDocument, so no deletion is needed.
        // The custom deleter is a no-op lambda.
        std::unique_ptr<tinyxml2::XMLElement, std::function<void(tinyxml2::XMLElement*)>> root_ptr(
            doc->NewElement(root_name.c_str()),
            [](tinyxml2::XMLElement*){ /* Owned by doc */ }
        );
        tinyxml2::XMLElement* root = root_ptr.get();
        if (root) {
            doc->InsertEndChild(root);

            int num_children = fdp.ConsumeIntegralInRange<int>(0, 10);
            std::vector<tinyxml2::XMLElement*> children;
            for (int i = 0; i < num_children; ++i) {
                std::string child_name = fdp.ConsumeRandomLengthString(32);
                tinyxml2::XMLElement* child = doc->NewElement(child_name.c_str());
                if (child) {
                    root->InsertEndChild(child);
                    children.push_back(child);
                }
            }

            // Case 1: Search for an existing child by name
            if (!children.empty() && fdp.ConsumeBool()) {
                tinyxml2::XMLElement* target_child = children[fdp.ConsumeIntegralInRange<size_t>(0, children.size() - 1)];
                root->LastChildElement(target_child->Name());
            }

            // Case 2: Search for a non-existent child name
            if (fdp.ConsumeBool()) {
                std::string non_existent_name = fdp.ConsumeRandomLengthString(32);
                root->LastChildElement(non_existent_name.c_str());
            }

            // Case 3: Search with null name (should return the last child element)
            if (fdp.ConsumeBool()) {
                root->LastChildElement(nullptr);
            }
        }
    }

    return 0;
}