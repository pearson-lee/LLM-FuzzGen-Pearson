#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>

#include "/src/tinyxml2/tinyxml2.h"

// Helper function to create a fuzzed XML node
tinyxml2::XMLNode* CreateFuzzedNode(FuzzedDataProvider& fdp, tinyxml2::XMLDocument& doc) {
    enum NodeType {
        ELEMENT,
        TEXT,
        COMMENT,
        DECLARATION,
        UNKNOWN,
        kMaxValue = UNKNOWN // Added kMaxValue for FuzzedDataProvider::ConsumeEnum
    };

    // Consume an enum value to determine the node type
    NodeType node_type = fdp.ConsumeEnum<NodeType>();
    // Consume a string for the node's content or name
    std::string content = fdp.ConsumeRandomLengthString(50);

    // Create the node based on the fuzzed type
    switch (node_type) {
        case ELEMENT:
            // tinyxml2::NewElement returns nullptr if the name is invalid or allocation fails
            return doc.NewElement(content.c_str());
        case TEXT:
            // tinyxml2::NewText returns nullptr if the text is invalid or allocation fails
            return doc.NewText(content.c_str());
        case COMMENT:
            // tinyxml2::NewComment returns nullptr if the comment is invalid or allocation fails
            return doc.NewComment(content.c_str());
        case DECLARATION:
            // tinyxml2::NewDeclaration returns nullptr if the declaration is invalid or allocation fails
            return doc.NewDeclaration(content.c_str());
        case UNKNOWN:
            // tinyxml2::NewUnknown returns nullptr if the unknown is invalid or allocation fails
            return doc.NewUnknown(content.c_str());
        default:
            return nullptr;
    }
}

// Helper function to create a fuzzed XML tree structure
tinyxml2::XMLNode* CreateFuzzedXMLTree(FuzzedDataProvider& fdp, tinyxml2::XMLDocument& doc) {
    // Determine the number of nodes to create
    int num_nodes = fdp.ConsumeIntegralInRange<int>(0, 20);
    std::vector<tinyxml2::XMLNode*> nodes;

    // Create the fuzzed nodes
    for (int i = 0; i < num_nodes; ++i) {
        tinyxml2::XMLNode* node = CreateFuzzedNode(fdp, doc);
        if (node) {
            nodes.push_back(node);
        }
    }

    // If no nodes were successfully created, return nullptr
    if (nodes.empty()) {
        return nullptr;
    }

    // Attempt to link the first element as the root to the document for proper cleanup
    tinyxml2::XMLNode* root = nullptr;
    for(tinyxml2::XMLNode* node : nodes) {
        if (node && node->ToElement()) { // Added null check for node
            root = node;
            doc.InsertEndChild(root);
            break;
        }
    }

    // If no element was found to be the root, the document will still own the created nodes
    if (!root) {
        // Ensure all created nodes are linked to the document even if no root element was found
        for(tinyxml2::XMLNode* node : nodes) {
            if (node && !node->Parent()) { // Check if node was not already linked
                 doc.InsertEndChild(node);
            }
        }
        return nullptr;
    }

    // Link other nodes into the tree structure
    for (size_t i = 0; i < nodes.size(); ++i) {
        tinyxml2::XMLNode* child = nodes[i];
        // Skip null nodes, the root, and nodes already linked to the document via root insertion
        if (!child || child == root || child->Parent() == &doc) continue;

        // Pick a random parent from the existing nodes (including the root)
        // Ensure parent_index is within bounds of nodes vector
        int parent_index = fdp.ConsumeIntegralInRange<int>(0, nodes.size() - 1);
        tinyxml2::XMLNode* parent = nodes[parent_index];

        // Only elements and the document can have children
        if (parent && (parent->ToElement() || parent->ToDocument())) {
             // Fuzz the insertion method
            enum InsertMethod {
                INSERT_END,
                INSERT_FIRST,
                INSERT_AFTER,
                kMaxValue = INSERT_AFTER // Added kMaxValue for FuzzedDataProvider::ConsumeEnum
            };
            InsertMethod method = fdp.ConsumeEnum<InsertMethod>();

            switch(method) {
                case INSERT_END:
                    parent->InsertEndChild(child);
                    break;
                case INSERT_FIRST:
                    parent->InsertFirstChild(child);
                    break;
                case INSERT_AFTER: {
                    // Need a sibling to insert after. Try to find one.
                    tinyxml2::XMLNode* sibling = parent->FirstChild();
                    if (sibling) {
                         parent->InsertAfterChild(sibling, child);
                    } else {
                         // If no sibling, just insert at the end
                         parent->InsertEndChild(child);
                    }
                    break;
                }
            }
        } else {
            // If the parent is not an element or document, the child remains unlinked but owned by the document.
            // Ensure the child is linked to the document if it wasn't linked to a valid parent
            if (!child->Parent()) {
                doc.InsertEndChild(child);
            }
        }
    }

    // Add fuzzed attributes to elements
    for (tinyxml2::XMLNode* node : nodes) {
        if (tinyxml2::XMLElement* elem = node->ToElement()) {
            int num_attributes = fdp.ConsumeIntegralInRange<int>(0, 5);
            for (int i = 0; i < num_attributes; ++i) {
                std::string attr_name = fdp.ConsumeRandomLengthString(10);
                std::string attr_value = fdp.ConsumeRandomLengthString(20);
                // SetAttribute handles memory for attribute names and values
                elem->SetAttribute(attr_name.c_str(), attr_value.c_str());
            }
        }
    }

    return root; // Return the root element (or nullptr if none)
}


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // FuzzedDataProvider for structured input
    FuzzedDataProvider fdp(Data, Size);

    // Use a switch to select which API call sequence to test, ensuring diversity
    // Increased range to cover new test cases based on coverage analysis.
    int test_case = fdp.ConsumeIntegralInRange<int>(0, 8);

    switch (test_case) {
        case 0: { // Test XMLDocument::Parse
            // Consume remaining data as a string to parse
            std::string xml_string = fdp.ConsumeRemainingBytesAsString();
            // Create an XMLDocument object. It will manage the memory of parsed nodes.
            tinyxml2::XMLDocument doc;
            // Parse the fuzzed string. tinyxml2 handles memory allocation/deallocation internally during parsing.
            // Added fuzzed boolean to sometimes pass nullptr to doc.Parse to hit missed branch in XMLDocument::Parse.
            bool pass_null = fdp.ConsumeBool();
            if (pass_null) {
                 doc.Parse(nullptr, 0); // Pass nullptr to hit the missed branch in XMLDocument::Parse
            } else {
                 doc.Parse(xml_string.c_str(), xml_string.size());
            }
            // The XMLDocument destructor automatically cleans up all allocated nodes and data.
            break;
        }
        case 1: { // Test XMLDocument::Print
            // Create an XMLDocument object
            tinyxml2::XMLDocument doc;
            // Create a fuzzed XML tree structure within the document
            CreateFuzzedXMLTree(fdp, doc);
            // Create an XMLPrinter object. It manages its internal buffer.
            tinyxml2::XMLPrinter printer;
            // Print the document using the printer. This exercises XMLPrinter's Visit methods.
            doc.Print(&printer);
            // The XMLDocument and XMLPrinter destructors automatically clean up memory.
            break;
        }
        case 2: { // Test XMLElement::ShallowEqual
            // Create an XMLDocument object to own the elements
            tinyxml2::XMLDocument doc;
            // Consume strings for element names
            std::string name1 = fdp.ConsumeRandomLengthString(10);
            std::string name2 = fdp.ConsumeRandomLengthString(10);
            // Create two elements. NewElement returns nullptr on failure.
            tinyxml2::XMLElement* elem1 = doc.NewElement(name1.c_str());
            tinyxml2::XMLElement* elem2 = doc.NewElement(name2.c_str());

            // Proceed only if both elements were created successfully
            if (elem1 && elem2) {
                // Add fuzzed attributes to the first element
                int num_attributes1 = fdp.ConsumeIntegralInRange<int>(0, 5);
                for (int i = 0; i < num_attributes1; ++i) {
                    std::string attr_name = fdp.ConsumeRandomLengthString(10);
                    std::string attr_value = fdp.ConsumeRandomLengthString(20);
                    // SetAttribute handles memory for attribute names and values
                    elem1->SetAttribute(attr_name.c_str(), attr_value.c_str());
                }

                // Add fuzzed attributes to the second element
                int num_attributes2 = fdp.ConsumeIntegralInRange<int>(0, 5);
                for (int i = 0; i < num_attributes2; ++i) {
                    std::string attr_name = fdp.ConsumeRandomLengthString(10);
                    std::string attr_value = fdp.ConsumeRandomLengthString(20);
                    elem2->SetAttribute(attr_name.c_str(), attr_value.c_str());
                }

                // Compare the elements shallowly
                elem1->ShallowEqual(elem2);

                // Link elements to the document to ensure their memory is managed by the document's destructor
                // Only link if not already linked (e.g., if NewElement failed and returned nullptr)
                if (!elem1->Parent()) doc.InsertEndChild(elem1);
                if (!elem2->Parent()) doc.InsertEndChild(elem2);

            } else {
                 // If element creation failed, link any created element to the document for cleanup
                 if (elem1 && !elem1->Parent()) doc.InsertEndChild(elem1);
                 if (elem2 && !elem2->Parent()) doc.InsertEndChild(elem2);
            }
            // The XMLDocument destructor automatically cleans up all allocated nodes and data.
            break;
        }
        case 3: { // Test XMLNode::DeleteNode
            // Create an XMLDocument object
            tinyxml2::XMLDocument doc;
            // Create a fuzzed XML tree structure
            tinyxml2::XMLNode* root = CreateFuzzedXMLTree(fdp, doc);

            // If a root element was created and linked to the document
            if (root && root->ToElement()) {
                std::vector<tinyxml2::XMLNode*> children;
                // Collect all children of the root element
                for (tinyxml2::XMLNode* child = root->FirstChild(); child; child = child->NextSibling()) {
                    children.push_back(child);
                }

                // If the root has children
                if (!children.empty()) {
                    // Select a child to delete using fuzzed data
                    int child_to_delete_index = fdp.ConsumeIntegralInRange<int>(0, children.size() - 1);
                    tinyxml2::XMLNode* child_to_delete = children[child_to_delete_index];
                    // Delete the selected child node. DeleteChild handles the memory of the deleted node.
                    if (child_to_delete) {
                        root->DeleteChild(child_to_delete);
                    }
                }
            }
            // The XMLDocument destructor automatically cleans up remaining allocated nodes and data.
            break;
        }
        case 4: { // Test XMLNode::InsertEndChild (and other insertions via helper)
            // Create an XMLDocument object
            tinyxml2::XMLDocument doc;
            // Create a fuzzed XML tree structure. The helper function uses InsertEndChild, InsertFirstChild, and InsertAfterChild.
            CreateFuzzedXMLTree(fdp, doc);
            // The XMLDocument destructor automatically cleans up all allocated nodes and data, including those inserted.
            break;
        }
        case 5: { // Test COLLAPSE_WHITESPACE parsing and printing
            // Added case to test COLLAPSE_WHITESPACE mode based on coverage report for StrPair::CollapseWhitespace.
            // Create an XMLDocument object with COLLAPSE_WHITESPACE mode
            tinyxml2::XMLDocument doc(true, tinyxml2::COLLAPSE_WHITESPACE);
            // Consume remaining data as a string to parse
            std::string xml_string = fdp.ConsumeRemainingBytesAsString();
            // Parse the fuzzed string
            doc.Parse(xml_string.c_str(), xml_string.size());
            // Optionally print the document to exercise printing with this mode
            tinyxml2::XMLPrinter printer;
            doc.Print(&printer);
            // The XMLDocument and XMLPrinter destructors automatically clean up memory.
            break;
        }
        case 6: { // Test XMLConstHandle methods
            // Added case to test XMLConstHandle methods based on coverage report.
            // Create an XMLDocument object
            tinyxml2::XMLDocument doc;
            // Create a fuzzed XML tree structure
            tinyxml2::XMLNode* original_root = CreateFuzzedXMLTree(fdp, doc);

            // Use XMLConstHandle to navigate the tree (exercises const methods)
            tinyxml2::XMLConstHandle handle(original_root); // Use original_root directly

            // Test casting methods on the root handle
            const tinyxml2::XMLNode* node = handle.ToNode();
            if (node) {
                node->ToElement();
                node->ToText();
                node->ToComment(); // This is the correct way to call ToComment() on a node pointer
                node->ToDeclaration();
                node->ToUnknown();
            }

            // Get a child element handle and test its methods
            tinyxml2::XMLConstHandle child_handle = handle.FirstChildElement(fdp.ConsumeRandomLengthString(10).c_str());
            if (!child_handle.ToElement()) {
                 child_handle = handle.LastChildElement(fdp.ConsumeRandomLengthString(10).c_str());
            }

            const tinyxml2::XMLElement* child_element = child_handle.ToElement();
            if (child_element) {
                // Access attributes via the XMLElement*
                child_element->Attribute(fdp.ConsumeRandomLengthString(10).c_str());

                // Test other XMLConstHandle navigation methods from the child handle
                child_handle.FirstChild();
                child_handle.LastChild();
                child_handle.PreviousSibling();
                child_handle.NextSibling();
                child_handle.PreviousSiblingElement(fdp.ConsumeRandomLengthString(10).c_str());
                child_handle.NextSiblingElement(fdp.ConsumeRandomLengthString(10).c_str());

                // Test casting methods on the child handle's underlying node
                const tinyxml2::XMLNode* child_node = child_handle.ToNode();
                if (child_node) {
                    child_node->ToElement();
                    child_node->ToText();
                    child_node->ToComment();
                    child_node->ToDeclaration();
                    child_node->ToUnknown();
                }
            }

            // The XMLDocument destructor automatically cleans up memory.
            break;
        }
        case 7: { // Test XMLElement::InsertNew* methods
            // Added case to test XMLElement::InsertNew* methods based on coverage report.
            // Create an XMLDocument object
            tinyxml2::XMLDocument doc;
            // Create a root element
            tinyxml2::XMLElement* root = doc.NewElement("root");
            doc.InsertEndChild(root);

            if (root) {
                // Use fuzzed data to insert various new node types
                int num_insertions = fdp.ConsumeIntegralInRange<int>(0, 10);
                for (int i = 0; i < num_insertions; ++i) {
                    enum NewNodeType {
                        NEW_ELEMENT,
                        NEW_COMMENT,
                        NEW_TEXT,
                        NEW_DECLARATION,
                        NEW_UNKNOWN,
                        kMaxValue = NEW_UNKNOWN
                    };
                    NewNodeType node_type = fdp.ConsumeEnum<NewNodeType>();
                    std::string content = fdp.ConsumeRandomLengthString(50);

                    switch(node_type) {
                        case NEW_ELEMENT:
                            root->InsertNewChildElement(content.c_str());
                            break;
                        case NEW_COMMENT:
                            root->InsertNewComment(content.c_str());
                            break;
                        case NEW_TEXT:
                            root->InsertNewText(content.c_str());
                            break;
                        case NEW_DECLARATION:
                            root->InsertNewDeclaration(content.c_str());
                            break;
                        case NEW_UNKNOWN:
                            root->InsertNewUnknown(content.c_str());
                            break;
                    }
                }
            }
            // The XMLDocument destructor automatically cleans up memory.
            break;
        }
        case 8: { // Test XMLNode::DeepClone
            // Added case to test XMLNode::DeepClone based on coverage report.
            // Create an XMLDocument object for the original tree
            tinyxml2::XMLDocument doc;
            // Create a fuzzed XML tree structure
            tinyxml2::XMLNode* original_root = CreateFuzzedXMLTree(fdp, doc);

            if (original_root) {
                // Create a new document to own the cloned node for memory safety.
                tinyxml2::XMLDocument cloned_doc;
                // Deep clone the original root node
                tinyxml2::XMLNode* cloned_node = original_root->DeepClone(&cloned_doc);
                // The cloned_doc will now own the cloned_node and its children.
                // The cloned_doc destructor will clean up the cloned tree.
            }
            // The original 'doc' destructor cleans up the original tree.
            break;
        }
    }

    return 0;
}