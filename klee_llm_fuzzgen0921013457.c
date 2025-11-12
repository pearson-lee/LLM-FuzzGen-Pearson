#include <klee/klee.h>
#include "tinyxml2.h"

using namespace tinyxml2;

int main() {
    XMLDocument doc;
    
    // Create a symbolic XML structure
    char xml_buf[200];
    klee_make_symbolic(xml_buf, sizeof(xml_buf), "xml");
    
    // Ensure null termination
    xml_buf[sizeof(xml_buf)-1] = '\0';
    
    // Constrain to valid XML characters
    for (int i = 0; i < sizeof(xml_buf)-1; i++) {
        klee_assume(xml_buf[i] >= 0x20 && xml_buf[i] <= 0x7e);
    }
    
    // Parse the symbolic XML
    doc.Parse(xml_buf);
    
    // Get root and its children
    XMLElement* root = doc.RootElement();
    if (root) {
        XMLNode* child = root->FirstChild();
        if (child) {
            // Key: directly call DeleteNode on a node that has a parent
            // This should trigger line 2330
            doc.DeleteNode(child);
        }
    }
    
    return 0;
}