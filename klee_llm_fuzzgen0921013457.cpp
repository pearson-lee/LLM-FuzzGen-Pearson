#include <klee/klee.h>
#include "tinyxml2.h"
#include <cstring>

using namespace tinyxml2;

int main() {
    XMLDocument doc;
    
    // Create symbolic XML buffer
    char xml_buf[200];
    klee_make_symbolic(xml_buf, sizeof(xml_buf), "xml");
    
    // Ensure null termination
    xml_buf[sizeof(xml_buf)-1] = '\0';
    
    // Constrain to printable ASCII characters
    for (int i = 0; i < sizeof(xml_buf)-1; i++) {
        klee_assume((xml_buf[i] >= 0x20 && xml_buf[i] <= 0x7e) || 
                    xml_buf[i] == '\0' || 
                    xml_buf[i] == '\n' || 
                    xml_buf[i] == '\t');
    }
    
    // Parse the symbolic XML
    XMLError error = doc.Parse(xml_buf);
    
    // Only proceed if parsing succeeded
    if (error == XML_SUCCESS) {
        XMLElement* root = doc.RootElement();
        if (root) {
            XMLNode* child = root->FirstChild();
            if (child) {
                // This should trigger line coverage in DeleteNode
                root->DeleteChild(child);
            }
        }
    }
    
    return 0;
}