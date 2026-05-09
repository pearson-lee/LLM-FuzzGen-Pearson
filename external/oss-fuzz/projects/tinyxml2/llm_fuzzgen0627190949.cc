#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include <cstdio>   // For tmpfile, fwrite, fclose
#include <unistd.h> // For mkstemp, close, remove

// Include the tinyxml2 header with its full project-relative path.
#include "/src/tinyxml2/tinyxml2.h"

// Custom visitor class to exercise the virtual methods of tinyxml2::XMLVisitor.
// These methods are called when XMLDocument::Accept() is invoked.
class FuzzVisitor : public tinyxml2::XMLVisitor {
public:
    // Override all Visit and VisitEnter/Exit methods to ensure they are called.
    bool VisitEnter(const tinyxml2::XMLDocument& /*doc*/) override { return true; }
    bool VisitExit(const tinyxml2::XMLDocument& /*doc*/) override { return true; }
    bool VisitEnter(const tinyxml2::XMLElement& /*element*/, const tinyxml2::XMLAttribute* /*firstAttribute*/) override { return true; }
    bool VisitExit(const tinyxml2::XMLElement& /*element*/) override { return true; }
    bool Visit(const tinyxml2::XMLDeclaration& /*declaration*/) override { return true; }
    bool Visit(const tinyxml2::XMLText& /*text*/) override { return true; }
    bool Visit(const tinyxml2::XMLComment& /*comment*/) override { return true; }
    bool Visit(const tinyxml2::XMLUnknown& /*unknown*/) override { return true; }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // Use a local scope to ensure all tinyxml2 objects (like doc and printer)
    // are properly destructed at the end of the function, which in turn
    // handles memory deallocation for nodes owned by the document.
    {
        tinyxml2::XMLDocument doc;

        // 1. Fuzz tinyxml2::XMLPrinter.
        // By using the default constructor, _fp (file pointer) will be NULL,
        // which forces XMLPrinter::Print to use its internal buffer and call TIXML_VSCPRINTF.
        tinyxml2::XMLPrinter printer;

        // The direct call to printer.Print is removed as it's a protected member.
        // The XMLPrinter is still fuzzed by being passed to doc.Print(&printer).

        // 2. Fuzz tinyxml2::XMLDocument::Print(tinyxml2::XMLPrinter*) const.
        // Parse some fuzzed XML data into the document.
        std::string xml_string = fdp.ConsumeRandomLengthString(1024);
        doc.Parse(xml_string.c_str());

        // Call Print with a nullptr for the printer to hit the internal branch
        // where a default XMLPrinter is created.
        doc.Print(nullptr);

        // Call Print with a valid XMLPrinter instance.
        doc.Print(&printer);

        // 3. Fuzz destructors of tinyxml2::XMLDeclaration, tinyxml2::XMLUnknown,
        // tinyxml2::XMLComment, and tinyxml2::XMLText.
        // These destructors will be implicitly called when the 'doc' object goes
        // out of scope, as 'doc' owns these nodes.
        if (fdp.ConsumeBool()) {
            tinyxml2::XMLDeclaration* decl = doc.NewDeclaration(fdp.ConsumeRandomLengthString(20).c_str());
            if (decl) doc.LinkEndChild(decl);
        }
        if (fdp.ConsumeBool()) {
            tinyxml2::XMLUnknown* unknown = doc.NewUnknown(fdp.ConsumeRandomLengthString(20).c_str());
            if (unknown) doc.LinkEndChild(unknown);
        }
        if (fdp.ConsumeBool()) {
            tinyxml2::XMLComment* comment = doc.NewComment(fdp.ConsumeRandomLengthString(50).c_str());
            if (comment) doc.LinkEndChild(comment);
        }
        if (fdp.ConsumeBool()) {
            tinyxml2::XMLText* text = doc.NewText(fdp.ConsumeRandomLengthString(50).c_str());
            if (text) doc.LinkEndChild(text);
        }

        // Create a root element to add children and attributes for further fuzzing.
        tinyxml2::XMLElement* root = doc.NewElement(fdp.ConsumeRandomLengthString(10).c_str());
        if (root) {
            doc.LinkEndChild(root); // Link root to the document.

            // Add some attributes to the root element.
            root->SetAttribute(fdp.ConsumeRandomLengthString(10).c_str(), fdp.ConsumeRandomLengthString(20).c_str());
            root->SetAttribute(fdp.ConsumeRandomLengthString(10).c_str(), fdp.ConsumeIntegral<int>());

            // Added to cover tinyxml2::XMLUtil::IsPrefixHex branch (p[1] == 'X')
            // by providing an attribute value that starts with "0X".
            root->SetAttribute("hex_attr", ("0X" + fdp.ConsumeRandomLengthString(8)).c_str());
            int val;
            root->QueryIntAttribute("hex_attr", &val);

            // 4. Fuzz tinyxml2::XMLNode::DeepClone(tinyxml2::XMLDocument*) const.
            // Clone the root element. The cloned node is owned by 'doc'.
            tinyxml2::XMLNode* cloned_root = root->DeepClone(&doc);
            // No explicit deletion needed for 'cloned_root' as it's managed by 'doc'.

            // Fuzz XMLNode::DeepClone with a nullptr target document to hit the !clone branch
            // within DeepClone (e.g., if ShallowClone returns nullptr due to allocation failure).
            if (fdp.ConsumeBool()) {
                tinyxml2::XMLNode* cloned_null_doc = root->DeepClone(nullptr);
                // cloned_null_doc will be nullptr, no need to delete.
            }

            // Add a child element to the root to test DeepClone with children.
            tinyxml2::XMLElement* child_element = doc.NewElement(fdp.ConsumeRandomLengthString(10).c_str());
            if (child_element) {
                root->LinkEndChild(child_element);
                child_element->SetText(fdp.ConsumeRandomLengthString(30).c_str());
            }
            // Clone again with children to exercise the recursive cloning logic.
            tinyxml2::XMLNode* cloned_root_with_children = root->DeepClone(&doc);
            // No explicit deletion needed for 'cloned_root_with_children' as it's managed by 'doc'.

            // 5. Fuzz XMLElement::InsertNewChildElement and related InsertNew... functions.
            // These functions create new nodes and link them to the current element.
            // The newly created nodes are owned by the document.
            if (fdp.ConsumeBool()) {
                root->InsertNewChildElement(fdp.ConsumeRandomLengthString(15).c_str());
            }
            if (fdp.ConsumeBool()) {
                root->InsertNewComment(fdp.ConsumeRandomLengthString(50).c_str());
            }
            if (fdp.ConsumeBool()) {
                root->InsertNewText(fdp.ConsumeRandomLengthString(50).c_str());
            }
            if (fdp.ConsumeBool()) {
                root->InsertNewDeclaration(fdp.ConsumeRandomLengthString(20).c_str());
            }
            if (fdp.ConsumeBool()) {
                root->InsertNewUnknown(fdp.ConsumeRandomLengthString(20).c_str());
            }

            // Added to cover XMLNode::InsertChildPreamble's 'if ( addThis->_parent )' branch.
            // This links a node to one parent, then re-links it to another, triggering the unlink logic.
            if (fdp.ConsumeBool()) {
                tinyxml2::XMLElement* element1 = doc.NewElement("element1_relink");
                tinyxml2::XMLElement* element2 = doc.NewElement("element2_relink");
                if (element1 && element2) {
                    doc.LinkEndChild(element1); // element1 now has doc as parent
                    element1->LinkEndChild(element2); // element2 now has element1 as parent
                    // Now, link element2 to doc directly. This should trigger Unlink from element1.
                    doc.LinkEndChild(element2);
                }
            }

            // Added to cover XMLElement::DeleteAttribute(XMLAttribute*) branches.
            // This exercises deleting attributes from different positions (first, middle, last).
            root->SetAttribute("attrA", "valA");
            root->SetAttribute("attrB", "valB");
            root->SetAttribute("attrC", "valC");

            if (fdp.ConsumeBool()) {
                const tinyxml2::XMLAttribute* attr = root->FirstAttribute();
                if (attr) {
                    root->DeleteAttribute(attr->Name()); // Delete the first attribute (hits !prev branch)
                }
            }
            // Re-add attributes to ensure there are enough for middle/last deletions
            root->SetAttribute("attrD", "valD");
            root->SetAttribute("attrE", "valE");
            root->SetAttribute("attrF", "valF");

            if (fdp.ConsumeBool()) {
                const tinyxml2::XMLAttribute* attr = root->FindAttribute("attrE");
                if (attr) {
                    root->DeleteAttribute(attr->Name()); // Delete a middle attribute (hits prev and next branches)
                }
            }
            if (fdp.ConsumeBool()) {
                const tinyxml2::XMLAttribute* attr_iter = root->FirstAttribute();
                const tinyxml2::XMLAttribute* last_attr = nullptr;
                while (attr_iter) {
                    last_attr = attr_iter;
                    attr_iter = attr_iter->Next();
                }
                if (last_attr) {
                    root->DeleteAttribute(last_attr->Name()); // Delete the last attribute (hits prev but !next branch)
                }
            }
        }

        // Removed: Fuzzing XMLNode::LinkEndChild with nullptr causes a crash.
        // The tinyxml2 library expects a valid XMLNode* for this operation.
        // if (fdp.ConsumeBool()) {
        //     doc.LinkEndChild(nullptr);
        // }

        // Fuzz XMLHandle and XMLConstHandle methods with nullptr to cover branches
        // where the internal node pointer is null.
        if (fdp.ConsumeBool()) {
            tinyxml2::XMLHandle null_handle(nullptr);
            null_handle.FirstChild();
            null_handle.LastChild();
            null_handle.NextSibling();
            null_handle.PreviousSibling();
            null_handle.FirstChildElement(nullptr);
            null_handle.LastChildElement(nullptr);
            null_handle.NextSiblingElement(nullptr);
            null_handle.PreviousSiblingElement(nullptr);
            null_handle.ToElement();
            null_handle.ToText();
            // null_handle.ToComment(); // Removed: No ToComment() member
            null_handle.ToDeclaration();
            null_handle.ToUnknown();
            null_handle.ToNode();
        }
        if (fdp.ConsumeBool()) {
            tinyxml2::XMLConstHandle null_const_handle(nullptr);
            null_const_handle.FirstChild();
            null_const_handle.LastChild();
            null_const_handle.NextSibling();
            null_const_handle.PreviousSibling();
            null_const_handle.FirstChildElement(nullptr);
            null_const_handle.LastChildElement(nullptr);
            null_const_handle.NextSiblingElement(nullptr);
            null_const_handle.PreviousSiblingElement(nullptr);
            null_const_handle.ToElement();
            null_const_handle.ToText();
            // null_const_handle.ToComment(); // Removed: No ToComment() member
            null_const_handle.ToDeclaration();
            null_const_handle.ToUnknown();
            null_const_handle.ToNode();
        }

        // Exercise tinyxml2::XMLVisitor methods by accepting a custom visitor.
        // This will traverse the document and call the appropriate Visit methods.
        FuzzVisitor visitor;
        doc.Accept(&visitor);

        // Added to cover XMLDocument::LoadFile and SaveFile.
        // Uses mkstemp for a secure temporary filename.
        if (fdp.ConsumeBool()) {
            char filename[] = "/tmp/fuzz_tinyxml2_XXXXXX";
            int fd = mkstemp(filename); // Create a unique temporary file
            if (fd != -1) {
                close(fd); // Close the file descriptor, we just need the name

                // Save the current document to file
                doc.SaveFile(filename);

                // Create a new document and load from the file
                tinyxml2::XMLDocument loaded_doc;
                loaded_doc.LoadFile(filename);

                // Clean up the temporary file
                remove(filename);
            }
        }

        // Added to cover XMLDocument::LoadFile(_IO_FILE*).
        // Uses tmpfile for a temporary file stream.
        if (fdp.ConsumeBool()) {
            FILE* tmp_file = tmpfile(); // Creates a temporary file and opens it
            if (tmp_file) {
                // Write some fuzzed XML to the temporary file
                std::string file_content = fdp.ConsumeRandomLengthString(512);
                fwrite(file_content.c_str(), 1, file_content.length(), tmp_file);
                fseek(tmp_file, 0, SEEK_SET); // Rewind to the beginning

                tinyxml2::XMLDocument loaded_doc_fp;
                loaded_doc_fp.LoadFile(tmp_file);

                fclose(tmp_file); // Close and delete the temporary file
            }
        }

    } // The 'doc' and 'printer' objects go out of scope here.
      // 'doc's destructor will automatically free all XML nodes it owns,
      // ensuring memory safety and covering node destructors.

    return 0;
}