#include <cstddef>
#include <cstdint>
#include <string>
#include <unistd.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/tinyxml2/tinyxml2.h"
#include <cstdio> // For FILE*

// Compile-time macro for unique temporary filenames
#ifndef _FUZZ_TARGET_NAME
#define _FUZZ_TARGET_NAME "fuzz_target"
#endif

/*
 * ANALYSIS: The function-level coverage report showed that the XMLVisitor virtual
 *           methods had 0% coverage.
 * IMPLEMENTATION: The following class implements the XMLVisitor interface. An
 *                 instance of it is later used with doc.Accept() to exercise this
 *                 uncovered API.
 */
class MyVisitor : public tinyxml2::XMLVisitor {
public:
    bool VisitEnter(const tinyxml2::XMLElement&, const tinyxml2::XMLAttribute*) override { return true; }
    bool VisitExit(const tinyxml2::XMLElement&) override { return true; }
    bool Visit(const tinyxml2::XMLDeclaration&) override { return true; }
    bool Visit(const tinyxml2::XMLText&) override { return true; }
    bool Visit(const tinyxml2::XMLComment&) override { return true; }
    bool Visit(const tinyxml2::XMLUnknown&) override { return true; }
};

// Helper class to expose the protected Print method for fuzzing
class PublicPrinter : public tinyxml2::XMLPrinter {
public:
    using tinyxml2::XMLPrinter::Print;
};


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Use a unique filename for each fuzzer instance to avoid race conditions
  std::string temp_filename = std::string("/tmp/") + _FUZZ_TARGET_NAME + ".xml";

  // Consume a string from the fuzzer input to use for our operations
  std::string xml_data = fdp.ConsumeRandomLengthString(1024);

  /*
   * ANALYSIS: The function-level coverage report showed that tinyxml2::StrPair::CollapseWhitespace
   *           had 0% coverage. This function is only called when the COLLAPSE_WHITESPACE
   *           flag is passed to the parser.
   * IMPLEMENTATION: The following code block sometimes passes the COLLAPSE_WHITESPACE
   *                 flag to doc.Parse() to exercise this uncovered code path.
   */
  bool collapseWhitespace = fdp.ConsumeBool();
  tinyxml2::XMLDocument doc(true, collapseWhitespace ? tinyxml2::COLLAPSE_WHITESPACE : tinyxml2::PRESERVE_WHITESPACE);
  doc.Parse(xml_data.c_str());

  // Create two elements to test ShallowEqual
  tinyxml2::XMLElement *elem1 = doc.NewElement(fdp.ConsumeRandomLengthString(16).c_str());
  tinyxml2::XMLElement *elem2 = doc.NewElement(fdp.ConsumeRandomLengthString(16).c_str());

  // Add attributes to the elements to test the attribute comparison in ShallowEqual
  if (elem1 && fdp.ConsumeBool()) {
    const std::string attr_name = fdp.ConsumeRandomLengthString(16);
    elem1->SetAttribute(attr_name.c_str(), fdp.ConsumeRandomLengthString(16).c_str());

    /*
     * ANALYSIS: The function-level coverage report showed that the various
     *           XMLElement::Query...Attribute functions had 0% coverage.
     * IMPLEMENTATION: The following code calls these functions on an element
     *                 that has had an attribute set on it. This exercises the
     *                 logic for finding and querying attributes.
     */
    int i;
    double d;
    bool b;
    const char* s;
    elem1->QueryIntAttribute(attr_name.c_str(), &i);
    elem1->QueryDoubleAttribute(attr_name.c_str(), &d);
    elem1->QueryBoolAttribute(attr_name.c_str(), &b);
    elem1->QueryStringAttribute(attr_name.c_str(), &s);

    /*
     * ANALYSIS: The function-level coverage report showed that the various
     *           XMLElement::QueryAttribute overloads (e.g., QueryAttribute(const char*, int*))
     *           had 0% coverage.
     * IMPLEMENTATION: The following code calls these functions on an element
     *                 that has had an attribute set on it. This exercises the
     *                 logic for finding and querying attributes using these specific
     *                 overloads.
     */
    unsigned u_attr;
    long l_attr;
    unsigned long ul_attr;
    float f_attr;
    elem1->QueryAttribute(attr_name.c_str(), &i);
    elem1->QueryAttribute(attr_name.c_str(), &u_attr);
    elem1->QueryAttribute(attr_name.c_str(), &l_attr);
    elem1->QueryAttribute(attr_name.c_str(), &ul_attr);
    elem1->QueryAttribute(attr_name.c_str(), &b);
    elem1->QueryAttribute(attr_name.c_str(), &d);
    elem1->QueryAttribute(attr_name.c_str(), &f_attr);
    // The following line is intentionally commented out to avoid saving a pointer
    // to internal data that may become dangling. The function is still covered by
    // the QueryStringAttribute call above.
    // elem1->QueryAttribute(attr_name.c_str(), &s);
    
    /*
     * ANALYSIS: The function-level coverage report showed XMLNode::GetLineNum() had
     *           0% coverage.
     * IMPLEMENTATION: The following code calls GetLineNum() on an attribute to
     *                 exercise this uncovered function.
     */
    if (elem1->FirstAttribute()) {
        elem1->FirstAttribute()->GetLineNum();
    }
  }
  if (elem2 && fdp.ConsumeBool()) {
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
  if (elem1 && elem2) {
    elem1->ShallowEqual(elem2);
  }

  if (elem1) {
    /*
     * ANALYSIS: The function-level coverage report showed that the various
     *           XMLElement::Query...Text functions and StrPair::CollapseWhitespace had
     *           low or zero coverage. The line-level report for tinyxml2::XMLUtil::ToInt64
     *           showed the hex parsing branch was untaken.
     * IMPLEMENTATION: The following code block sets the text of an element to a
     *                 fuzzed value (number, whitespace-prefixed, or hex string) and then
     *                 calls the various Query...Text functions to exercise their parsing logic.
     */
    if (fdp.ConsumeBool()) {
        std::string text_val;
        int choice = fdp.ConsumeIntegralInRange(0, 2);
        if (choice == 0) {
            text_val = std::to_string(fdp.ConsumeIntegral<int64_t>());
        } else if (choice == 1) {
            text_val = " " + fdp.ConsumeRandomLengthString(32);
        } else {
            text_val = "0x" + fdp.ConsumeBytesAsString(fdp.ConsumeIntegralInRange(1, 8));
        }
        elem1->SetText(text_val.c_str());
        elem1->GetText();

        int i;
        unsigned u;
        int64_t l;
        uint64_t ul;
        bool b;
        double d;
        float f;
        elem1->QueryIntText(&i);
        elem1->QueryUnsignedText(&u);
        elem1->QueryInt64Text(&l);
        elem1->QueryUnsigned64Text(&ul);
        elem1->QueryBoolText(&b);
        elem1->QueryDoubleText(&d);
        elem1->QueryFloatText(&f);
    }
    doc.InsertFirstChild(elem1);
  }
  if (elem1 && elem2) {
    elem1->InsertFirstChild(elem2);
  }

  /*
   * ANALYSIS: The function-level coverage report showed XMLNode::InsertAfterChild had
   *           low coverage (60%). The line-level report showed error handling branches
   *           for inserting a node after itself or from another document were not taken.
   * IMPLEMENTATION: The following code blocks exercise these uncovered error paths in
   *                 InsertAfterChild.
   */
  if (elem1) {
      elem1->InsertAfterChild(elem1, elem1);
  }
  if (elem1 && elem1->Parent()) {
      tinyxml2::XMLDocument otherDoc;
      tinyxml2::XMLElement* otherElem = otherDoc.NewElement("other");
      if (otherElem) {
          elem1->Parent()->InsertAfterChild(elem1, otherElem);
      }
  }

  /*
   * ANALYSIS: The function-level coverage report showed XMLNode::InsertAfterChild had
   *           low coverage (60%).
   * IMPLEMENTATION: The following code block creates a third element and inserts it
   *                 after an existing child to exercise the logic in InsertAfterChild.
   *                 The new element is allocated from the document and will be freed
   *                 when the document is destroyed.
   */
  tinyxml2::XMLElement *elem3 = doc.NewElement(fdp.ConsumeRandomLengthString(16).c_str());
  if (elem2 && elem2->Parent() && elem3) {
      elem2->Parent()->InsertAfterChild(elem2, elem3);
  }

  /*
   * ANALYSIS: The function-level coverage report showed that the XMLNode::To...()
   *           (e.g., ToDeclaration, ToComment) and XMLNode::GetDocument() functions
   *           had 0% coverage.
   * IMPLEMENTATION: The following code block creates a declaration and a comment,
   *                 adds them to the document, retrieves them as base XMLNode
   *                 pointers, and then calls the specific To...() methods to exercise
   *                 the down-casting logic. It also calls GetDocument() on an element.
   */
  if (fdp.ConsumeBool()) {
    tinyxml2::XMLNode* declNode = doc.NewDeclaration(fdp.ConsumeRandomLengthString(16).c_str());
    if (declNode) {
      doc.InsertFirstChild(declNode);
      if (doc.FirstChild()) {
        doc.FirstChild()->ToDeclaration();
      }
    }
  }
  if (fdp.ConsumeBool()) {
    tinyxml2::XMLNode* commentNode = doc.NewComment(fdp.ConsumeRandomLengthString(16).c_str());
    if (commentNode) {
      doc.InsertEndChild(commentNode);
      if (doc.LastChild()) {
        doc.LastChild()->ToComment();
        /*
         * ANALYSIS: The function-level coverage report showed that the various ShallowClone
         *           methods had low coverage.
         * IMPLEMENTATION: The following code calls ShallowClone on a comment node to
         *                 exercise this uncovered functionality. The cloned node must be
         *                 explicitly deleted as it is not part of the document.
         */
        tinyxml2::XMLNode* clonedNode = doc.LastChild()->ShallowClone(&doc);
        if (clonedNode) {
            // Do not delete clonedNode here. It is owned by the document 'doc'
            // and will be freed when 'doc' goes out of scope.
        }
      }
    }
  }
  if (elem1) {
    elem1->GetDocument();
  }

  /*
   * ANALYSIS: The function-level coverage report showed 0% coverage for
   *           XMLNode::ToUnknown() and XMLNode::GetLineNum(), and low coverage for
   *           XMLDocument::DeleteNode.
   * IMPLEMENTATION: The following code creates an XMLUnknown node, calls ToUnknown()
   *                 and GetLineNum() on it, and then deletes it using doc.DeleteNode()
   *                 to exercise these uncovered code paths.
   */
  if (fdp.ConsumeBool()) {
      tinyxml2::XMLNode* unknownNode = doc.NewUnknown(fdp.ConsumeRandomLengthString(16).c_str());
      if (unknownNode) {
          doc.InsertEndChild(unknownNode);
          unknownNode->ToUnknown();
          unknownNode->GetLineNum();
          doc.DeleteNode(unknownNode);
      }
  }

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

  /*
   * ANALYSIS: The function-level coverage report showed XMLDocument::LoadFile(FILE*)
   *           had low coverage, as only the LoadFile(const char*) overload was being called.
   * IMPLEMENTATION: The following code opens the temporary file to get a FILE* handle
   *                 and passes it to the LoadFile(FILE*) overload. This ensures the
   *                 logic for loading from a file stream is exercised. The FILE* is
   *                 safely closed afterward.
   */
  if (fdp.ConsumeBool()) {
    FILE* fp = fopen(temp_filename.c_str(), "r");
    if (fp) {
        doc.LoadFile(fp);
        fclose(fp);
    }
  }

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
  PublicPrinter printer;
  doc.Print(&printer);

  /*
   * ANALYSIS: The function-level coverage report showed that XMLPrinter::Print(const char*, ...)
   *           and TIXML_VSCPRINTF had 0% coverage.
   * IMPLEMENTATION: The following code block calls Print with a format string and
   *                 fuzzed arguments to exercise the logic within this function, which in turn
   *                 calls TIXML_VSCPRINTF.
   */
  if (fdp.ConsumeBool()) {
    printer.Print("fuzz_int=%d fuzz_str=%s", fdp.ConsumeIntegral<int>(), fdp.ConsumeRandomLengthString(16).c_str());
  }

  if (fdp.ConsumeBool()) {
    printer.PushText(fdp.ConsumeRandomLengthString(16).c_str());
  }

    /*
     * ANALYSIS: The function-level coverage report showed that XMLUtil::SetBoolSerialization
     *           had low branch coverage (50%).
     * IMPLEMENTATION: The following code calls SetBoolSerialization with fuzzer-
     *                 generated strings to exercise the uncovered branches.
     */
    if (fdp.ConsumeBool()) {
        tinyxml2::XMLUtil::SetBoolSerialization(
            fdp.ConsumeRandomLengthString(8).c_str(),
            fdp.ConsumeRandomLengthString(8).c_str()
        );
    }

    /*
     * ANALYSIS: The function-level coverage report showed that XMLPrinter::PushHeader
     *           had low branch coverage (50%).
     * IMPLEMENTATION: The following code calls PushHeader with different boolean
     *                 arguments to exercise both branches of the function.
     */
    if (fdp.ConsumeBool()) {
        printer.PushHeader(fdp.ConsumeBool(), fdp.ConsumeBool());
    }

  /*
   * ANALYSIS: The function-level coverage report showed that the XMLHandle and
   *           XMLConstHandle related functions had 0% coverage.
   * IMPLEMENTATION: The following code creates handles and uses them to navigate the
   *                 document, exercising the various handle methods like FirstChild,
   *                 and NextSiblingElement.
   */
  if (doc.RootElement()) {
    tinyxml2::XMLHandle docHandle(&doc);
    tinyxml2::XMLElement* root = docHandle.FirstChildElement().ToElement();
    if (root) {
        tinyxml2::XMLHandle rootHandle(root);
        rootHandle.FirstChild().ToElement();
        rootHandle.NextSiblingElement(fdp.ConsumeRandomLengthString(8).c_str()).ToElement();
        /*
         * ANALYSIS: The function-level coverage report showed that the XMLHandle
         *           copy constructor and assignment operator had 0% coverage.
         * IMPLEMENTATION: The following code exercises the copy constructor and
         *                 assignment operator for XMLHandle.
         */
        tinyxml2::XMLHandle copiedHandle(rootHandle);
        tinyxml2::XMLHandle assignedHandle = copiedHandle;
    }
    tinyxml2::XMLConstHandle constDocHandle(&doc);
    constDocHandle.FirstChildElement(fdp.ConsumeRandomLengthString(8).c_str());
    /*
     * ANALYSIS: The function-level coverage report showed that the XMLConstHandle
     *           copy constructor and assignment operator had 0% coverage.
     * IMPLEMENTATION: The following code exercises the copy constructor and
     *                 assignment operator for XMLConstHandle.
     */
    tinyxml2::XMLConstHandle copiedConstHandle(constDocHandle);
    tinyxml2::XMLConstHandle assignedConstHandle = copiedConstHandle;
  }

    /*
     * ANALYSIS: The function-level coverage report showed that XMLNode::SetValue
     *           had low coverage.
     * IMPLEMENTATION: The following code calls SetValue on a comment node to
     *                 exercise this uncovered functionality.
     */
    if (doc.LastChild() && doc.LastChild()->ToComment()) {
        doc.LastChild()->SetValue(fdp.ConsumeRandomLengthString(16).c_str());
    }

    /*
     * ANALYSIS: The function-level coverage showed 0% coverage for tinyxml2::StrPair::SetInternedStr.
     *           This is called by XMLNode::SetValue when its 'staticMem' argument is true.
     * IMPLEMENTATION: The following code calls SetValue with 'true' to exercise this
     *                 uncovered code path.
     */
    if (doc.LastChild()) {
        doc.LastChild()->SetValue("static string", true);
    }

    /*
     * ANALYSIS: The function-level coverage report showed that XMLDocument::DeepCopy
     *           had low coverage.
     * IMPLEMENTATION: The following code creates a new document and deep copies
     *                 the existing document to it. The new document is deleted
     *                 to prevent memory leaks.
     */
    if (fdp.ConsumeBool()) {
        tinyxml2::XMLDocument newDoc;
        doc.DeepCopy(&newDoc);
    }

  /*
   * ANALYSIS: The function-level coverage report showed that the XMLVisitor virtual
   *           methods had 0% coverage.
   * IMPLEMENTATION: The following code calls doc.Accept() with the custom visitor to
   *                 exercise the visitor interface and all its virtual methods.
   */
  MyVisitor visitor;
  doc.Accept(&visitor);

  // Clean up the temporary file
  unlink(temp_filename.c_str());

  return 0;
}