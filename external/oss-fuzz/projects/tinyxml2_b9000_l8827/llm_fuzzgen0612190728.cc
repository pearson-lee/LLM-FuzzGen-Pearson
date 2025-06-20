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
//
// Enhancements in this version:
// - Added calls to XMLElement::SetText(float) and XMLElement::GetText().
// - Added calls to XMLElement::QueryBoolAttribute and XMLElement::BoolAttribute.
// - Modified QueryDoubleAttribute to potentially set non-double string attributes to improve coverage in XMLUtil::ToDouble.
// - Added a second call to XMLElement::SetText(const char*) to cover a branch where a text node already exists.
// New Enhancements:
// - Added coverage for XMLElement::IntAttribute and XMLElement::QueryIntAttribute.
// - Added coverage for XMLElement::SetText(double) and XMLElement::QueryDoubleText.
// - Added targeted tests for branches in XMLElement::GetText() related to comment skipping and null returns.
// Further Enhancements:
// - Added coverage for XMLElement Set/Query/Int64Attribute, Set/Query/UnsignedAttribute, Set/Query/FloatAttribute.
// - Added coverage for XMLElement::SetText(int64_t) and XMLElement::SetText(uint64_t).
// - Added coverage for XMLUtil::SetBoolSerialization.
// - Added test for XMLNode::InsertFirstChild branch where _firstChild already exists.
// - Added test for XMLNode::SetValue staticMem=true branch.
// Latest Enhancements:
// - Added coverage for StrPair::GetStr() entity/newline/whitespace processing branches.
// - Added coverage for XMLElement text functions: QueryBoolText, BoolText, QueryIntText, IntText, QueryUnsignedText, UnsignedText, QueryInt64Text, Int64Text, QueryUnsigned64Text, Unsigned64Text, QueryFloatText, FloatText, DoubleText.
// - Added coverage for XMLElement attribute functions: QueryUnsigned64Attribute, Unsigned64Attribute, DoubleAttribute.
// - Added coverage for XMLElement::ShallowEqual and XMLElement::FirstAttribute.
// - Added coverage for XMLNode::PreviousSiblingElement, XMLNode::LastChildElement, XMLNode::ChildElementCount (with and without name).
// - Added coverage for XMLDocument::Clear() unlinked node path.
// - Added coverage for XMLElement::InsertNewDeclaration, XMLElement::InsertNewText, XMLElement::InsertNewUnknown and their To...() and destructor counterparts.
// - Added coverage for specific branches in XMLNode::Unlink and XMLNode::InsertChildPreamble.
// - Added coverage for XMLElement::DeleteAttribute(nullptr).

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    std::string trueStrForSerialization;
    std::string falseStrForSerialization;

    XMLDocument doc;

    if (fdp.ConsumeBool()) {
        trueStrForSerialization = fdp.ConsumeRandomLengthString(8);
        falseStrForSerialization = fdp.ConsumeRandomLengthString(8);
        if (trueStrForSerialization.empty()) trueStrForSerialization = "custom_true_val";
        if (falseStrForSerialization.empty()) falseStrForSerialization = "custom_false_val";
        XMLUtil::SetBoolSerialization(trueStrForSerialization.c_str(), falseStrForSerialization.c_str());
    } else {
        XMLUtil::SetBoolSerialization("true", "false");
    }

    std::string rootNameStr = fdp.ConsumeRandomLengthString(32);
    XMLElement* rootElement = doc.NewElement(rootNameStr.c_str());
    
    if (!rootElement) {
        return 0; 
    }
    doc.InsertFirstChild(rootElement);

    // Section for XMLDocument::Clear() unlinked node coverage (lines 2228-2229 in XMLDocument::Clear)
    // Create nodes but don't link them. They remain in doc's _unlinked list and are cleared by doc's destructor.
    // Memory is managed by 'doc'.
    if (fdp.ConsumeBool()) {
        (void)doc.NewElement("unlinked_el_for_clear_test"); 
    }
    if (fdp.ConsumeBool()) {
        (void)doc.NewComment("unlinked_comment_for_clear_test");
    }
    if (fdp.ConsumeBool()) {
        (void)doc.NewText("unlinked_text_for_clear_test");
    }


    // Section for StrPair::GetStr() entity/newline/whitespace processing (lines 286-376) and StrPair::CollapseWhitespace (line 373)
    // This is triggered by parsing XML and then accessing values that require string processing.
    // Memory for parseDoc and its nodes is self-contained and cleaned up when parseDoc goes out of scope.
    if (fdp.ConsumeBool()) {
        XMLDocument parseDoc(true, fdp.ConsumeBool() ? COLLAPSE_WHITESPACE : PRESERVE_WHITESPACE);
        std::string xmlToParse = "<docRoot ";
        xmlToParse += "attrName='" + fdp.ConsumeBytesAsString(5) + " &amp; &#65; \r\n " + fdp.ConsumeBytesAsString(5) + "&apos;" + "' ";
        xmlToParse += ">";
        xmlToParse += fdp.ConsumeBytesAsString(5) + " &lt; text \r content &gt; \n " + fdp.ConsumeBytesAsString(5);
        xmlToParse += "</docRoot>";

        parseDoc.Parse(xmlToParse.c_str()); // Parse to populate StrPair flags
        if (XMLElement* parsedRoot = parseDoc.RootElement()) {
            (void)parsedRoot->Name(); // Potentially triggers GetStr() for element name
            if (const XMLAttribute* attr = parsedRoot->FirstAttribute()) { // Covers XMLElement::FirstAttribute
                (void)attr->Name();  // Potentially triggers GetStr() for attribute name
                (void)attr->Value(); // Potentially triggers GetStr() for attribute value
            }
            (void)parsedRoot->GetText(); // Potentially triggers GetStr() for text content
        }
        // parseDoc and its contents are destructed here, freeing memory.
    }


    if (fdp.ConsumeBool()) { 
        const char* staticNameForElement = "element_static_name_literal"; 
        rootElement->SetName(staticNameForElement, true); 

        XMLComment* newStaticComment = doc.NewComment("comment_initial_value_literal");
        if (newStaticComment) {
            rootElement->InsertEndChild(newStaticComment); 
            const char* staticValueForComment = "comment_static_value_literal";
            newStaticComment->SetValue(staticValueForComment, true); 
        }
    }

    std::string commentText = fdp.ConsumeRandomLengthString(128); 
    XMLComment* firstComment = rootElement->InsertNewComment(commentText.c_str());
    if (firstComment && fdp.ConsumeBool()) { // Test ToComment()
        (void)firstComment->ToComment();
    }


    if (fdp.ConsumeBool() && firstComment) { 
        std::string anotherChildName = fdp.ConsumeRandomLengthString(32);
        XMLElement* anotherChildElement = doc.NewElement(anotherChildName.c_str());
        if (anotherChildElement) {
            rootElement->InsertFirstChild(anotherChildElement); 
        }
    }

    // Cover XMLElement::InsertNewDeclaration, InsertNewText, InsertNewUnknown
    // and their To...() methods and destructors (via doc cleanup).
    // Memory for these nodes is managed by rootElement or doc.
    if (fdp.ConsumeBool()) {
        XMLDeclaration* decl = rootElement->InsertNewDeclaration(fdp.ConsumeRandomLengthString(30).c_str());
        if (decl && fdp.ConsumeBool()) (void)decl->ToDeclaration(); // Cover ToDeclaration()
    }
    if (fdp.ConsumeBool()) {
        XMLText* textNode = rootElement->InsertNewText(fdp.ConsumeRandomLengthString(30).c_str());
        if (textNode && fdp.ConsumeBool()) (void)textNode->ToText(); // Cover ToText()
    }
    if (fdp.ConsumeBool()) {
        XMLUnknown* unknown = rootElement->InsertNewUnknown(fdp.ConsumeRandomLengthString(30).c_str());
        if (unknown && fdp.ConsumeBool()) (void)unknown->ToUnknown(); // Cover ToUnknown()
    }


    std::string childNameForSetText = fdp.ConsumeRandomLengthString(32);
    XMLElement* setTextElement = doc.NewElement(childNameForSetText.c_str());
    if (setTextElement) {
        rootElement->InsertEndChild(setTextElement); 
        unsigned int uintVal = fdp.ConsumeIntegral<unsigned int>();
        setTextElement->SetText(uintVal);
        
        std::string anotherText = fdp.ConsumeRandomLengthString(16);
        setTextElement->SetText(anotherText.c_str());

        float floatVal = fdp.ConsumeFloatingPoint<float>();
        setTextElement->SetText(floatVal);

        (void)setTextElement->GetText();

        if (fdp.ConsumeBool()) {
            setTextElement->SetText(fdp.ConsumeFloatingPoint<double>()); 
        } else {
            setTextElement->SetText("not-a-double-text-for-query"); 
        }
        double queryDblTextRes = 0.0;
        (void)setTextElement->QueryDoubleText(&queryDblTextRes);

        if (fdp.ConsumeBool()) {
            setTextElement->SetText(fdp.ConsumeIntegral<int64_t>());
        }
        if (fdp.ConsumeBool()) {
            setTextElement->SetText(fdp.ConsumeIntegral<uint64_t>());
        }

        // Cover XMLElement text functions (QueryBoolText, BoolText, etc.)
        bool bValText;
        (void)setTextElement->QueryBoolText(&bValText); // Cover QueryBoolText
        (void)setTextElement->BoolText(fdp.ConsumeBool()); // Cover BoolText

        int iValText;
        (void)setTextElement->QueryIntText(&iValText); // Cover QueryIntText
        (void)setTextElement->IntText(fdp.ConsumeIntegral<int>()); // Cover IntText

        unsigned uValText;
        (void)setTextElement->QueryUnsignedText(&uValText); // Cover QueryUnsignedText
        (void)setTextElement->UnsignedText(fdp.ConsumeIntegral<unsigned int>()); // Cover UnsignedText
        
        int64_t i64ValText;
        (void)setTextElement->QueryInt64Text(&i64ValText); // Cover QueryInt64Text
        (void)setTextElement->Int64Text(fdp.ConsumeIntegral<int64_t>()); // Cover Int64Text

        uint64_t u64ValText;
        (void)setTextElement->QueryUnsigned64Text(&u64ValText); // Cover QueryUnsigned64Text
        (void)setTextElement->Unsigned64Text(fdp.ConsumeIntegral<uint64_t>()); // Cover Unsigned64Text

        float fValText;
        (void)setTextElement->QueryFloatText(&fValText); // Cover QueryFloatText
        (void)setTextElement->FloatText(fdp.ConsumeFloatingPoint<float>()); // Cover FloatText
        
        (void)setTextElement->DoubleText(fdp.ConsumeFloatingPoint<double>()); // Cover DoubleText


        if (fdp.ConsumeBool()) { 
            XMLElement* queryEmptyDblTxtEl = doc.NewElement(fdp.ConsumeRandomLengthString(32).c_str());
            if (queryEmptyDblTxtEl) {
                rootElement->InsertEndChild(queryEmptyDblTxtEl);
                double tempDouble = 0.0;
                (void)queryEmptyDblTxtEl->QueryDoubleText(&tempDouble);
            }
        }
    }

    std::string childNameForQueryAttr = fdp.ConsumeRandomLengthString(32);
    XMLElement* queryAttrElement = doc.NewElement(childNameForQueryAttr.c_str());
    if (queryAttrElement) {
        rootElement->InsertEndChild(queryAttrElement); 

        std::string attrName = fdp.ConsumeRandomLengthString(32); 
        
        enum class AttrScenario { SET_DOUBLE, SET_INVALID_STRING, DONT_SET };
        AttrScenario scenario = fdp.PickValueInArray<AttrScenario>({
            AttrScenario::SET_DOUBLE, AttrScenario::SET_INVALID_STRING, AttrScenario::DONT_SET 
        });

        if (scenario == AttrScenario::SET_DOUBLE) {
            queryAttrElement->SetAttribute(attrName.c_str(), fdp.ConsumeFloatingPoint<double>());
        } else if (scenario == AttrScenario::SET_INVALID_STRING) {
            std::string nonDoubleStr = fdp.ConsumeBool() ? "not-a-valid-double" : fdp.ConsumeRandomLengthString(5);
            queryAttrElement->SetAttribute(attrName.c_str(), nonDoubleStr.c_str());
        }
        
        double queryDoubleResult = 0.0;
        (void)queryAttrElement->QueryDoubleAttribute(attrName.c_str(), &queryDoubleResult);
        // Cover XMLElement::DoubleAttribute
        (void)queryAttrElement->DoubleAttribute(attrName.c_str(), fdp.ConsumeFloatingPoint<double>());


        std::string boolAttrName = fdp.ConsumeRandomLengthString(32);
        enum class BoolAttrScenario { SET_BOOL, SET_STRING_FOR_BOOL, DONT_SET };
        BoolAttrScenario boolScenario = fdp.PickValueInArray<BoolAttrScenario>({
            BoolAttrScenario::SET_BOOL, BoolAttrScenario::SET_STRING_FOR_BOOL, BoolAttrScenario::DONT_SET 
        });

        if (boolScenario == BoolAttrScenario::SET_BOOL) {
            queryAttrElement->SetAttribute(boolAttrName.c_str(), fdp.ConsumeBool());
        } else if (boolScenario == BoolAttrScenario::SET_STRING_FOR_BOOL) {
            queryAttrElement->SetAttribute(boolAttrName.c_str(), fdp.ConsumeBytesAsString(fdp.ConsumeIntegralInRange<size_t>(0, 8)).c_str());
        }
        
        bool queryBoolResultVal = false;
        (void)queryAttrElement->QueryBoolAttribute(boolAttrName.c_str(), &queryBoolResultVal);
        bool defaultBool = fdp.ConsumeBool();
        (void)queryAttrElement->BoolAttribute(boolAttrName.c_str(), defaultBool);

        std::string intAttrName = fdp.ConsumeRandomLengthString(32);
        int defaultIntValue = fdp.ConsumeIntegral<int>();
        int queryIntResultValStorage = 0; 
        
        if (fdp.ConsumeBool()) { 
            queryAttrElement->SetAttribute(intAttrName.c_str(), fdp.ConsumeIntegral<int>());
        } else if (fdp.ConsumeBool()) { 
            queryAttrElement->SetAttribute(intAttrName.c_str(), "not-an-integer");
        } 

        (void)queryAttrElement->QueryIntAttribute(intAttrName.c_str(), &queryIntResultValStorage);
        (void)queryAttrElement->IntAttribute(intAttrName.c_str(), defaultIntValue);
        
        std::string nonExistentIntAttr = fdp.ConsumeRandomLengthString(16) + "_nexInt";
        (void)queryAttrElement->QueryIntAttribute(nonExistentIntAttr.c_str(), &queryIntResultValStorage);
        (void)queryAttrElement->IntAttribute(nonExistentIntAttr.c_str(), defaultIntValue);

        std::string i64AttrName = fdp.ConsumeRandomLengthString(32);
        int64_t defaultI64Value = fdp.ConsumeIntegral<int64_t>();
        int64_t queryI64ResultVal = 0;
        if (fdp.ConsumeBool()) {
            queryAttrElement->SetAttribute(i64AttrName.c_str(), fdp.ConsumeIntegral<int64_t>());
        } else if (fdp.ConsumeBool()) {
            queryAttrElement->SetAttribute(i64AttrName.c_str(), "not-an-int64-value");
        }
        (void)queryAttrElement->QueryInt64Attribute(i64AttrName.c_str(), &queryI64ResultVal);
        (void)queryAttrElement->Int64Attribute(i64AttrName.c_str(), defaultI64Value);
        
        // Cover XMLElement::[Query]Unsigned64Attribute and SetAttribute(..., uint64_t)
        std::string u64AttrName = fdp.ConsumeRandomLengthString(32);
        uint64_t defaultU64Value = fdp.ConsumeIntegral<uint64_t>();
        uint64_t queryU64ResultVal = 0;
        if (fdp.ConsumeBool()) {
            queryAttrElement->SetAttribute(u64AttrName.c_str(), fdp.ConsumeIntegral<uint64_t>()); // Covers SetAttribute for uint64_t
        } else if (fdp.ConsumeBool()) {
            queryAttrElement->SetAttribute(u64AttrName.c_str(), "not-an-u64-value");
        }
        (void)queryAttrElement->QueryUnsigned64Attribute(u64AttrName.c_str(), &queryU64ResultVal); // Cover QueryUnsigned64Attribute
        (void)queryAttrElement->Unsigned64Attribute(u64AttrName.c_str(), defaultU64Value); // Cover Unsigned64Attribute


        std::string uAttrName = fdp.ConsumeRandomLengthString(32);
        unsigned int defaultUValue = fdp.ConsumeIntegral<unsigned int>();
        unsigned int queryUResultVal = 0;
        if (fdp.ConsumeBool()) {
            queryAttrElement->SetAttribute(uAttrName.c_str(), fdp.ConsumeIntegral<unsigned int>());
        } else if (fdp.ConsumeBool()) {
            queryAttrElement->SetAttribute(uAttrName.c_str(), "not-an-unsigned-value");
        }
        (void)queryAttrElement->QueryUnsignedAttribute(uAttrName.c_str(), &queryUResultVal);
        (void)queryAttrElement->UnsignedAttribute(uAttrName.c_str(), defaultUValue);
        
        std::string floatAttrName = fdp.ConsumeRandomLengthString(32);
        float defaultFloatValue = fdp.ConsumeFloatingPoint<float>();
        float queryFloatResultVal = 0.0f;
        if (fdp.ConsumeBool()) {
            queryAttrElement->SetAttribute(floatAttrName.c_str(), fdp.ConsumeFloatingPoint<float>());
        } else if (fdp.ConsumeBool()) {
            queryAttrElement->SetAttribute(floatAttrName.c_str(), "not-a-float-value");
        }
        (void)queryAttrElement->QueryFloatAttribute(floatAttrName.c_str(), &queryFloatResultVal);
        (void)queryAttrElement->FloatAttribute(floatAttrName.c_str(), defaultFloatValue);

        // Cover XMLElement::DeleteAttribute
        // Provide a non-null, possibly empty or non-matching, string.
        std::string attrNameToDelete = fdp.ConsumeRandomLengthString(16);
        queryAttrElement->DeleteAttribute(attrNameToDelete.c_str());
    }


    if (setTextElement) { 
        (void)setTextElement->NextSiblingElement();

        std::string searchName;
        if (queryAttrElement && !childNameForQueryAttr.empty() && fdp.ConsumeBool()) {
            searchName = childNameForQueryAttr; 
        } else {
            searchName = fdp.ConsumeRandomLengthString(32); 
        }
        (void)setTextElement->NextSiblingElement(searchName.c_str());
    }

    // Cover XMLElement::ShallowEqual (0% coverage) and by extension XMLElement::FirstAttribute (0% coverage)
    // Memory for el1, el2, and their attributes is managed by doc.
    if (fdp.ConsumeBool() && rootElement) {
        XMLElement* el1 = doc.NewElement(fdp.ConsumeRandomLengthString(16).c_str());
        XMLElement* el2 = doc.NewElement(fdp.ConsumeRandomLengthString(16).c_str());
        if (el1 && el2) {
            rootElement->InsertEndChild(el1);
            rootElement->InsertEndChild(el2);
            if (fdp.ConsumeBool()) { // Maybe add attributes
                el1->SetAttribute(fdp.ConsumeRandomLengthString(8).c_str(), fdp.ConsumeRandomLengthString(8).c_str());
                if (fdp.ConsumeBool()) { // el2 gets same attributes or different
                     el2->SetAttribute(fdp.ConsumeRandomLengthString(8).c_str(), fdp.ConsumeRandomLengthString(8).c_str());
                } else {
                    // Make el2 attributes same as el1 for a potential true return from ShallowEqual
                    if (const XMLAttribute* attr1 = el1->FirstAttribute()) {
                         el2->SetAttribute(attr1->Name(), attr1->Value());
                    }
                }
            }
            if (fdp.ConsumeBool()) { // Make names same for a potential true return
                el2->SetName(el1->Name());
            }
            (void)el1->ShallowEqual(el2);
            (void)el1->ShallowEqual(el1); // Test equality with self
            XMLComment* shallowEqualCommentNode = doc.NewComment("not an element");
            if (shallowEqualCommentNode) {
                 (void)el1->ShallowEqual(shallowEqualCommentNode); // Test with different node type
            }
        }
    }

    // Cover XMLNode::PreviousSiblingElement, XMLNode::LastChildElement, XMLNode::ChildElementCount
    // Memory for parentNode and children is managed by doc/rootElement.
    if (fdp.ConsumeBool() && rootElement) {
        XMLElement* navParent = doc.NewElement("navParent");
        if (navParent) {
            rootElement->InsertEndChild(navParent);
            XMLElement* c1 = doc.NewElement(fdp.ConsumeRandomLengthString(8).c_str());
            XMLElement* c2 = doc.NewElement(fdp.ConsumeRandomLengthString(8).c_str());
            XMLElement* c3 = doc.NewElement(fdp.ConsumeRandomLengthString(8).c_str());

            if (c1 && c2 && c3) {
                navParent->InsertEndChild(c1);
                navParent->InsertEndChild(c2);
                navParent->InsertEndChild(c3);

                // PreviousSiblingElement
                (void)c2->PreviousSiblingElement();
                (void)c2->PreviousSiblingElement(c1->Name());
                (void)c2->PreviousSiblingElement("non_existent_prev_sib");
                (void)c1->PreviousSiblingElement(); // Should be null

                // LastChildElement
                (void)navParent->LastChildElement();
                (void)navParent->LastChildElement(c3->Name());
                (void)navParent->LastChildElement("non_existent_last_child");
                
                // ChildElementCount
                (void)navParent->ChildElementCount();
                (void)navParent->ChildElementCount(c1->Name()); // Count specific name
                (void)navParent->ChildElementCount("non_existent_child_count");
            }
             // Test with no children
            XMLElement* emptyParent = doc.NewElement("emptyNavParent");
            if (emptyParent) {
                rootElement->InsertEndChild(emptyParent);
                (void)emptyParent->LastChildElement();
                (void)emptyParent->ChildElementCount();
            }
        }
    }
    
    // Cover specific branches in XMLNode::Unlink (child->_prev != nullptr) and XMLNode::InsertChildPreamble (node already has a parent)
    // Memory for these nodes is managed by doc/rootElement.
    if (fdp.ConsumeBool() && rootElement) {
        XMLElement* p_unlink = doc.NewElement("p_unlink");
        XMLElement* c1_unlink = doc.NewElement("c1_unlink");
        XMLElement* c2_unlink = doc.NewElement("c2_unlink");
        if (p_unlink && c1_unlink && c2_unlink) {
            rootElement->InsertEndChild(p_unlink);
            p_unlink->InsertEndChild(c1_unlink);
            p_unlink->InsertEndChild(c2_unlink); // c2_unlink->_prev is c1_unlink
            if (fdp.ConsumeBool()) {
                 p_unlink->DeleteChild(c2_unlink); // Covers Unlink where child->_prev is not null (line 901)
            } else {
                 p_unlink->DeleteChild(c1_unlink); // Covers Unlink where child->_prev is null but child->_next is not (line 904)
            }
        }

        XMLElement* p1_reparent = doc.NewElement("p1_reparent");
        XMLElement* child_reparent = doc.NewElement("child_reparent");
        XMLElement* p2_reparent = doc.NewElement("p2_reparent");
        if (p1_reparent && child_reparent && p2_reparent) {
            rootElement->InsertEndChild(p1_reparent);
            rootElement->InsertEndChild(p2_reparent);
            p1_reparent->InsertEndChild(child_reparent); // child_reparent's parent is p1_reparent
            if (fdp.ConsumeBool()) {
                // Move child_reparent to p2_reparent.
                // This covers InsertChildPreamble where insertThis->_parent is not null (line 1209).
                p2_reparent->InsertEndChild(child_reparent);
            }
        }
    }


    std::string getTextElementName = fdp.ConsumeRandomLengthString(32);
    XMLElement* getTextElement = doc.NewElement(getTextElementName.c_str());
    if (getTextElement) {
        rootElement->InsertEndChild(getTextElement); 

        int structure_type = fdp.ConsumeIntegralInRange<int>(0, 4);

        if (structure_type == 1) { 
            XMLText* text = doc.NewText(fdp.ConsumeRandomLengthString(16).c_str());
            if (text) getTextElement->InsertFirstChild(text);
        } else if (structure_type == 2) { 
            XMLComment* comment = doc.NewComment(fdp.ConsumeRandomLengthString(16).c_str());
            if (comment) getTextElement->InsertFirstChild(comment);
        } else if (structure_type == 3) { 
            XMLComment* comment = doc.NewComment(fdp.ConsumeRandomLengthString(16).c_str());
            if (comment) getTextElement->InsertFirstChild(comment); 
            XMLText* text = doc.NewText(fdp.ConsumeRandomLengthString(16).c_str());
            if (text) getTextElement->InsertEndChild(text); 
        } else if (structure_type == 4) { 
            XMLComment* comment = doc.NewComment(fdp.ConsumeRandomLengthString(16).c_str());
            if (comment) getTextElement->InsertFirstChild(comment); 
            XMLElement* otherEl = doc.NewElement(fdp.ConsumeRandomLengthString(16).c_str());
            if (otherEl) getTextElement->InsertEndChild(otherEl); 
        }
        
        (void)getTextElement->GetText(); 
    }


    std::string boolStr = fdp.ConsumeRandomLengthString(10); 
    bool outBoolVal = false; 
    (void)XMLUtil::ToBool(boolStr.c_str(), &outBoolVal);

    // doc goes out of scope here, and its destructor will clean up all allocated nodes,
    // including unlinked ones, ensuring no memory leaks.
    return 0;
}