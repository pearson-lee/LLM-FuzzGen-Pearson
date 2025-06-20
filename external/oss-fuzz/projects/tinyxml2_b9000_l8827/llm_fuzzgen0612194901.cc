#include "/src/tinyxml2/tinyxml2.h" // Using project-relative path for tinyxml2 header

#include <cstddef> // For size_t
#include <cstdint> // For uint8_t
#include <string>  // For std::string
#include <vector>  // For std::vector in XMLPrinter section, if needed for complex scenarios (not strictly needed for these changes)

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
// This Fuzzer Version Enhancements:
// - Added XMLPrinter coverage for PushHeader, PushAttribute (various types), PushText (various types), Print/Accept, CStr, CStrSize, ClearBuffer.
// - Added XMLDocument error reporting coverage (PrintError, ErrorStr, ErrorName) by inducing parse errors.
// - Enhanced XML parsing input for StrPair::GetStr() to cover XMLUtil::ReadBOM (UTF-8 BOM), XMLUtil::GetCharacterRef (hex/multibyte entities), XMLDocument::Identify (CDATA), XMLText::ParseDeep (CDATA).
// - Refined XMLElement::ShallowEqual attribute generation to better cover attribute count mismatches.
// - Added tests for XMLDocument::Parse() with nullptr and empty string inputs.
// - Added test for XMLDocument max parsing depth (XML_ELEMENT_DEPTH_EXCEEDED).
// This Fuzzer Version Enhancements (Post-System-Prompt):
// - Added coverage for const versions of XMLDeclaration::ToDeclaration(), XMLUnknown::ToUnknown(),
//   XMLNode::ToDeclaration() (const), and XMLNode::ToUnknown() (const).
// - Enhanced XML parsing input to cover more branches in XMLUtil::ConvertUTF32ToUTF8 and XMLUtil::GetCharacterRef
//   by adding specific Unicode character references (2-byte and out-of-range).

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
        // This path is unlikely to be hit without OOM, existing coverage shows 0.
        return 0; 
    }
    doc.InsertFirstChild(rootElement);

    // Section for XMLDocument::Clear() unlinked node coverage
    if (fdp.ConsumeBool()) {
        (void)doc.NewElement("unlinked_el_for_clear_test"); 
    }
    if (fdp.ConsumeBool()) {
        (void)doc.NewComment("unlinked_comment_for_clear_test");
    }
    if (fdp.ConsumeBool()) {
        (void)doc.NewText("unlinked_text_for_clear_test");
    }


    // Section for StrPair::GetStr() entity/newline/whitespace processing & other parsing coverage
    if (fdp.ConsumeBool()) {
        XMLDocument parseDoc(true, fdp.ConsumeBool() ? COLLAPSE_WHITESPACE : PRESERVE_WHITESPACE);
        std::string xmlToParse;

        // Coverage: XMLUtil::ReadBOM (lines 409-411 in tinyxml2.cpp)
        if (fdp.ConsumeBool()) { 
            xmlToParse += "\xEF\xBB\xBF"; // UTF-8 BOM
        }

        if (fdp.ConsumeBool()) { // Create minimal content to test BOM/whitespace only parse
             if (xmlToParse.empty() && fdp.ConsumeBool()) { // only whitespace if no BOM
                xmlToParse = "   \t\n";
             }
             // If xmlToParse is just BOM or just whitespace, it tests XMLDocument::Parse() empty after BOM/whitespace (lines 2560-2562)
        } else { // Create more complex XML
            xmlToParse += "<docRoot ";
            // Coverage: XMLUtil::GetCharacterRef hex/multibyte entities (lines 520-524, 538-539, 544-545), XMLUtil::ConvertUTF32ToUTF8 (lines 426-438)
            // Added &#162; (0xA2, 2-byte UTF-8) and &#x200000; (out of Unicode range) for XMLUtil::ConvertUTF32ToUTF8 and XMLUtil::GetCharacterRef coverage.
            xmlToParse += "attrName='" + fdp.ConsumeBytesAsString(5) + " &amp; &#65; &#162; &#20013; &#x4E2D; &#x0A; &#x10000; &#x200000; \r\n " + fdp.ConsumeBytesAsString(5) + "&apos;" + "' ";
            xmlToParse += "hexAttr='&#xAbC; &#x10fFfF; &#x1FFFFF; &#x200000;' "; // Test hex, valid U+10FFFF, invalid U+1FFFFF, and out of range U+200000
            xmlToParse += ">";
            xmlToParse += fdp.ConsumeBytesAsString(5) + " &lt; text &#36; content &gt; \n " + fdp.ConsumeBytesAsString(5);
            // Coverage: XMLDocument::Identify for CDATA (lines 742-747), XMLText::ParseDeep for CDATA (lines 1236-1241)
            if (fdp.ConsumeBool()) {
                xmlToParse += "<![CDATA[ This is some <CDATA> text with entities &amp; stuff. ]]>";
            }
            // Induce error for error reporting coverage
            if (fdp.ConsumeBool()) {
                xmlToParse += "<unclosedTag"; 
            }
            xmlToParse += "</docRoot>";
        }

        parseDoc.Parse(xmlToParse.c_str()); 

        // Coverage: XMLDocument error reporting (PrintError, ErrorStr, ErrorName)
        if (parseDoc.Error()) {
            parseDoc.PrintError();  // Cover PrintError
            (void)parseDoc.ErrorStr();  // Cover ErrorStr
            (void)parseDoc.ErrorName(); // Cover ErrorName
        }

        if (XMLElement* parsedRoot = parseDoc.RootElement()) {
            (void)parsedRoot->Name(); 
            if (const XMLAttribute* attr = parsedRoot->FirstAttribute()) { 
                (void)attr->Name();  
                (void)attr->Value(); 
            }
            (void)parsedRoot->GetText(); 
        }
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
    if (firstComment && fdp.ConsumeBool()) { 
        (void)firstComment->ToComment();
    }


    if (fdp.ConsumeBool() && firstComment) { 
        std::string anotherChildName = fdp.ConsumeRandomLengthString(32);
        XMLElement* anotherChildElement = doc.NewElement(anotherChildName.c_str());
        if (anotherChildElement) {
            rootElement->InsertFirstChild(anotherChildElement); 
        }
    }

    if (fdp.ConsumeBool()) {
        XMLDeclaration* decl = rootElement->InsertNewDeclaration(fdp.ConsumeRandomLengthString(30).c_str());
        if (decl) { // Ensure decl is not null before using
            if (fdp.ConsumeBool()) {
                (void)decl->ToDeclaration(); // Original call (XMLDeclaration::ToDeclaration() non-const)
            }
            // Coverage for const XMLDeclaration* XMLDeclaration::ToDeclaration() const
            if (fdp.ConsumeBool()) {
                const XMLDeclaration* constDecl = decl;
                (void)constDecl->ToDeclaration(); 
            }
            // Coverage for const XMLDeclaration* XMLNode::ToDeclaration() const (via virtual call to XMLDeclaration::ToDeclaration() const)
            if (fdp.ConsumeBool()) {
                const XMLNode* constNode = decl; 
                (void)constNode->ToDeclaration(); 
            }
        }
    }
    if (fdp.ConsumeBool()) {
        XMLText* textNode = rootElement->InsertNewText(fdp.ConsumeRandomLengthString(30).c_str());
        if (textNode && fdp.ConsumeBool()) (void)textNode->ToText(); 
    }
    if (fdp.ConsumeBool()) {
        XMLUnknown* unknown = rootElement->InsertNewUnknown(fdp.ConsumeRandomLengthString(30).c_str());
        if (unknown) { // Ensure unknown is not null
            if (fdp.ConsumeBool()) {
                (void)unknown->ToUnknown(); // Original call (XMLUnknown::ToUnknown() non-const)
            }
            // Coverage for const XMLUnknown* XMLUnknown::ToUnknown() const
            if (fdp.ConsumeBool()) {
                const XMLUnknown* constUnknown = unknown;
                (void)constUnknown->ToUnknown(); 
            }
            // Coverage for const XMLUnknown* XMLNode::ToUnknown() const (via virtual call to XMLUnknown::ToUnknown() const)
            if (fdp.ConsumeBool()) {
                const XMLNode* constNode = unknown;
                (void)constNode->ToUnknown();
            }
        }
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

        bool bValText;
        (void)setTextElement->QueryBoolText(&bValText); 
        (void)setTextElement->BoolText(fdp.ConsumeBool()); 

        int iValText;
        (void)setTextElement->QueryIntText(&iValText); 
        (void)setTextElement->IntText(fdp.ConsumeIntegral<int>()); 

        unsigned uValText;
        (void)setTextElement->QueryUnsignedText(&uValText); 
        (void)setTextElement->UnsignedText(fdp.ConsumeIntegral<unsigned int>()); 
        
        int64_t i64ValText;
        (void)setTextElement->QueryInt64Text(&i64ValText); 
        (void)setTextElement->Int64Text(fdp.ConsumeIntegral<int64_t>()); 

        uint64_t u64ValText;
        (void)setTextElement->QueryUnsigned64Text(&u64ValText); 
        (void)setTextElement->Unsigned64Text(fdp.ConsumeIntegral<uint64_t>()); 

        float fValText;
        (void)setTextElement->QueryFloatText(&fValText); 
        (void)setTextElement->FloatText(fdp.ConsumeFloatingPoint<float>()); 
        
        (void)setTextElement->DoubleText(fdp.ConsumeFloatingPoint<double>()); 


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
        
        std::string u64AttrName = fdp.ConsumeRandomLengthString(32);
        uint64_t defaultU64Value = fdp.ConsumeIntegral<uint64_t>();
        uint64_t queryU64ResultVal = 0;
        if (fdp.ConsumeBool()) {
            queryAttrElement->SetAttribute(u64AttrName.c_str(), fdp.ConsumeIntegral<uint64_t>()); 
        } else if (fdp.ConsumeBool()) {
            queryAttrElement->SetAttribute(u64AttrName.c_str(), "not-an-u64-value");
        }
        (void)queryAttrElement->QueryUnsigned64Attribute(u64AttrName.c_str(), &queryU64ResultVal); 
        (void)queryAttrElement->Unsigned64Attribute(u64AttrName.c_str(), defaultU64Value); 


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

    // Cover XMLElement::ShallowEqual attribute count mismatch (lines 2135-2136 in tinyxml2.cpp)
    if (fdp.ConsumeBool() && rootElement) {
        XMLElement* el1 = doc.NewElement(fdp.ConsumeRandomLengthString(16).c_str());
        XMLElement* el2 = doc.NewElement(fdp.ConsumeRandomLengthString(16).c_str());
        if (el1 && el2) {
            rootElement->InsertEndChild(el1);
            rootElement->InsertEndChild(el2);
            
            // Create different attribute counts for el1 and el2
            if (fdp.ConsumeBool()) {
                int el1_attrs_count = fdp.ConsumeIntegralInRange(0, 2);
                for (int i = 0; i < el1_attrs_count; ++i) {
                    el1->SetAttribute((std::string("el1_attr") + std::to_string(i)).c_str(), fdp.ConsumeRandomLengthString(5).c_str());
                }
                int el2_attrs_count = fdp.ConsumeIntegralInRange(0, 2);
                 // Ensure counts are different if both are non-zero, or one is zero and other non-zero
                if (el1_attrs_count > 0 && el2_attrs_count > 0 && el1_attrs_count == el2_attrs_count && fdp.ConsumeBool()) {
                    el2_attrs_count = (el1_attrs_count == 1) ? 2 : 1; // Make them different if they were same
                } else if (el1_attrs_count == 0 && el2_attrs_count == 0 && fdp.ConsumeBool()) {
                    el1_attrs_count = 1; // Make one non-zero
                }


                for (int i = 0; i < el2_attrs_count; ++i) {
                     // For a possible true return from ShallowEqual (if names and counts match), try to make attributes identical
                    bool try_match_attributes = (el1_attrs_count == el2_attrs_count) && fdp.ConsumeBool();
                    if (try_match_attributes) {
                        const XMLAttribute* el1_corresp_attr = el1->FirstAttribute();
                        for(int k=0; k<i && el1_corresp_attr; ++k) el1_corresp_attr = el1_corresp_attr->Next();
                        
                        if(el1_corresp_attr) {
                            el2->SetAttribute(el1_corresp_attr->Name(), el1_corresp_attr->Value());
                        } else { // Fallback if el1 doesn't have this attribute
                             el2->SetAttribute((std::string("el2_attr") + std::to_string(i)).c_str(), fdp.ConsumeRandomLengthString(5).c_str());
                        }
                    } else {
                        el2->SetAttribute((std::string("el2_attr") + std::to_string(i)).c_str(), fdp.ConsumeRandomLengthString(5).c_str());
                    }
                }
            }

            if (fdp.ConsumeBool()) { // Make names same for a potential true return
                el2->SetName(el1->Name());
            }
            (void)el1->ShallowEqual(el2);
            (void)el1->ShallowEqual(el1); 
            XMLComment* shallowEqualCommentNode = doc.NewComment("not an element for shallowequal");
            if (shallowEqualCommentNode) {
                 // This node is unlinked and managed by 'doc' for cleanup.
                 (void)el1->ShallowEqual(shallowEqualCommentNode); 
            }
        }
    }

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

                (void)c2->PreviousSiblingElement();
                (void)c2->PreviousSiblingElement(c1->Name());
                (void)c2->PreviousSiblingElement("non_existent_prev_sib");
                (void)c1->PreviousSiblingElement(); 

                (void)navParent->LastChildElement();
                (void)navParent->LastChildElement(c3->Name());
                (void)navParent->LastChildElement("non_existent_last_child");
                
                (void)navParent->ChildElementCount();
                (void)navParent->ChildElementCount(c1->Name()); 
                (void)navParent->ChildElementCount("non_existent_child_count");
            }
            XMLElement* emptyParent = doc.NewElement("emptyNavParent");
            if (emptyParent) {
                rootElement->InsertEndChild(emptyParent);
                (void)emptyParent->LastChildElement();
                (void)emptyParent->ChildElementCount();
            }
        }
    }
    
    if (fdp.ConsumeBool() && rootElement) {
        XMLElement* p_unlink = doc.NewElement("p_unlink");
        XMLElement* c1_unlink = doc.NewElement("c1_unlink");
        XMLElement* c2_unlink = doc.NewElement("c2_unlink");
        if (p_unlink && c1_unlink && c2_unlink) {
            rootElement->InsertEndChild(p_unlink);
            p_unlink->InsertEndChild(c1_unlink);
            p_unlink->InsertEndChild(c2_unlink); 
            if (fdp.ConsumeBool()) {
                 p_unlink->DeleteChild(c2_unlink); 
            } else {
                 p_unlink->DeleteChild(c1_unlink); 
            }
        }

        XMLElement* p1_reparent = doc.NewElement("p1_reparent");
        XMLElement* child_reparent = doc.NewElement("child_reparent");
        XMLElement* p2_reparent = doc.NewElement("p2_reparent");
        if (p1_reparent && child_reparent && p2_reparent) {
            rootElement->InsertEndChild(p1_reparent);
            rootElement->InsertEndChild(p2_reparent);
            p1_reparent->InsertEndChild(child_reparent); 
            if (fdp.ConsumeBool()) {
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

    // --- Start XMLPrinter Coverage ---
    // Covers various XMLPrinter methods (PushHeader, PushAttribute, PushText, Print/Accept, CStr, CStrSize, ClearBuffer)
    if (fdp.ConsumeBool()) {
        XMLPrinter printer(nullptr, fdp.ConsumeBool()); // FILE* is null, control compactness. Printer is stack-allocated, RAII.

        printer.PushHeader(fdp.ConsumeBool(), fdp.ConsumeBool());

        std::string attrNameForPrinter = fdp.ConsumeRandomLengthString(16);
        if (!attrNameForPrinter.empty()) {
            printer.PushAttribute(attrNameForPrinter.c_str(), fdp.ConsumeRandomLengthString(16).c_str());
            printer.PushAttribute(attrNameForPrinter.c_str(), fdp.ConsumeIntegral<int>());
            printer.PushAttribute(attrNameForPrinter.c_str(), fdp.ConsumeIntegral<unsigned int>());
            printer.PushAttribute(attrNameForPrinter.c_str(), fdp.ConsumeIntegral<int64_t>());
            printer.PushAttribute(attrNameForPrinter.c_str(), fdp.ConsumeIntegral<uint64_t>());
            printer.PushAttribute(attrNameForPrinter.c_str(), fdp.ConsumeBool());
            printer.PushAttribute(attrNameForPrinter.c_str(), fdp.ConsumeFloatingPoint<double>());
        }

        printer.PushText(fdp.ConsumeRandomLengthString(20).c_str(), fdp.ConsumeBool()); // text, cdata
        printer.PushText(fdp.ConsumeIntegral<int>());
        printer.PushText(fdp.ConsumeIntegral<unsigned int>());
        printer.PushText(fdp.ConsumeIntegral<int64_t>());
        printer.PushText(fdp.ConsumeIntegral<uint64_t>());
        printer.PushText(fdp.ConsumeBool());
        printer.PushText(fdp.ConsumeFloatingPoint<float>());
        printer.PushText(fdp.ConsumeFloatingPoint<double>());

        if (fdp.ConsumeBool()) {
            doc.Print(&printer);
        } else if (rootElement) {
            rootElement->Accept(&printer);
        }
        
        (void)printer.CStr();
        (void)printer.CStrSize(); 
        printer.ClearBuffer(); 
    }
    // --- End XMLPrinter Coverage ---

    // --- Start XMLDocument::Parse() with empty/null input coverage ---
    // Covers XMLDocument::Parse(nullptr/empty, 0) (lines 2452-2454 in tinyxml2.cpp)
    if (fdp.ConsumeBool()) {
        XMLDocument testDocEmpty; // RAII for testDocEmpty
        if (fdp.ConsumeBool()) {
            testDocEmpty.Parse(nullptr, 0); 
        } else {
            testDocEmpty.Parse("", 0); 
        }
        if (testDocEmpty.Error()) { // Also covers error reporting functions
            testDocEmpty.PrintError();
            (void)testDocEmpty.ErrorStr();
            (void)testDocEmpty.ErrorName();
        }
    }
    // --- End XMLDocument::Parse() with empty/null input coverage ---

    // --- Start XMLDocument max depth parsing test ---
    // Covers XMLDocument::PushDepth() for XML_ELEMENT_DEPTH_EXCEEDED (lines 2570-2571 in tinyxml2.cpp)
    if (fdp.ConsumeBool()) {
        XMLDocument depthDoc; // RAII for depthDoc
        std::string depthXml;
        // TINYXML2_MAX_ELEMENT_DEPTH is typically 100. Go slightly over.
        int depth = TINYXML2_MAX_ELEMENT_DEPTH + fdp.ConsumeIntegralInRange(1, 5); 
        for (int i = 0; i < depth; ++i) {
            depthXml += "<d>";
        }
        depthXml += "text"; // Some content in the middle
        for (int i = 0; i < depth; ++i) {
            depthXml += "</d>";
        }
        depthDoc.Parse(depthXml.c_str());
        if (depthDoc.Error()) { // Should be XML_ELEMENT_DEPTH_EXCEEDED. Also covers error reporting.
            depthDoc.PrintError();
            (void)depthDoc.ErrorStr();
            (void)depthDoc.ErrorName();
        }
    }
    // --- End XMLDocument max depth parsing test ---

    return 0;
}