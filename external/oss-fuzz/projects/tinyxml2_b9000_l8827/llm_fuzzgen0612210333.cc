#include "/src/tinyxml2/tinyxml2.h" // Using project-relative path for tinyxml2 header

#include <cstddef> // For size_t
#include <cstdint> // For uint8_t
#include <string>  // For std::string
#include <vector>  // For std::vector in XMLPrinter section, if needed for complex scenarios (not strictly needed for these changes)
#include <cstdio>  // For FILE, tmpfile, fclose (for XMLPrinter to FILE* coverage), snprintf

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
// This Fuzzer Version Enhancements (Coverage Driven):
// - Added coverage for XMLPrinter::Print(const char* format, ...)
// - Added coverage for XMLElement::Query...Text methods returning XML_NO_TEXT_NODE.
// - Added coverage for XMLPrinter::VisitEnter(const XMLDocument&) path where doc.HasBOM() is true.

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    std::string trueStrForSerialization;
    std::string falseStrForSerialization;

    XMLDocument doc; // Document object, RAII handles cleanup.

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
    XMLDocument parseDocForBOMTest(true, PRESERVE_WHITESPACE); // Keep this doc for BOM test with printer
    bool parsedDocWithBOM = false;

    if (fdp.ConsumeBool()) {
        XMLDocument parseDoc(true, fdp.ConsumeBool() ? COLLAPSE_WHITESPACE : PRESERVE_WHITESPACE); // Local parseDoc for general parsing tests
        std::string xmlToParse;

        // Coverage: XMLUtil::ReadBOM (lines 409-411 in tinyxml2.cpp)
        if (fdp.ConsumeBool()) { 
            xmlToParse += "\xEF\xBB\xBF"; // UTF-8 BOM
        }

        if (fdp.ConsumeBool()) { // Create minimal content to test BOM/whitespace only parse
             if (xmlToParse.empty() && fdp.ConsumeBool()) { // only whitespace if no BOM
                xmlToParse = "   \t\n";
             }
        } else { // Create more complex XML
            xmlToParse += "<docRoot ";
            xmlToParse += "attrName='" + fdp.ConsumeBytesAsString(5) + " &amp; &#65; &#162; &#20013; &#x4E2D; &#x0A; &#x10000; &#x200000; \r\n " + fdp.ConsumeBytesAsString(5) + "&apos;" + "' ";
            xmlToParse += "hexAttr='&#xAbC; &#x10fFfF; &#x1FFFFF; &#x200000;' "; 
            // Coverage for XMLUtil::GetCharacterRef error paths (lines 501, 506 in tinyxml2.cpp)
            if (fdp.ConsumeBool()) {
                xmlToParse += " malformed_entities='&#x; &#;' "; // No digits after #x or #
                xmlToParse += " no_semicolon='&#x41 " + fdp.ConsumeRandomLengthString(3) + "' "; // Missing semicolon
            }
            xmlToParse += ">";
            xmlToParse += fdp.ConsumeBytesAsString(5) + " &lt; text &#36; content &gt; \n " + fdp.ConsumeBytesAsString(5);
            if (fdp.ConsumeBool()) {
                xmlToParse += "<![CDATA[ This is some <CDATA> text with entities &amp; stuff. ]]>";
            }
            if (fdp.ConsumeBool()) {
                xmlToParse += "<unclosedTag"; 
            }
            xmlToParse += "</docRoot>";
        }

        parseDoc.Parse(xmlToParse.c_str()); 

        if (parseDoc.Error()) {
            parseDoc.PrintError();
            (void)parseDoc.ErrorStr();
            (void)parseDoc.ErrorName();
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
    
    std::string bomXmlForPrinter = "\xEF\xBB\xBF<bomRootPrinterTest><child/></bomRootPrinterTest>";
    parseDocForBOMTest.Parse(bomXmlForPrinter.c_str());
    if (!parseDocForBOMTest.Error() && parseDocForBOMTest.HasBOM()) {
        parsedDocWithBOM = true; 
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

    XMLDeclaration* firstDecl = nullptr;
    if (fdp.ConsumeBool()) {
        firstDecl = rootElement->InsertNewDeclaration(fdp.ConsumeRandomLengthString(30).c_str());
        if (firstDecl) { 
            if (fdp.ConsumeBool()) {
                (void)firstDecl->ToDeclaration(); 
            }
            if (fdp.ConsumeBool()) {
                const XMLDeclaration* constDecl = firstDecl;
                (void)constDecl->ToDeclaration(); 
            }
            if (fdp.ConsumeBool()) {
                const XMLNode* constNode = firstDecl; 
                (void)constNode->ToDeclaration(); 
            }
        }
    }
    XMLText* firstTextNode = nullptr;
    if (fdp.ConsumeBool()) {
        firstTextNode = rootElement->InsertNewText(fdp.ConsumeRandomLengthString(30).c_str());
        if (firstTextNode && fdp.ConsumeBool()) (void)firstTextNode->ToText(); 
    }
    XMLUnknown* unknown = nullptr; // Moved declaration to wider scope for ShallowClone test
    if (fdp.ConsumeBool()) {
        unknown = rootElement->InsertNewUnknown(fdp.ConsumeRandomLengthString(30).c_str());
        if (unknown) { 
            if (fdp.ConsumeBool()) {
                (void)unknown->ToUnknown(); 
            }
            if (fdp.ConsumeBool()) {
                const XMLUnknown* constUnknown = unknown;
                (void)constUnknown->ToUnknown(); 
            }
            if (fdp.ConsumeBool()) {
                const XMLNode* constNode = unknown;
                (void)constNode->ToUnknown();
            }
        }
    }


    XMLElement* setTextElement = nullptr;
    // Coverage for fuzzer line 664: make setTextElement conditional
    if (fdp.ConsumeBool()) {
        std::string childNameForSetText = fdp.ConsumeRandomLengthString(32);
        setTextElement = doc.NewElement(childNameForSetText.c_str());
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
    }


    if (fdp.ConsumeBool()) {
        XMLElement* noTextQueryEl = doc.NewElement(fdp.ConsumeRandomLengthString(16).c_str());
        if (noTextQueryEl) {
            rootElement->InsertEndChild(noTextQueryEl); 

            if (fdp.ConsumeBool()) { 
                XMLComment* c = doc.NewComment("comment child for noTextQueryEl");
                if (c) noTextQueryEl->InsertFirstChild(c); 
            }

            bool bVal = false; int iVal = 0; unsigned uVal = 0; int64_t i64Val = 0; uint64_t u64Val = 0; float fVal = 0.0f; double dVal = 0.0;
            (void)noTextQueryEl->QueryBoolText(&bVal);
            (void)noTextQueryEl->QueryIntText(&iVal);
            (void)noTextQueryEl->QueryUnsignedText(&uVal);
            (void)noTextQueryEl->QueryInt64Text(&i64Val);
            (void)noTextQueryEl->QueryUnsigned64Text(&u64Val);
            (void)noTextQueryEl->QueryFloatText(&fVal);
            (void)noTextQueryEl->QueryDoubleText(&dVal); 

            (void)noTextQueryEl->BoolText(fdp.ConsumeBool());
            (void)noTextQueryEl->IntText(fdp.ConsumeIntegral<int>());
            (void)noTextQueryEl->UnsignedText(fdp.ConsumeIntegral<unsigned int>());
            (void)noTextQueryEl->Int64Text(fdp.ConsumeIntegral<int64_t>());
            (void)noTextQueryEl->Unsigned64Text(fdp.ConsumeIntegral<uint64_t>());
            (void)noTextQueryEl->FloatText(fdp.ConsumeFloatingPoint<float>());
            (void)noTextQueryEl->DoubleText(fdp.ConsumeFloatingPoint<double>());
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

    if (fdp.ConsumeBool() && rootElement) {
        XMLElement* el1 = doc.NewElement(fdp.ConsumeRandomLengthString(16).c_str());
        XMLElement* el2 = doc.NewElement(fdp.ConsumeRandomLengthString(16).c_str());
        if (el1 && el2) {
            rootElement->InsertEndChild(el1);
            rootElement->InsertEndChild(el2);
            
            if (fdp.ConsumeBool()) {
                int el1_attrs_count = fdp.ConsumeIntegralInRange(0, 2);
                for (int i = 0; i < el1_attrs_count; ++i) {
                    el1->SetAttribute((std::string("el1_attr") + std::to_string(i)).c_str(), fdp.ConsumeRandomLengthString(5).c_str());
                }
                int el2_attrs_count = fdp.ConsumeIntegralInRange(0, 2);
                if (el1_attrs_count > 0 && el2_attrs_count > 0 && el1_attrs_count == el2_attrs_count && fdp.ConsumeBool()) {
                    el2_attrs_count = (el1_attrs_count == 1) ? 2 : 1; 
                } else if (el1_attrs_count == 0 && el2_attrs_count == 0 && fdp.ConsumeBool()) {
                    // el1_attrs_count = 1; // Keep this commented to allow el1_attrs_count == 0 && el2_attrs_count == 0
                }


                for (int i = 0; i < el2_attrs_count; ++i) {
                    bool try_match_attributes = (el1_attrs_count == el2_attrs_count) && fdp.ConsumeBool();
                    if (try_match_attributes) {
                        const XMLAttribute* el1_corresp_attr = el1->FirstAttribute();
                        for(int k=0; k<i && el1_corresp_attr; ++k) el1_corresp_attr = el1_corresp_attr->Next();
                        
                        if(el1_corresp_attr) {
                            el2->SetAttribute(el1_corresp_attr->Name(), el1_corresp_attr->Value());
                        } 
                        // else { // This branch (fuzzer line 475) is unreachable with current logic.
                        //      el2->SetAttribute((std::string("el2_attr") + std::to_string(i)).c_str(), fdp.ConsumeRandomLengthString(5).c_str());
                        // }
                    } else {
                        el2->SetAttribute((std::string("el2_attr") + std::to_string(i)).c_str(), fdp.ConsumeRandomLengthString(5).c_str());
                    }
                }
            }

            if (fdp.ConsumeBool()) { 
                el2->SetName(el1->Name());
            }
            (void)el1->ShallowEqual(el2);
            (void)el1->ShallowEqual(el1); 
            XMLComment* shallowEqualCommentNode = doc.NewComment("not an element for shallowequal");
            if (shallowEqualCommentNode) {
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
    if (fdp.ConsumeBool()) {
        XMLPrinter printer(nullptr, fdp.ConsumeBool()); 

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

        printer.PushText(fdp.ConsumeRandomLengthString(20).c_str(), fdp.ConsumeBool()); 
        printer.PushText(fdp.ConsumeIntegral<int>());
        printer.PushText(fdp.ConsumeIntegral<unsigned int>());
        printer.PushText(fdp.ConsumeIntegral<int64_t>());
        printer.PushText(fdp.ConsumeIntegral<uint64_t>());
        printer.PushText(fdp.ConsumeBool());
        printer.PushText(fdp.ConsumeFloatingPoint<float>());
        printer.PushText(fdp.ConsumeFloatingPoint<double>());
        
        // Coverage for XMLPrinter::Print(const char* format, ...)
        // Corrected to use PushComment for adding formatted comments
        if (fdp.ConsumeBool()) {
            std::string randomCommentStr = fdp.ConsumeRandomLengthString(10);
            int randomCommentInt = fdp.ConsumeIntegral<int>();
            char commentBuffer[256]; 
            snprintf(commentBuffer, sizeof(commentBuffer), " Fuzzer random comment: %s value=%d ", 
                     randomCommentStr.c_str(), 
                     randomCommentInt);
            printer.PushComment(commentBuffer);
        }

        bool printedSpecificDoc = false;
        if (parsedDocWithBOM && fdp.ConsumeBool()) { 
            parseDocForBOMTest.Print(&printer); 
            printedSpecificDoc = true;
        }

        if (!printedSpecificDoc) { 
            if (fdp.ConsumeBool()) {
                doc.Print(&printer);
            } else if (rootElement) {
                rootElement->Accept(&printer);
            }
        }
        
        (void)printer.CStr();
        (void)printer.CStrSize(); 
        printer.ClearBuffer(); 
    }
    // --- End XMLPrinter Coverage ---

    // --- Start DeepClone Coverage ---
    if (fdp.ConsumeBool()) {
        XMLDocument clonedDoc; 

        if (rootElement && fdp.ConsumeBool()) {
            XMLNode* clonedRootNode = rootElement->DeepClone(&clonedDoc);
            if (clonedRootNode) {
                clonedDoc.InsertFirstChild(clonedRootNode); 
            }
        }

        if (firstComment && fdp.ConsumeBool()) {
            XMLNode* clonedCommentNode = firstComment->DeepClone(&clonedDoc);
            if (clonedCommentNode) {
                if (clonedDoc.RootElement()) {
                    clonedDoc.RootElement()->InsertEndChild(clonedCommentNode);
                } else {
                    clonedDoc.InsertFirstChild(clonedCommentNode);
                }
            }
        }
        
        XMLNode* originalTextNodeToClone = nullptr;
        if (setTextElement && setTextElement->FirstChild() && setTextElement->FirstChild()->ToText()) {
            originalTextNodeToClone = setTextElement->FirstChild();
        } else if (firstTextNode) { // This path is now reachable due to conditional setTextElement
            originalTextNodeToClone = firstTextNode;
        }

        if (originalTextNodeToClone && fdp.ConsumeBool()) {
             XMLNode* clonedTextNode = originalTextNodeToClone->DeepClone(&clonedDoc);
             if (clonedTextNode) {
                if (clonedDoc.RootElement()) {
                    clonedDoc.RootElement()->InsertEndChild(clonedTextNode);
                } else {
                    clonedDoc.InsertFirstChild(clonedTextNode);
                }
             }
        }
        
        if (firstDecl && fdp.ConsumeBool()) {
            XMLNode* clonedDeclNode = firstDecl->DeepClone(&clonedDoc);
            if (clonedDeclNode) {
                 if (clonedDoc.RootElement()) {
                     // if (clonedDoc.FirstChild() == nullptr) { // This branch (fuzzer line 682-683) is unreachable.
                     //    clonedDoc.InsertFirstChild(clonedDeclNode);
                     // } else {
                        clonedDoc.RootElement() ? clonedDoc.RootElement()->InsertEndChild(clonedDeclNode) : clonedDoc.InsertFirstChild(clonedDeclNode);
                     // }
                 } else {
                     clonedDoc.InsertFirstChild(clonedDeclNode);
                 }
            }
        }
    }
    // --- End DeepClone Coverage ---


    // --- Start XMLDocument::Parse() with empty/null input coverage ---
    if (fdp.ConsumeBool()) {
        XMLDocument testDocEmpty; 
        if (fdp.ConsumeBool()) {
            testDocEmpty.Parse(nullptr, 0); 
        } else {
            testDocEmpty.Parse("", 0); 
        }
        if (testDocEmpty.Error()) { 
            testDocEmpty.PrintError();
            (void)testDocEmpty.ErrorStr();
            (void)testDocEmpty.ErrorName();
        }
    }
    // --- End XMLDocument::Parse() with empty/null input coverage ---

    // --- Start XMLDocument max depth parsing test ---
    if (fdp.ConsumeBool()) {
        XMLDocument depthDoc; 
        std::string depthXml;
        int depth = TINYXML2_MAX_ELEMENT_DEPTH + fdp.ConsumeIntegralInRange(1, 5); 
        for (int i = 0; i < depth; ++i) {
            depthXml += "<d>";
        }
        depthXml += "text"; 
        for (int i = 0; i < depth; ++i) {
            depthXml += "</d>";
        }
        depthDoc.Parse(depthXml.c_str());
        if (depthDoc.Error()) { 
            depthDoc.PrintError();
            (void)depthDoc.ErrorStr();
            (void)depthDoc.ErrorName();
        }
    }
    // --- End XMLDocument max depth parsing test ---

    // --- Start PREVIOUS NEW COVERAGE ENHANCEMENTS ---

    // Coverage for XMLNode::InsertEndChild cross-document error (tinyxml2.cpp lines 929-931)
    // and XMLNode::InsertFirstChild cross-document error (tinyxml2.cpp lines 959-961)
    if (fdp.ConsumeBool()) {
        XMLDocument doc2; // RAII for doc2
        XMLElement* el_from_main_doc = doc.NewElement("el_from_main_for_doc2"); // Belongs to 'doc', added to doc._unlinked
        if (el_from_main_doc) { 
            XMLElement* root_doc2 = doc2.NewElement("root_doc2");
            if (root_doc2) {
                doc2.InsertFirstChild(root_doc2); // root_doc2 owned by doc2
                if (fdp.ConsumeBool()) {
                    root_doc2->InsertEndChild(el_from_main_doc); // Attempt cross-document. Should fail. el_from_main_doc remains owned by 'doc'.
                } else {
                    root_doc2->InsertFirstChild(el_from_main_doc); // Attempt cross-document. Should fail. el_from_main_doc remains owned by 'doc'.
                }
            }
        }
        // el_from_main_doc (if created) is cleaned up by 'doc' destructor via _unlinked list.
        // doc2 and root_doc2 (if created) are cleaned up by doc2 destructor.
    }

    // Coverage for misplaced XMLDeclaration parsing (error path in XMLNode::ParseDeep, tinyxml2.cpp lines 1131-1143)
    if (fdp.ConsumeBool()) {
        XMLDocument parseMisplacedDeclDoc; // RAII for parseMisplacedDeclDoc
        std::string xmlWithMisplacedDecl = "<elem1 test='123'/><?xml version=\"1.0\"?>";
        parseMisplacedDeclDoc.Parse(xmlWithMisplacedDecl.c_str()); // Should trigger error due to declaration after element
        if (parseMisplacedDeclDoc.Error()) { // Expected
            (void)parseMisplacedDeclDoc.ErrorStr(); // Exercise error reporting
        }
    }

    // Coverage for XMLElement::ShallowClone(nullptr) (tinyxml2.cpp lines 2107-2108)
    if (fdp.ConsumeBool() && rootElement) {
        XMLNode* clonedNode = rootElement->ShallowClone(nullptr);
        if (clonedNode && fdp.ConsumeBool()) { 
            (void)clonedNode->Value(); 
        }
        // clonedNode is on doc's _unlinked list, cleaned up by doc's destructor.
    }

    // Coverage for XMLPrinter writing to FILE* (tinyxml2.cpp lines 2633-2634 for Write, 2646-2647 for Putc)
    if (fdp.ConsumeBool()) {
        FILE* tmpFp = tmpfile(); 
        if (tmpFp) {
            XMLPrinter printerWithFp(tmpFp, fdp.ConsumeBool() /* compact */);
            if (fdp.ConsumeBool() && rootElement) { 
                rootElement->Accept(&printerWithFp);
            } else { 
                doc.Print(&printerWithFp);
            }
            fclose(tmpFp); 
        }
    }

    // Coverage for XMLPrinter with _processEntities = false (tinyxml2.cpp lines 2713-2715 in PrintString)
    if (fdp.ConsumeBool()) {
        XMLDocument noEntityDoc(false /* processEntities */); 
        XMLElement* rootNoEntity = noEntityDoc.NewElement("rootNoEnt");
        if (rootNoEntity) {
            noEntityDoc.InsertFirstChild(rootNoEntity);
            std::string textWithEntities = fdp.ConsumeRandomLengthString(10) + "&<>'\"" + fdp.ConsumeRandomLengthString(10);
            rootNoEntity->SetAttribute("attr", textWithEntities.c_str()); 
            rootNoEntity->SetText(textWithEntities.c_str());          

            XMLPrinter printerNoEntities(nullptr, fdp.ConsumeBool() /* compact */); 
            noEntityDoc.Print(&printerNoEntities);
            (void)printerNoEntities.CStr(); 
        }
    }
    // --- End PREVIOUS NEW COVERAGE ENHANCEMENTS ---

    // --- Start CURRENT NEW COVERAGE ENHANCEMENTS ---

    // Coverage for XMLNode::Value() on XMLDocument (tinyxml2.cpp line 851)
    if (fdp.ConsumeBool()) {
        const XMLNode* nodeDoc = &doc; 
        (void)nodeDoc->Value(); // Should return nullptr and cover the branch where this->ToDocument() is true.
    }

    // Coverage for XMLDocument::Print(nullptr) path (tinyxml2.cpp lines 2484-2485)
    if (fdp.ConsumeBool()) {
        doc.Print(nullptr); // This will print to stdout.
    }

    // Coverage for ShallowClone(nullptr) for various node types (lines like XMLText.cpp:1263)
    // XMLElement::ShallowClone(nullptr) is already covered above.
    if (firstDecl && fdp.ConsumeBool()) {
        XMLNode* clonedDecl = firstDecl->ShallowClone(nullptr); 
        if (clonedDecl && fdp.ConsumeBool()) (void)clonedDecl->Value();
        // clonedDecl is on doc's _unlinked list, managed by doc.
    }
    if (firstComment && fdp.ConsumeBool()) {
        XMLNode* clonedComment = firstComment->ShallowClone(nullptr);
        if (clonedComment && fdp.ConsumeBool()) (void)clonedComment->Value();
        // clonedComment is on doc's _unlinked list, managed by doc.
    }
    if (firstTextNode && fdp.ConsumeBool()) {
        XMLNode* clonedText = firstTextNode->ShallowClone(nullptr);
        if (clonedText && fdp.ConsumeBool()) (void)clonedText->Value();
        // clonedText is on doc's _unlinked list, managed by doc.
    }
    if (unknown && fdp.ConsumeBool()) { // 'unknown' is from line 211
        XMLNode* clonedUnknownNode = unknown->ShallowClone(nullptr);
        if (clonedUnknownNode && fdp.ConsumeBool()) (void)clonedUnknownNode->Value();
        // clonedUnknownNode is on doc's _unlinked list, managed by doc.
    }
    
    // Coverage for XMLDocument::Identify PEDANTIC_WHITESPACE for closing tag (tinyxml2.cpp line 757)
    if (fdp.ConsumeBool()) {
        XMLDocument pedanticDoc(true, PEDANTIC_WHITESPACE); // Create doc with PEDANTIC_WHITESPACE
        std::string pedanticXml;
        if (fdp.ConsumeBool()) {
             pedanticXml = "<r><c/> </r>"; // Whitespace before closing tag, after another element
        } else {
             pedanticXml = "<r> \t\n</r>"; // Whitespace as first child content before closing tag
        }
        pedanticDoc.Parse(pedanticXml.c_str());
        // Parsing is sufficient to potentially hit the line in Identify.
    }

    // Coverage for XMLNode::ParseDeep, wellLocated XMLDeclaration in an empty document (tinyxml2.cpp line 1139)
    if (fdp.ConsumeBool()) {
        XMLDocument declDoc; // Fresh document
        std::string declXml = "<?xml version='1.0'?>";
        if (fdp.ConsumeBool()) {
            declXml += "<root/>"; // Optionally make it a valid document afterwards
        } else {
            declXml += fdp.ConsumeRandomLengthString(5); // Or add some other content
        }
        declDoc.Parse(declXml.c_str()); // Parse with declaration first.
    }

    // Coverage for XMLElement::Attribute(const char* name, const char* reqValue) (tinyxml2.cpp lines 1633-1636)
    if (queryAttrElement && fdp.ConsumeBool()) { // Use an existing element
        std::string attrNameForTest = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange(1,10)); // Ensure non-empty name
        std::string attrValForTest = fdp.ConsumeRandomLengthString(10);
        queryAttrElement->SetAttribute(attrNameForTest.c_str(), attrValForTest.c_str());

        (void)queryAttrElement->Attribute(attrNameForTest.c_str(), nullptr);
        (void)queryAttrElement->Attribute(attrNameForTest.c_str(), attrValForTest.c_str());
        
        std::string nonMatchingVal = attrValForTest + "_non_match_suffix";
        if (attrValForTest.empty() && nonMatchingVal == "_non_match_suffix") nonMatchingVal = "z"; 
        (void)queryAttrElement->Attribute(attrNameForTest.c_str(), nonMatchingVal.c_str());

        std::string nonExistentAttrName = attrNameForTest + "_non_existent";
        (void)queryAttrElement->Attribute(nonExistentAttrName.c_str(), nullptr);
        (void)queryAttrElement->Attribute(nonExistentAttrName.c_str(), "any_value");
    }

    // --- Start NEW ENHANCEMENTS FOR THIS VERSION ---

    // Coverage for XMLDocument::DeleteNode where node has a parent (tinyxml2.cpp line 2330)
    if (fdp.ConsumeBool()) {
        XMLElement* delNodeParent = doc.NewElement("delNodeParent");
        if (delNodeParent) {
            rootElement->InsertEndChild(delNodeParent); // Add to main tree so it's managed
            XMLElement* delNodeChild = doc.NewElement("delNodeChild");
            if (delNodeChild) {
                delNodeParent->InsertEndChild(delNodeChild); // child's parent is delNodeParent
                if (fdp.ConsumeBool()) {
                     // This call should hit the 'if (node->_parent)' branch in XMLDocument::DeleteNode
                    doc.DeleteNode(delNodeChild); 
                }
                // If not deleted here, delNodeChild is cleaned up when delNodeParent is deleted (via doc cleanup)
            }
        }
    }
    
    // Coverage for XMLDocument::Accept and XMLElement::Accept break conditions (tinyxml2.cpp lines 788, 2149)
    if (fdp.ConsumeBool()) {
        class FuzzVisitor : public XMLVisitor {
        public:
            FuzzedDataProvider& fdp_ref;
            FuzzVisitor(FuzzedDataProvider& provider) : fdp_ref(provider) {}

            bool VisitEnter(const XMLDocument& doc_visited) override { 
                if (fdp_ref.ConsumeBool()) return false; // If this returns false, loop over children is skipped.
                return XMLVisitor::VisitEnter(doc_visited); // Default true
            }
            bool VisitExit(const XMLDocument& doc_visited) override { 
                // This return value becomes the return value of XMLDocument::Accept().
                // If it's false, and this doc was a child in another Accept, it could trigger a break.
                if (fdp_ref.ConsumeBool()) return false;
                return XMLVisitor::VisitExit(doc_visited); // Default true
            }

            bool VisitEnter(const XMLElement& el, const XMLAttribute* attr) override {
                if (fdp_ref.ConsumeBool()) return false; // If this returns false, children of 'el' are not visited.
                return XMLVisitor::VisitEnter(el, attr); // Default true
            }
            bool VisitExit(const XMLElement& el) override { 
                // This return value becomes the return value of XMLElement::Accept().
                // If false, it can trigger the break condition in the parent's Accept loop.
                if (fdp_ref.ConsumeBool()) return false;
                return XMLVisitor::VisitExit(el); // Default true
            }

            bool Visit(const XMLDeclaration& decl) override {
                // This return value becomes the return value of XMLDeclaration::Accept().
                if (fdp_ref.ConsumeBool()) return false; 
                return XMLVisitor::Visit(decl); // Default true
            }
            bool Visit(const XMLText& text) override {
                if (fdp_ref.ConsumeBool()) return false; 
                return XMLVisitor::Visit(text); // Default true
            }
            bool Visit(const XMLComment& comment) override {
                if (fdp_ref.ConsumeBool()) return false; 
                return XMLVisitor::Visit(comment); // Default true
            }
            bool Visit(const XMLUnknown& unknown) override {
                if (fdp_ref.ConsumeBool()) return false; 
                return XMLVisitor::Visit(unknown); // Default true
            }
        };

        FuzzVisitor visitor(fdp);
        if (fdp.ConsumeBool()) {
            doc.Accept(&visitor);
        } else if (rootElement) {
            // Ensure rootElement has some children for the visitor to traverse to make breaks meaningful
            if (fdp.ConsumeBool() && rootElement->FirstChild() == nullptr) {
                XMLElement* childForVisitor = doc.NewElement("child_for_visitor_accept");
                if (childForVisitor) {
                    rootElement->InsertFirstChild(childForVisitor);
                    if (fdp.ConsumeBool()) { // Add a grandchild for deeper traversal
                         XMLElement* grandchild = doc.NewElement("grandchild_for_visitor");
                         if (grandchild) childForVisitor->InsertFirstChild(grandchild);
                    }
                }
            }
            rootElement->Accept(&visitor);
        }
    }
    // --- End NEW ENHANCEMENTS FOR THIS VERSION ---

    // --- End CURRENT NEW COVERAGE ENHANCEMENTS ---

    return 0;
}