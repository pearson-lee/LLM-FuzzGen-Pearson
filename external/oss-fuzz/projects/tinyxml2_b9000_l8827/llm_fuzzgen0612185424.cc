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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // Declare strings for SetBoolSerialization here to ensure their lifetime covers all uses.
    std::string trueStrForSerialization;
    std::string falseStrForSerialization;

    // XMLDocument is the main container. It handles memory for all its nodes.
    // When 'doc' goes out of scope, all associated XML nodes are automatically deleted,
    // preventing memory leaks. This is a key RAII pattern in TinyXML2.
    XMLDocument doc;

    // Added to cover XMLUtil::SetBoolSerialization (0% coverage API)
    // This affects how boolean values are converted to strings by subsequent API calls.
    if (fdp.ConsumeBool()) {
        trueStrForSerialization = fdp.ConsumeRandomLengthString(8);
        falseStrForSerialization = fdp.ConsumeRandomLengthString(8);
        if (trueStrForSerialization.empty()) trueStrForSerialization = "custom_true_val"; // Ensure non-empty for SetBoolSerialization
        if (falseStrForSerialization.empty()) falseStrForSerialization = "custom_false_val"; // Ensure non-empty for SetBoolSerialization
        XMLUtil::SetBoolSerialization(trueStrForSerialization.c_str(), falseStrForSerialization.c_str());
    } else {
        // Reset to default to avoid state pollution between fuzzer runs for these global settings.
        XMLUtil::SetBoolSerialization("true", "false");
    }

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

    // Added to cover the staticMem=true branch in XMLNode::SetValue (lines 858-859 in coverage report),
    // which in turn calls StrPair::SetInternedStr (0% coverage).
    // This is achieved by calling XMLElement::SetName and XMLComment::SetValue with staticMem=true.
    if (fdp.ConsumeBool()) { 
        const char* staticNameForElement = "element_static_name_literal"; // String literal has static storage
        rootElement->SetName(staticNameForElement, true); // Calls SetValue with staticMem=true

        XMLComment* newStaticComment = doc.NewComment("comment_initial_value_literal");
        if (newStaticComment) {
            rootElement->InsertEndChild(newStaticComment); // newStaticComment is now owned by rootElement
            const char* staticValueForComment = "comment_static_value_literal";
            newStaticComment->SetValue(staticValueForComment, true); // Calls SetValue with staticMem=true
        }
    }

    // API 1: tinyxml2::XMLElement::InsertNewComment(const char *comment)
    // This function creates a new XMLComment node and inserts it as a child of 'rootElement'.
    // The memory for the new comment node is managed by its parent ('rootElement'),
    // and ultimately by 'doc'.
    std::string commentText = fdp.ConsumeRandomLengthString(128); // Max length 128 for comment.
    XMLComment* firstComment = rootElement->InsertNewComment(commentText.c_str());

    // Added to cover the branch in XMLNode::InsertFirstChild where _firstChild already exists (lines 965-973 in coverage report).
    // rootElement already has firstComment as a child.
    if (fdp.ConsumeBool() && firstComment) { // Ensure firstComment was successfully created
        std::string anotherChildName = fdp.ConsumeRandomLengthString(32);
        XMLElement* anotherChildElement = doc.NewElement(anotherChildName.c_str());
        if (anotherChildElement) {
            // This call to InsertFirstChild on rootElement (which already has a child)
            // will exercise the targeted branch.
            rootElement->InsertFirstChild(anotherChildElement); 
            // anotherChildElement is now owned by rootElement.
        }
    }


    // API 2: tinyxml2::XMLElement::SetText(unsigned int value)
    // Enhanced to also call SetText(float), GetText(), and SetText(const char*) again.
    std::string childNameForSetText = fdp.ConsumeRandomLengthString(32);
    XMLElement* setTextElement = doc.NewElement(childNameForSetText.c_str());
    if (setTextElement) {
        rootElement->InsertEndChild(setTextElement); // 'setTextElement' is now owned by 'rootElement'.
        unsigned int uintVal = fdp.ConsumeIntegral<unsigned int>();
        setTextElement->SetText(uintVal);
        // Any internal XMLText node created by SetText is managed by 'setTextElement'.

        // Added to cover the branch in XMLElement::SetText(const char*) where a text node already exists.
        // The existing text node will be reused and its value updated.
        std::string anotherText = fdp.ConsumeRandomLengthString(16);
        setTextElement->SetText(anotherText.c_str());

        // Added to cover tinyxml2::XMLElement::SetText(float) (0% coverage).
        // This will replace the previous text content.
        float floatVal = fdp.ConsumeFloatingPoint<float>();
        setTextElement->SetText(floatVal);

        // Added to cover const char* tinyxml2::XMLElement::GetText() (0% coverage).
        // The returned string is owned by the element/document; no manual deallocation needed by fuzzer.
        (void)setTextElement->GetText();

        // Coverage for XMLElement::SetText(double) and XMLElement::QueryDoubleText (0% coverage APIs)
        // Modifies setTextElement's content.
        if (fdp.ConsumeBool()) {
            // Call XMLElement::SetText(double) to cover this currently uncovered overload.
            setTextElement->SetText(fdp.ConsumeFloatingPoint<double>()); 
        } else {
            // Set non-double text to test QueryDoubleText's failure path.
            setTextElement->SetText("not-a-double-text-for-query"); 
        }
        double queryDblTextRes = 0.0;
        // Call XMLElement::QueryDoubleText to cover this 0% API.
        // Handles both successful conversion and failure (if text is not a double).
        (void)setTextElement->QueryDoubleText(&queryDblTextRes);

        // Added to cover XMLElement::SetText(int64_t) (0% coverage API)
        if (fdp.ConsumeBool()) {
            setTextElement->SetText(fdp.ConsumeIntegral<int64_t>());
        }
        // Added to cover XMLElement::SetText(uint64_t) (0% coverage API)
        if (fdp.ConsumeBool()) {
            setTextElement->SetText(fdp.ConsumeIntegral<uint64_t>());
        }

        // Test XMLElement::QueryDoubleText on an element with no text node (0% coverage path).
        // A new element is created to ensure it has no prior text.
        // Memory for queryEmptyDblTxtEl is managed by rootElement once inserted.
        if (fdp.ConsumeBool()) { 
            XMLElement* queryEmptyDblTxtEl = doc.NewElement(fdp.ConsumeRandomLengthString(32).c_str());
            if (queryEmptyDblTxtEl) {
                rootElement->InsertEndChild(queryEmptyDblTxtEl);
                double tempDouble = 0.0;
                // Call QueryDoubleText on an element guaranteed to have no text.
                (void)queryEmptyDblTxtEl->QueryDoubleText(&tempDouble);
            }
        }
    }

    // API 3: tinyxml2::XMLElement::QueryDoubleAttribute(const char *name, double *value)
    // Enhanced to potentially set non-double string attributes to improve XMLUtil::ToDouble coverage.
    std::string childNameForQueryAttr = fdp.ConsumeRandomLengthString(32);
    XMLElement* queryAttrElement = doc.NewElement(childNameForQueryAttr.c_str());
    if (queryAttrElement) {
        rootElement->InsertEndChild(queryAttrElement); // 'queryAttrElement' is owned by 'rootElement'.

        std::string attrName = fdp.ConsumeRandomLengthString(32); 
        
        // Enhanced logic to set attribute for QueryDoubleAttribute
        // This aims to cover different paths in QueryDoubleAttribute and underlying parsing (e.g., XMLUtil::ToDouble failure).
        enum class AttrScenario { SET_DOUBLE, SET_INVALID_STRING, DONT_SET };
        AttrScenario scenario = fdp.PickValueInArray<AttrScenario>({
            AttrScenario::SET_DOUBLE, 
            AttrScenario::SET_INVALID_STRING, 
            AttrScenario::DONT_SET 
        });

        if (scenario == AttrScenario::SET_DOUBLE) {
            double doubleAttrVal = fdp.ConsumeFloatingPoint<double>();
            queryAttrElement->SetAttribute(attrName.c_str(), doubleAttrVal);
        } else if (scenario == AttrScenario::SET_INVALID_STRING) {
            // Set a string attribute that is unlikely to be a valid double.
            // This helps test the failure path in XMLUtil::ToDouble (line 668 in coverage report).
            std::string nonDoubleStr = fdp.ConsumeBool() ? "not-a-valid-double" : fdp.ConsumeRandomLengthString(5);
            queryAttrElement->SetAttribute(attrName.c_str(), nonDoubleStr.c_str());
        }
        // If scenario is DONT_SET, attribute is not set, testing XML_NO_ATTRIBUTE.


        double queryDoubleResult = 0.0;
        (void)queryAttrElement->QueryDoubleAttribute(attrName.c_str(), &queryDoubleResult);

        // New: Add calls for QueryBoolAttribute and BoolAttribute (0% coverage APIs)
        // Reusing queryAttrElement for these tests.
        std::string boolAttrName = fdp.ConsumeRandomLengthString(32);
        
        enum class BoolAttrScenario { SET_BOOL, SET_STRING_FOR_BOOL, DONT_SET };
        BoolAttrScenario boolScenario = fdp.PickValueInArray<BoolAttrScenario>({
            BoolAttrScenario::SET_BOOL, 
            BoolAttrScenario::SET_STRING_FOR_BOOL, 
            BoolAttrScenario::DONT_SET 
        });

        if (boolScenario == BoolAttrScenario::SET_BOOL) {
            // This covers XMLElement::SetAttribute(const char*, bool)
            queryAttrElement->SetAttribute(boolAttrName.c_str(), fdp.ConsumeBool());
        } else if (boolScenario == BoolAttrScenario::SET_STRING_FOR_BOOL) {
            // Set as a string that might be parsed as a bool (e.g., "true", "0", "random")
            // This tests parsing logic within QueryBoolAttribute/BoolAttribute.
            queryAttrElement->SetAttribute(boolAttrName.c_str(), fdp.ConsumeBytesAsString(fdp.ConsumeIntegralInRange<size_t>(0, 8)).c_str());
        }
        // If boolScenario is DONT_SET, attribute is not set.

        bool queryBoolResultVal = false;
        // Added to cover XMLElement::QueryBoolAttribute(const char*, bool*) (0% coverage).
        (void)queryAttrElement->QueryBoolAttribute(boolAttrName.c_str(), &queryBoolResultVal);

        // Added to cover XMLElement::BoolAttribute(const char*, bool) (0% coverage).
        bool defaultBool = fdp.ConsumeBool();
        (void)queryAttrElement->BoolAttribute(boolAttrName.c_str(), defaultBool);

        // Coverage for XMLElement::IntAttribute and XMLElement::QueryIntAttribute (0% coverage APIs)
        std::string intAttrName = fdp.ConsumeRandomLengthString(32);
        int defaultIntValue = fdp.ConsumeIntegral<int>();
        int queryIntResultValStorage = 0; 
        
        if (fdp.ConsumeBool()) { // Set a valid int attribute
            // This call covers XMLElement::SetAttribute(const char*, int).
            queryAttrElement->SetAttribute(intAttrName.c_str(), fdp.ConsumeIntegral<int>());
        } else if (fdp.ConsumeBool()) { // Set a non-int string attribute
            queryAttrElement->SetAttribute(intAttrName.c_str(), "not-an-integer");
        } // Else: attribute intAttrName may not exist for the first calls, testing that path.

        (void)queryAttrElement->QueryIntAttribute(intAttrName.c_str(), &queryIntResultValStorage);
        (void)queryAttrElement->IntAttribute(intAttrName.c_str(), defaultIntValue);
        
        std::string nonExistentIntAttr = fdp.ConsumeRandomLengthString(16) + "_nexInt";
        (void)queryAttrElement->QueryIntAttribute(nonExistentIntAttr.c_str(), &queryIntResultValStorage);
        (void)queryAttrElement->IntAttribute(nonExistentIntAttr.c_str(), defaultIntValue);

        // Added to cover XMLElement::[Query]Int64Attribute and SetAttribute(..., int64_t) (0% coverage APIs)
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
        std::string nonExistentI64Attr = fdp.ConsumeRandomLengthString(16) + "_nexI64";
        (void)queryAttrElement->QueryInt64Attribute(nonExistentI64Attr.c_str(), &queryI64ResultVal);
        (void)queryAttrElement->Int64Attribute(nonExistentI64Attr.c_str(), defaultI64Value);

        // Added to cover XMLElement::[Query]UnsignedAttribute and SetAttribute(..., unsigned int) (0% coverage APIs)
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
        std::string nonExistentUAttr = fdp.ConsumeRandomLengthString(16) + "_nexU";
        (void)queryAttrElement->QueryUnsignedAttribute(nonExistentUAttr.c_str(), &queryUResultVal);
        (void)queryAttrElement->UnsignedAttribute(nonExistentUAttr.c_str(), defaultUValue);
        
        // Added to cover XMLElement::[Query]FloatAttribute and SetAttribute(..., float) (0% coverage APIs)
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
        std::string nonExistentFloatAttr = fdp.ConsumeRandomLengthString(16) + "_nexFlt";
        (void)queryAttrElement->QueryFloatAttribute(nonExistentFloatAttr.c_str(), &queryFloatResultVal);
        (void)queryAttrElement->FloatAttribute(nonExistentFloatAttr.c_str(), defaultFloatValue);
    }


    // API 4: const XMLElement * tinyxml2::XMLNode::NextSiblingElement(const char *name)
    // 'setTextElement' and 'queryAttrElement', if created, are siblings under 'rootElement'.
    if (setTextElement) { // Check if the first potential sibling exists.
        (void)setTextElement->NextSiblingElement();

        std::string searchName;
        if (queryAttrElement && !childNameForQueryAttr.empty() && fdp.ConsumeBool()) {
            searchName = childNameForQueryAttr; 
        } else {
            searchName = fdp.ConsumeRandomLengthString(32); 
        }
        (void)setTextElement->NextSiblingElement(searchName.c_str());
    }

    // Coverage for XMLElement::GetText() branches (lines 1694, 1703 in coverage report)
    // Aims to cover skipping comment nodes and handling cases where no text is found.
    std::string getTextElementName = fdp.ConsumeRandomLengthString(32);
    XMLElement* getTextElement = doc.NewElement(getTextElementName.c_str());
    if (getTextElement) {
        rootElement->InsertEndChild(getTextElement); // getTextElement is owned by rootElement, ensuring memory safety.

        // Determine structure: 0 = Empty, 1 = Text, 2 = Comment, 3 = Comment->Text, 4 = Comment->OtherElement
        // All created nodes (Comment, Text, OtherElement) are managed by their parent (getTextElement) or doc.
        int structure_type = fdp.ConsumeIntegralInRange<int>(0, 4);

        if (structure_type == 1) { // Text only: To test GetText without comments.
            XMLText* text = doc.NewText(fdp.ConsumeRandomLengthString(16).c_str());
            if (text) getTextElement->InsertFirstChild(text);
        } else if (structure_type == 2) { // Comment only: To test skipping comment then finding no text (hits 1694 & 1703).
            XMLComment* comment = doc.NewComment(fdp.ConsumeRandomLengthString(16).c_str());
            if (comment) getTextElement->InsertFirstChild(comment);
        } else if (structure_type == 3) { // Comment -> Text: To test skipping comment then finding text (hits 1694).
            XMLComment* comment = doc.NewComment(fdp.ConsumeRandomLengthString(16).c_str());
            if (comment) getTextElement->InsertFirstChild(comment); // Comment is first.
            XMLText* text = doc.NewText(fdp.ConsumeRandomLengthString(16).c_str());
            if (text) getTextElement->InsertEndChild(text); // Text is after the comment.
        } else if (structure_type == 4) { // Comment -> OtherElement: To test skipping comment then non-text (hits 1694 & 1703).
            XMLComment* comment = doc.NewComment(fdp.ConsumeRandomLengthString(16).c_str());
            if (comment) getTextElement->InsertFirstChild(comment); // Comment is first.
            XMLElement* otherEl = doc.NewElement(fdp.ConsumeRandomLengthString(16).c_str());
            if (otherEl) getTextElement->InsertEndChild(otherEl); // Other element after comment.
        }
        // structure_type == 0 means empty (no children added): To test GetText on empty element (hits 1703).
        
        (void)getTextElement->GetText(); // Call GetText to exercise the different paths.
    }


    // API 5: bool tinyxml2::XMLUtil::ToBool(const char *str, bool *outBool)
    std::string boolStr = fdp.ConsumeRandomLengthString(10); 
    bool outBoolVal = false; 
    (void)XMLUtil::ToBool(boolStr.c_str(), &outBoolVal);

    return 0;
}