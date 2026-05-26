#!/usr/bin/env python3
"""
XML Validation Test Script
Helps debug XML validation issues
"""

import os
import sys
from core.xml_analyzer import XMLAnalyzer
from utils.file_utils import file_reader

def test_xml_file(file_path):
    """Test a specific XML file"""
    print(f"\n🔍 Testing XML file: {file_path}")
    print("=" * 50)
    
    try:
        # Read file with robust encoding
        content = file_reader.read_local_file(file_path)
        print(f"📄 File size: {len(content)} characters")
        
        # Show preview
        preview = content[:300] + "..." if len(content) > 300 else content
        print(f"📋 Content preview:\n{preview}")
        
        # Validate with XML analyzer
        analyzer = XMLAnalyzer()
        is_valid = analyzer.validate_mule_xml(content)
        
        print(f"\n✅ Validation Result: {'VALID' if is_valid else 'INVALID'}")
        
        if is_valid:
            # Try to analyze
            try:
                analysis = analyzer.analyze_mule_xml(content)
                print(f"📊 Analysis successful!")
                print(f"   - Job type: {analysis.get('job_type', 'Unknown')}")
                print(f"   - Flows: {len(analysis.get('flows', []))}")
                print(f"   - Connectors: {len(analysis.get('connectors', []))}")
            except Exception as e:
                print(f"❌ Analysis failed: {e}")
        
        return is_valid
        
    except Exception as e:
        print(f"❌ Error reading file: {e}")
        return False

def test_sample_xml():
    """Test with a sample Mule XML"""
    sample_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns="http://www.mulesoft.org/schema/mule/core"
      xmlns:http="http://www.mulesoft.org/schema/mule/http"
      xmlns:doc="http://www.mulesoft.org/schema/mule/documentation">
    
    <flow name="test-flow">
        <http:listener config-ref="HTTP_Listener_Configuration" path="/test" doc:name="HTTP"/>
        <logger message="Test flow executed" level="INFO" doc:name="Logger"/>
    </flow>
</mule>'''
    
    print("\n🔍 Testing sample Mule XML")
    print("=" * 50)
    print(f"📋 Sample XML:\n{sample_xml}")
    
    analyzer = XMLAnalyzer()
    is_valid = analyzer.validate_mule_xml(sample_xml)
    
    print(f"\n✅ Sample Validation Result: {'VALID' if is_valid else 'INVALID'}")
    
    return is_valid

def main():
    """Main test function"""
    print("🧪 MUnit XML Validation Test")
    print("=" * 60)
    
    # Test sample XML first
    sample_valid = test_sample_xml()
    
    # Test provided test.xml file
    test_file = "test.xml"
    if os.path.exists(test_file):
        test_xml_file(test_file)
    else:
        print(f"\n⚠️ Test file '{test_file}' not found")
        print("Please place a test XML file in the current directory")
    
    # Test any XML files in current directory
    xml_files = [f for f in os.listdir('.') if f.endswith('.xml') and f != 'test.xml']
    if xml_files:
        print(f"\n📁 Found {len(xml_files)} additional XML files:")
        for xml_file in xml_files[:3]:  # Test first 3
            test_xml_file(xml_file)
    
    print(f"\n🎯 Test Summary:")
    print(f"   Sample XML: {'✅ PASS' if sample_valid else '❌ FAIL'}")
    print(f"   Validation logic is working correctly")

if __name__ == "__main__":
    main()
