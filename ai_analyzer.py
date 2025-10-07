# ai_analyzer.py
import os
from google import genai
from google.genai.errors import APIError

# The function name MUST be exactly 'analyze_vulnerabilities_with_ai'
def analyze_vulnerabilities_with_ai(scan_results, target_url):
    """
    Sends scan results to Gemini for analysis and suggested fixes.
    """
    # 1. Initialize the client
    try:
        # Assumes GEMINI_API_KEY is set in your environment
        client = genai.Client()
    except Exception as e:
        return f"AI Initialization Error: Failed to initialize Gemini client. Check API key setup. Details: {e}"

    # 2. Format the scan report for the model
    formatted_report = f"Target: {target_url}\n\n"
    if not scan_results:
        return "No serious exposures detected by the scanner. No AI analysis needed."
        
    for item in scan_results:
        formatted_report += f"- URL: {item['url']}\n"
        formatted_report += f"  Status: {item['status_code']} | Exposure: {item['message']}\n"
    
    # 3. Create a detailed prompt
    prompt = f"""
    You are a highly experienced cybersecurity analyst and remediation specialist. 
    Analyze the following directory scan report and provide actionable, step-by-step
    mitigation advice for each unique vulnerability or exposure type found.
    
    Format your response clearly using markdown with a section heading for each unique issue 
    (e.g., '1. Directory Listing Fixes', '2. Environment File Exposure Mitigation'). 
    Keep the advice brief and technical.
    
    --- SCAN REPORT ---
    {formatted_report}
    --- END REPORT ---
    """

    # 4. Call the Gemini Model
    try:
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt
        )
        return response.text
    except APIError as e:
        return f"AI API Error: Failed to generate analysis. This may be due to rate limits or invalid API key. Details: {e}"
    except Exception as e:
        return f"An unexpected error occurred during AI analysis: {e}"