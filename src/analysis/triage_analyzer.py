import requests
import json
import os
import time
from dotenv import load_dotenv
from multiprocessing import Pool

# Load environment variables
load_dotenv()

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1")  # Default to llama3.1, can be changed

INPUT_FILENAME = "data/raw_articles.json"
OUTPUT_FILENAME = "data/triaged_articles.json"

TRIAGE_PROMPT_TEMPLATE = """
You are a highly-skilled SOC (Security Operations Center) analyst responsible for triaging incoming threat intelligence. Your task is to analyze the provided article and extract structured, evidence-based data. Your response MUST be only a single, clean JSON object. Do not add any other text, comments, or markdown formatting like ```json.

Analyze the article based on these cybersecurity criteria:
1.  Vulnerability Details: Does it mention a specific CVE identifier? Is a CVSS score provided? Most importantly, does it state the vulnerability is being actively exploited in the wild?
2.  Threat Actor Information: Does it name a specific threat actor, ransomware gang, or APT group?
3.  Technical Indicators: Does it contain specific Indicators of Compromise (IOCs) or describe specific Tactics, Techniques, and Procedures (TTPs)?
4.  Impact: What is the ultimate impact of the attack (e.g., ransomware, data exfiltration, cryptomining)?

Based on your analysis of the article content below, fill out the following JSON object:

{{
  "is_relevant": <boolean>,
  "alert_category": "<'ACTIVE_THREAT'|'VULNERABILITY_DISCLOSURE'|'DATA_BREACH'|'STRATEGIC_REPORT'|'GENERAL_NEWS'>",
  "one_sentence_summary": "<string>",
  "scoring_evidence": {{
    "mentions_cve": <boolean>,
    "cve_details": "<string|null>",
    "cvss_score": <float|null>,
    "is_actively_exploited": <boolean>,
    "mentions_threat_actor": <boolean>,
    "threat_actor_names": ["<string>", "..."],
    "mentions_indicators": <boolean>,
    "impact_assessment": "<string>"
  }},
  "priority_reasoning": "<string>",
  "initial_priority_score": <integer>
}}

--- ARTICLE CONTENT ---
{article_content}
"""

def analyze_article_with_ai(article_content):
    """
    Sends article content to Ollama for analysis and returns structured JSON.
    """
    prompt = TRIAGE_PROMPT_TEMPLATE.format(article_content=article_content)
    
    try:
        # Ollama API endpoint for chat completions
        response = requests.post(
            url=f"{OLLAMA_BASE_URL}/api/generate",
            headers={
                "Content-Type": "application/json",
            },
            data=json.dumps({
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
                "format": "json"  # Request JSON format response
            })
        )

        # Handle potential API errors
        if response.status_code != 200:
            print(f"  [!] Ollama API Error: Status Code {response.status_code}")
            print(f"  [!] Response: {response.text}")
            return None

        response_data = response.json()
        ai_response_content = response_data.get('response', '')
        
        # The AI's response should be a JSON string, so we parse it.
        analysis_json = json.loads(ai_response_content)
        return analysis_json

    except requests.exceptions.RequestException as e:
        print(f"  [!] Network Error: Could not connect to Ollama. Make sure Ollama is running. {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"  [!] JSON Decode Error: The AI did not return valid JSON.")
        print(f"  [!] Raw AI Response: {ai_response_content}")
        print(f"  [!] JSON Error: {e}")
        return None
    except Exception as e:
        print(f"  [!] An unexpected error occurred: {e}")
        return None
    
def process_article(article):
    print(f"  Title: {article.get('title', 'No Title')}")

    if not article.get('content') or len(article['content'].strip()) < 100:
        print(f"  [!] Skipping article: Content is missing or too short.")
        return None

    analysis_data = analyze_article_with_ai(article['content'])

    time.sleep(1)

    if analysis_data:
        final_article_data = {**article, "analysis": analysis_data}
        print(f"  [SUCCESS] Article analyzed and added to triage list.")
        return final_article_data
    else:
        print(f"  [FAILURE] Could not analyze article.")
        return None

def main():
    """
    Main function to run the triage process using Ollama.
    """
    try:
        response = requests.get(f"{OLLAMA_BASE_URL}/api/tags")
        if response.status_code != 200:
            print(f"\n[ERROR] Could not connect to Ollama at {OLLAMA_BASE_URL}")
            print("Please make sure Ollama is running. Install and start it with:")
            print("1. Install Ollama: https://ollama.ai/")
            print(f"2. Pull the model: ollama pull {OLLAMA_MODEL}")
            print("3. Start Ollama: ollama serve")
            return
        else:
            available_models = response.json().get('models', [])
            model_names = [model['name'] for model in available_models]
            if OLLAMA_MODEL not in model_names and f"{OLLAMA_MODEL}:latest" not in model_names:
                print(f"\n[WARNING] Model '{OLLAMA_MODEL}' not found in Ollama.")
                print(f"Available models: {model_names}")
                print(f"To install the model, run: ollama pull {OLLAMA_MODEL}")
            else:
                print(f"\n[INFO] Connected to Ollama. Using model: {OLLAMA_MODEL}")
    except Exception as e:
        print(f"\n[ERROR] Could not connect to Ollama: {e}")
        print("Please make sure Ollama is running.")
        return

    # Load the raw articles
    try:
        with open(INPUT_FILENAME, 'r', encoding='utf-8') as f:
            raw_articles = json.load(f)
        print(f"\n[INFO] Loaded {len(raw_articles)} articles from '{INPUT_FILENAME}'.")
    except FileNotFoundError:
        print(f"\n[ERROR] Input file not found: '{INPUT_FILENAME}'")
        print("Please run the data collection script first.")
        return
    except json.JSONDecodeError:
        print(f"\n[ERROR] Could not parse '{INPUT_FILENAME}'. Make sure it's a valid JSON file.")
        return

    all_triaged_articles = []

    #multi threading
    with Pool(processes=4) as pool:
        # Run processing concurrently
        results = pool.map(process_article, raw_articles)

    # Filter out None results (failed/skipped articles)
    all_triaged_articles = [r for r in results if r]

    # Save the final, enriched data
    if all_triaged_articles:
        print(f"\n--- Triage Complete ---")
        print(f"Successfully analyzed {len(all_triaged_articles)} relevant articles.")
        with open(OUTPUT_FILENAME, 'w', encoding='utf-8') as f:
            json.dump(all_triaged_articles, f, indent=2)
        print(f"Enriched data saved to '{OUTPUT_FILENAME}'.")
        print("This file is now ready for the final review stage with Claude.")
    else:
        print("\n--- Triage Complete ---")
        print("No articles were successfully analyzed.")

if __name__ == "__main__":
    main()
