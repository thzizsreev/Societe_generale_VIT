import requests
import json
import os
import time
from dotenv import load_dotenv

# Load env vars
load_dotenv()

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")

YOUR_SITE_URL = "http://localhost" 
YOUR_SITE_NAME = "DailyBreachSummary"

INPUT_FILENAME = "data/triaged_articles.json"
OUTPUT_FILENAME = "docs/final_briefing.md"
MODEL_NAME = "anthropic/claude-3.5-haiku"
PRIORITY_THRESHOLD = 4

REWRITE_PROMPT_TEMPLATE = """
You are a cybersecurity journalist and analyst for the "Daily Breach Summary." Your audience consists of experienced professionals (CISOs, SOC analysts, threat hunters) who require accurate, technical, and actionable intelligence.

Your task is to take the provided raw news report and rewrite it into a clear, comprehensive, and professional article.

**CRITICAL INSTRUCTIONS:**
1.  **ZERO IMAGINATION:** You MUST base your article **exclusively** on the information provided in the original `content`. Do not use any outside knowledge, do not infer details not present, and do not make any assumptions. If a detail is not in the source text, you cannot include it.
2.  **PROFESSIONAL TONE:** Write for a technical audience. Avoid sensationalism and marketing language. Focus on the facts, TTPs, impact, and mitigation if mentioned.
3.  **CREATE A NEW TITLE:** Write a new, informative headline that accurately reflects the core event. Do not use the original title.
4.  **WRITE A COMPLETE ARTICLE:** The article should be several paragraphs long, with a clear introduction, a body explaining the technical details, and a conclusion discussing the implications.
5.  **ATTRIBUTION:** At the end of your article, add a horizontal rule (`---`) and attribute the source using the provided `source_name` and `link`.

**Input Article Data:**
```json
{article_json}
```

Your final output must be a single block of Markdown text containing only the new title, the new article, and the source attribution.
"""

def rewrite_article_with_claude(article_object):
    """
    Sends a triaged article to Claude for a full rewrite.
    """
    prompt = REWRITE_PROMPT_TEMPLATE.format(article_json=json.dumps(article_object, indent=2))
    
    try:
        response = requests.post(
            url="https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "Content-Type": "application/json",
                "HTTP-Referer": YOUR_SITE_URL,
                "X-Title": YOUR_SITE_NAME,
            },
            data=json.dumps({
                "model": MODEL_NAME,
                "messages": [
                    {"role": "user", "content": prompt}
                ]
            })
        )

        if response.status_code != 200:
            print(f"  [!] API Error: Status Code {response.status_code}")
            print(f"  [!] Response: {response.text}")
            return None

        response_data = response.json()
        rewritten_article = response_data['choices'][0]['message']['content']
        return rewritten_article

    except requests.exceptions.RequestException as e:
        print(f"  [!] Network Error: Could not connect to API. {e}")
        return None
    except Exception as e:
        print(f"  [!] An unexpected error occurred: {e}")
        return None

def main():
    """
    Main function to run the final content generation process.
    """
    print("--- Final Content Generation with Claude ---")

    if not OPENROUTER_API_KEY:
        print("\n[ERROR] OPENROUTER_API_KEY environment variable not set.")
        return

    try:
        with open(INPUT_FILENAME, 'r', encoding='utf-8') as f:
            all_articles = json.load(f)
    except FileNotFoundError:
        print(f"\n[ERROR] Input file not found: '{INPUT_FILENAME}'")
        print("Please run the triage.py script first.")
        return

    high_priority_articles = [
        article for article in all_articles
        if article.get("analysis", {}).get("initial_priority_score", 0) >= PRIORITY_THRESHOLD
    ]

    if not high_priority_articles:
        print("\n[INFO] No articles met the priority threshold for rewriting.")
        return

    print(f"\n[INFO] Found {len(high_priority_articles)} articles with priority >= {PRIORITY_THRESHOLD}.")
    
    final_briefing_content = []
    for i, article in enumerate(high_priority_articles):
        print(f"\n--- Rewriting article {i+1}/{len(high_priority_articles)} ---")
        print(f"  Original Title: {article.get('title', 'No Title')}")
        print(f"  Priority Score: {article['analysis']['initial_priority_score']}")

        rewritten_content = rewrite_article_with_claude(article)
        
        time.sleep(1)

        if rewritten_content:
            final_briefing_content.append(rewritten_content)
            print(f"  [SUCCESS] Article rewritten by Claude.")
        else:
            print(f"  [FAILURE] Could not rewrite article. It will be skipped.")

    # 3. Save the final briefing file
    if final_briefing_content:
        print(f"\n--- Briefing Complete ---")
        # Join all the rewritten articles, separated by a double horizontal rule for clarity
        full_briefing = "\n\n---\n\n".join(final_briefing_content)
        
        with open(OUTPUT_FILENAME, 'w', encoding='utf-8') as f:
            f.write(full_briefing)
            
        print(f"Final briefing saved to '{OUTPUT_FILENAME}'.")
        print("This file is now ready to be displayed in your Gradio app.")
    else:
        print("\n--- Briefing Generation Failed ---")
        print("No articles were successfully rewritten.")

if __name__ == "__main__":
    main()
