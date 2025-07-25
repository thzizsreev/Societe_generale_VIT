import praw
import feedparser
from newspaper import Article, Config
import os
import json
import requests
from dotenv import load_dotenv
from github import Github
import re
from datetime import datetime, timedelta

load_dotenv()

MAX_ARTICLES_PER_SOURCE = 10 

newspaper_config = Config()
newspaper_config.browser_user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36'
newspaper_config.fetch_image = False
newspaper_config.memoize_articles = False

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

def extract_iocs_from_content(text):
    """
    Enhanced IOC extraction with comprehensive patterns.
    """
    iocs = {
        'ip_addresses': set(),
        'urls': set(),
        'file_hashes': set(),
        'domains': set(),
        'cves': set(),
        'email_addresses': set(),
        'bitcoin_addresses': set(),
        'registry_keys': set()
    }
    
    ipv4_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ipv6_pattern = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
    iocs['ip_addresses'].update(re.findall(ipv4_pattern, text))
    iocs['ip_addresses'].update(re.findall(ipv6_pattern, text))
    
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    iocs['urls'].update(re.findall(url_pattern, text))
    
    # File hashes (MD5, SHA1, SHA256, SHA512)
    hash_patterns = [
        r'\b[a-fA-F0-9]{32}\b',  # MD5
        r'\b[a-fA-F0-9]{40}\b',  # SHA1
        r'\b[a-fA-F0-9]{64}\b',  # SHA256
        r'\b[a-fA-F0-9]{128}\b'  # SHA512
    ]
    for pattern in hash_patterns:
        iocs['file_hashes'].update(re.findall(pattern, text))
    
    domain_pattern = r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}\b'
    potential_domains = re.findall(domain_pattern, text)
    for domain in potential_domains:
        if any(keyword in domain.lower() for keyword in ['malware', 'phish', 'attack', 'exploit', 'threat', 'suspicious']):
            iocs['domains'].add(domain)
        elif not any(domain.endswith(tld) for tld in ['.com', '.org', '.net', '.edu', '.gov']):
            iocs['domains'].add(domain)
    
    # CVE identifiers
    cve_pattern = r'CVE-\d{4}-\d{4,7}'
    iocs['cves'].update(re.findall(cve_pattern, text, re.IGNORECASE))
    
    # Email addresses
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    iocs['email_addresses'].update(re.findall(email_pattern, text))
    
    # Bitcoin addresses
    bitcoin_pattern = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|bc1[a-z0-9]{39,59}\b'
    iocs['bitcoin_addresses'].update(re.findall(bitcoin_pattern, text))
    
    # Windows Registry keys
    registry_pattern = r'HKEY_[A-Z_]+\\[^\s]+'
    iocs['registry_keys'].update(re.findall(registry_pattern, text, re.IGNORECASE))
    
    # Convert sets to lists
    return {key: list(values) for key, values in iocs.items()}


def get_daily_breach_news(target_subreddit):
    """
    Fetches articles from a subreddit and returns them as a list of dictionaries.
    """
    print(f"\n🔎 Searching for top posts in r/{target_subreddit}...")
    try:
        reddit = praw.Reddit(
            client_id=os.getenv("CLIENT_ID"),
            client_secret=os.getenv("CLIENT_SECRET"),
            user_agent=os.getenv("USER_AGENT"),
            read_only=True
        )
        subreddit = reddit.subreddit(target_subreddit)
        print(f"Successfully connected to Reddit and r/{subreddit.display_name}")
    except Exception as e:
        print(f"Could not connect to Reddit. Error: {e}")
        return []

    found_articles = []
    for submission in subreddit.top(time_filter="day", limit=MAX_ARTICLES_PER_SOURCE * 2):
        if len(found_articles) >= MAX_ARTICLES_PER_SOURCE:
            print(f"Reached target of {MAX_ARTICLES_PER_SOURCE} articles for this source.")
            break

        url = submission.url
        if "reddit.com" in url or url.startswith("/r/"):
            continue

        try:
            print(f"🔗 Reading: '{submission.title}'")
            article = Article(url, config=newspaper_config)
            article.download()
            article.parse()

            if len(article.text) > 250:
                extracted_iocs = extract_iocs_from_content(f"{submission.title} {article.text}")
                
                article_data = {
                    "source_type": "reddit",
                    "source_name": f"r/{target_subreddit}",
                    "title": submission.title,
                    "link": url,
                    "content": article.text,
                    "extracted_iocs": extracted_iocs,
                    "collection_timestamp": datetime.now().isoformat()
                }
                found_articles.append(article_data)
                print(f" Successfully scraped article ({len(found_articles)}/{MAX_ARTICLES_PER_SOURCE}).")
                
                total_iocs = sum(len(iocs) for iocs in extracted_iocs.values())
                if total_iocs > 0:
                    print(f"  Extracted {total_iocs} IOCs from this article")
            else:
                print("  Skipping: Not enough text found.")
        except Exception as e:
            print(f"  Could not read article. Skipping. (Reason: {e})")
            continue
            
    return found_articles

def fetch_rss_entries(feed_urls):
    """
    Fetches articles from RSS feeds and returns them as a list of dictionaries.
    """
    all_entries = []
    for feed_url in feed_urls:
        print(f"\nFetching from RSS feed: {feed_url}")
        feed = feedparser.parse(feed_url)
        
        if feed.bozo:
            print(f"  [!] Failed to parse feed: {feed_url}")
            continue

        for entry in feed.entries[:MAX_ARTICLES_PER_SOURCE]:
            link = entry.get('link')
            if not link:
                continue

            try:
                print(f"Reading: '{entry.title}'")
                article = Article(link, config=newspaper_config)
                article.download()
                article.parse()
                
                if len(article.text) > 250:
                    extracted_iocs = extract_iocs_from_content(f"{entry.title} {article.text}")
                    
                    article_data = {
                        "source_type": "rss",
                        "source_name": feed.feed.get('title', 'Unknown Feed'),
                        "title": entry.title,
                        "link": link,
                        "content": article.text,
                        "extracted_iocs": extracted_iocs,
                        "collection_timestamp": datetime.now().isoformat()
                    }
                    all_entries.append(article_data)
                    print(f"  Successfully scraped article.")
                    
                    total_iocs = sum(len(iocs) for iocs in extracted_iocs.values())
                    if total_iocs > 0:
                        print(f" Extracted {total_iocs} IOCs from this article")
                else:
                    print("  Skipping: Not enough text found.")
            except Exception as e:
                print(f"  Could not read article. Skipping. (Reason: {e})")
                continue
    
    return all_entries

def fetch_github_threat_intel():
    print(f"\nFetching from GitHub threat intelligence repositories...")
    
    if GITHUB_TOKEN:
        g = Github(GITHUB_TOKEN)
        print(f"Using GitHub token for authentication")
    else:
        g = Github()
        print(f"Using GitHub without authentication (rate limited)")
    
    threat_intel_repos = [
        "mitre/cti",
        "CyberMonitor/APT_CyberCriminal_Campagin_Collections",
        "blackorbird/APT_REPORT",
        "kbandla/APTnotes",
        "aptnotes/data"
    ]
    
    all_entries = []
    
    for repo_name in threat_intel_repos:
        try:
            print(f"Checking repository: {repo_name}")
            repo = g.get_repo(repo_name)
            
            since = datetime.now() - timedelta(days=7)
            commits = repo.get_commits(since=since)
            
            commit_count = 0
            for commit in commits:
                if commit_count >= 5:
                    break
                
                try:
                    for file in commit.files:
                        if file.filename.lower().endswith(('.md', '.txt', '.json', '.yaml', '.yml')):
                            try:
                                file_content = repo.get_contents(file.filename, ref=commit.sha)
                                if file_content.size < 50000:  # Limit file size
                                    content = file_content.decoded_content.decode('utf-8')
                                    
                                    # Extract IOCs from content
                                    extracted_iocs = extract_iocs_from_content(content)
                                    
                                    article_data = {
                                        "source_type": "github",
                                        "source_name": f"GitHub: {repo_name}",
                                        "title": f"{file.filename} - {commit.commit.message[:100]}",
                                        "link": f"https://github.com/{repo_name}/blob/{commit.sha}/{file.filename}",
                                        "content": content[:5000],  # Truncate long content
                                        "extracted_iocs": extracted_iocs,
                                        "collection_timestamp": datetime.now().isoformat()
                                    }
                                    all_entries.append(article_data)
                                    
                                    total_iocs = sum(len(iocs) for iocs in extracted_iocs.values())
                                    if total_iocs > 0:
                                        print(f"  Found {total_iocs} IOCs in {file.filename}")
                                    
                            except Exception as e:
                                print(f"  Could not read file {file.filename}: {e}")
                                continue
                                
                    commit_count += 1
                    
                except Exception as e:
                    print(f"  Error processing commit: {e}")
                    continue
                    
        except Exception as e:
            print(f"  Could not access repository {repo_name}: {e}")
            continue
    
    print(f"Collected {len(all_entries)} entries from GitHub repositories")
    return all_entries

if __name__ == "__main__":
    os.system('cls' if os.name == 'nt' else 'clear')
    print("Enhanced Cyber Threat Intelligence Aggregator")
    
    all_articles = []
    processed_links = set()

    rss_urls = [
        "https://feeds.feedburner.com/TheHackersNews",
        "https://www.bleepingcomputer.com/feed/",
        "https://threatpost.com/feed/",
        "https://krebsonsecurity.com/feed/",
        "https://www.darkreading.com/rss.xml"
    ]
    target_subreddits = ["cybersecurity", "cybersecurity_news", "netsec"]

    print("Phase 1: RSS Feed Collection")
    rss_articles = fetch_rss_entries(rss_urls)
    for article in rss_articles:
        if article['link'] not in processed_links:
            all_articles.append(article)
            processed_links.add(article['link'])

    print("\nPhase 2: Reddit Collection")
    for sub_name in target_subreddits:
        reddit_articles = get_daily_breach_news(sub_name)
        for article in reddit_articles:
            if article['link'] not in processed_links:
                all_articles.append(article)
                processed_links.add(article['link'])

    print("\nPhase 3: GitHub Threat Intelligence Collection")
    github_articles = fetch_github_threat_intel()
    for article in github_articles:
        if article['link'] not in processed_links:
            all_articles.append(article)
            processed_links.add(article['link'])

    if all_articles:
        os.makedirs("data", exist_ok=True)
        output_filename = "data/raw_articles.json"
        print("\n" + "="*60)
        print(f"COLLECTION COMPLETE!")
        print(f"Collected a total of {len(all_articles)} unique articles.")
        
        total_iocs = {}
        for article in all_articles:
            for ioc_type, iocs in article.get('extracted_iocs', {}).items():
                total_iocs[ioc_type] = total_iocs.get(ioc_type, 0) + len(iocs)
        
        print(f"\nIOC Summary:")
        for ioc_type, count in total_iocs.items():
            if count > 0:
                print(f"  • {ioc_type.replace('_', ' ').title()}: {count}")
        
        source_counts = {}
        for article in all_articles:
            source = article.get('source_type', 'unknown')
            source_counts[source] = source_counts.get(source, 0) + 1
        
        print(f"\nSource Breakdown:")
        for source, count in source_counts.items():
            print(f"  • {source.title()}: {count} articles")
        
        with open(output_filename, "w", encoding="utf-8") as f:
            json.dump(all_articles, f, indent=4)
            
        print(f"\nAll data saved to '{output_filename}'")
        print("="*60)
    else:
        print("\nCould not find any readable articles today.")


def main():
    """Main function for import compatibility."""
    if __name__ != "__main__":
        all_articles = []
        processed_links = set()

        rss_urls = [
            "https://feeds.feedburner.com/TheHackersNews",
            "https://www.bleepingcomputer.com/feed/",
            "https://threatpost.com/feed/",
            "https://krebsonsecurity.com/feed/",
            "https://www.darkreading.com/rss.xml"
        ]
        
        rss_articles = fetch_rss_entries(rss_urls)
        for article in rss_articles:
            if article['link'] not in processed_links:
                all_articles.append(article)
                processed_links.add(article['link'])

        target_subreddits = ["cybersecurity", "cybersecurity_news", "netsec"]
        for sub_name in target_subreddits:
            reddit_articles = get_daily_breach_news(sub_name)
            for article in reddit_articles:
                if article['link'] not in processed_links:
                    all_articles.append(article)
                    processed_links.add(article['link'])

        github_articles = fetch_github_threat_intel()
        for article in github_articles:
            if article['link'] not in processed_links:
                all_articles.append(article)
                processed_links.add(article['link'])

        if all_articles:
            os.makedirs("data", exist_ok=True)
            output_filename = "data/raw_articles.json"
            with open(output_filename, "w", encoding="utf-8") as f:
                json.dump(all_articles, f, indent=4)
            print(f"Data collection complete: {len(all_articles)} articles saved to {output_filename}")
        
        return all_articles
