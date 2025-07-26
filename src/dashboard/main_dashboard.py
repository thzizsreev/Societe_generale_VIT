#!/usr/bin/env python3
"""
Unified Threat Intelligence Dashboard - Advanced Analytics & Operations Center
A comprehensive, production-ready dashboard that combines multiple data sources and metrics
to provide actionable threat intelligence insights for security teams.

Features:
- Real-time threat metrics and KPIs
- Advanced threat trend analysis
- Comprehensive IOC management and export
- Threat actor tracking and attribution
- Priority-based threat assessment
- Interactive drill-down capabilities
- Automated pipeline orchestration
- Executive reporting and briefings
"""

import gradio as gr
import json
import os
import subprocess
import time
import logging
import pandas as pd
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple
import re
from collections import defaultdict, Counter
import numpy as np

try:
    import plotly.graph_objects as go
    import plotly.express as px
    HAS_PLOTLY = True
except ImportError:
    HAS_PLOTLY = False
    logger = logging.getLogger(__name__)
    logger.warning("Plotly not available. Advanced visualizations will be disabled.")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('unified_threat_dashboard.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Configuration
DATA_DIR = Path("data")
DOCS_DIR = Path("docs")
RAW_ARTICLES_FILE = DATA_DIR / "raw_articles.json"
TRIAGED_ARTICLES_FILE = DATA_DIR / "triaged_articles.json"
FINAL_BRIEFING_FILE = DOCS_DIR / "final_briefing.md"

# Threat severity colors and categories
SEVERITY_COLORS = {
    'CRITICAL': '#dc2626',  # Red
    'HIGH': '#ea580c',      # Orange
    'MEDIUM': '#ca8a04',    # Yellow
    'LOW': '#16a34a',       # Green
    'INFO': '#6b7280'       # Gray
}

CATEGORY_COLORS = {
    'ACTIVE_THREAT': '#dc2626',
    'VULNERABILITY_DISCLOSURE': '#ea580c',
    'DATA_BREACH': '#7c2d12',
    'STRATEGIC_REPORT': '#1d4ed8',
    'GENERAL_NEWS': '#6b7280'
}

class ThreatIntelligenceAnalyzer:
    """Advanced threat intelligence analytics engine."""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
    def load_all_data(self) -> Tuple[List[Dict], List[Dict]]:
        """Load and validate all threat intelligence data."""
        self.logger.info("Loading threat intelligence data")
        
        raw_articles = self._load_json_safe(RAW_ARTICLES_FILE)
        triaged_articles = self._load_json_safe(TRIAGED_ARTICLES_FILE)
        
        self.logger.info(f"Loaded {len(raw_articles)} raw articles, {len(triaged_articles)} triaged articles")
        return raw_articles, triaged_articles
    
    def _load_json_safe(self, filepath: Path) -> List[Dict]:
        """Safely load JSON file with error handling."""
        try:
            if filepath.exists():
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return data if isinstance(data, list) else []
            return []
        except Exception as e:
            self.logger.error(f"Error loading {filepath}: {e}")
            return []
    
    def calculate_threat_metrics(self, triaged_articles: List[Dict]) -> Dict[str, Any]:
        """Calculate comprehensive threat intelligence metrics."""
        self.logger.info("Calculating threat metrics")
        
        if not triaged_articles:
            return self._empty_metrics()
        
        # Basic counts
        total_threats = len(triaged_articles)
        
        # Priority distribution
        priorities = [art.get('analysis', {}).get('initial_priority_score', 0) for art in triaged_articles]
        critical_threats = sum(1 for p in priorities if p >= 9)
        high_threats = sum(1 for p in priorities if 7 <= p < 9)
        medium_threats = sum(1 for p in priorities if 4 <= p < 7)
        low_threats = sum(1 for p in priorities if p < 4)
        
        # Category distribution
        categories = [art.get('analysis', {}).get('alert_category', 'UNKNOWN') for art in triaged_articles]
        category_counts = Counter(categories)
        
        # Source distribution
        sources = [art.get('source_name', 'Unknown') for art in triaged_articles]
        source_counts = Counter(sources)
        
        # Threat actors
        threat_actors = set()
        for art in triaged_articles:
            actors = art.get('analysis', {}).get('scoring_evidence', {}).get('threat_actor_names', [])
            if actors:
                threat_actors.update(actors)
        
        # CVEs and vulnerabilities
        cves = set()
        actively_exploited = 0
        for art in triaged_articles:
            evidence = art.get('analysis', {}).get('scoring_evidence', {})
            if evidence.get('mentions_cve') and evidence.get('cve_details'):
                cves.add(evidence.get('cve_details'))
            if evidence.get('is_actively_exploited'):
                actively_exploited += 1
        
        # IOCs analysis
        total_iocs = self._count_total_iocs(triaged_articles)
        
        # Time-based analysis
        recent_threats = self._get_recent_threats(triaged_articles, hours=24)
        
        metrics = {
            'total_threats': total_threats,
            'critical_threats': critical_threats,
            'high_threats': high_threats,
            'medium_threats': medium_threats,
            'low_threats': low_threats,
            'category_distribution': dict(category_counts),
            'source_distribution': dict(source_counts),
            'unique_threat_actors': len(threat_actors),
            'threat_actor_list': list(threat_actors),
            'unique_cves': len(cves),
            'cve_list': list(cves),
            'actively_exploited': actively_exploited,
            'total_iocs': total_iocs,
            'recent_threats_24h': len(recent_threats),
            'avg_priority_score': np.mean(priorities) if priorities else 0,
            'priority_distribution': {
                'critical': critical_threats,
                'high': high_threats,
                'medium': medium_threats,
                'low': low_threats
            }
        }
        
        self.logger.info(f"Calculated metrics for {total_threats} threats")
        return metrics
    
    def _empty_metrics(self) -> Dict[str, Any]:
        """Return empty metrics structure."""
        return {
            'total_threats': 0,
            'critical_threats': 0,
            'high_threats': 0,
            'medium_threats': 0,
            'low_threats': 0,
            'category_distribution': {},
            'source_distribution': {},
            'unique_threat_actors': 0,
            'threat_actor_list': [],
            'unique_cves': 0,
            'cve_list': [],
            'actively_exploited': 0,
            'total_iocs': 0,
            'recent_threats_24h': 0,
            'avg_priority_score': 0,
            'priority_distribution': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        }
    
    def _count_total_iocs(self, articles: List[Dict]) -> int:
        """Count total IOCs across all articles."""
        total = 0
        for article in articles:
            iocs = article.get('extracted_iocs', {})
            if isinstance(iocs, dict):
                total += sum(len(v) for v in iocs.values() if isinstance(v, list))
        return total
    
    def _get_recent_threats(self, articles: List[Dict], hours: int = 24) -> List[Dict]:
        """Get threats from the last N hours."""
        cutoff = datetime.now() - timedelta(hours=hours)
        recent = []
        
        for article in articles:
            timestamp_str = article.get('collection_timestamp')
            if timestamp_str:
                try:
                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    if timestamp >= cutoff:
                        recent.append(article)
                except:
                    continue
        
        return recent
    
    def create_category_distribution(self, metrics: Dict[str, Any]):
        """Create threat category distribution chart."""
        categories = metrics.get('category_distribution', {})
        if not categories:
            return self._create_fallback_chart("No category data available")
        
        if not HAS_PLOTLY:
            return self._create_fallback_pie_data(categories, "Category Distribution")
        
        fig = go.Figure(data=[
            go.Pie(labels=list(categories.keys()),
                  values=list(categories.values()),
                  marker_colors=[CATEGORY_COLORS.get(cat, '#6b7280') for cat in categories.keys()],
                  textinfo='label+percent',
                  hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>')
        ])
        
        fig.update_layout(
            title="Threat Distribution by Category",
            height=400,
            showlegend=True,
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='white'),
            title_font=dict(color='white', size=16)
        )
        
        return fig
    
    def create_priority_heatmap(self, triaged_articles: List[Dict]):
        """Create priority vs category heatmap."""
        if not triaged_articles:
            return self._create_fallback_chart("No data for heatmap")
        
        if not HAS_PLOTLY:
            return self._create_fallback_heatmap_data(triaged_articles)
        
        # Create matrix data
        categories = set()
        priority_ranges = ['1-3 (Low)', '4-6 (Medium)', '7-8 (High)', '9-10 (Critical)']
        
        matrix_data = defaultdict(lambda: defaultdict(int))
        
        for article in triaged_articles:
            analysis = article.get('analysis', {})
            category = analysis.get('alert_category', 'UNKNOWN')
            priority = analysis.get('initial_priority_score', 0)
            
            categories.add(category)
            
            if priority <= 3:
                matrix_data[category]['1-3 (Low)'] += 1
            elif priority <= 6:
                matrix_data[category]['4-6 (Medium)'] += 1
            elif priority <= 8:
                matrix_data[category]['7-8 (High)'] += 1
            else:
                matrix_data[category]['9-10 (Critical)'] += 1
        
        # Convert to matrix format
        categories = sorted(categories)
        z_data = []
        for cat in categories:
            row = [matrix_data[cat][pr] for pr in priority_ranges]
            z_data.append(row)
        
        fig = go.Figure(data=go.Heatmap(
            z=z_data,
            x=priority_ranges,
            y=categories,
            colorscale='Reds',
            showscale=True,
            hovertemplate='Category: %{y}<br>Priority: %{x}<br>Count: %{z}<extra></extra>'
        ))
        
        fig.update_layout(
            title="Threat Priority vs Category Heatmap",
            xaxis_title="Priority Range",
            yaxis_title="Threat Category",
            height=400,
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='white'),
            title_font=dict(color='white', size=16),
            xaxis=dict(color='white'),
            yaxis=dict(color='white')
        )
        
        return fig
    
    def _create_fallback_chart(self, message: str):
        """Create fallback chart when plotly is not available."""
        if HAS_PLOTLY:
            fig = go.Figure()
            fig.add_annotation(
                text=message,
                xref="paper", yref="paper",
                x=0.5, y=0.5, xanchor='center', yanchor='middle',
                showarrow=False,
                font=dict(size=16, color="gray")
            )
            fig.update_layout(height=400)
            return fig
        else:
            # Return a DataFrame or simple visualization for Gradio
            return pd.DataFrame({'Message': [message]})
    
    def _create_fallback_pie_data(self, categories: Dict[str, int], title: str) -> pd.DataFrame:
        """Create fallback pie chart data as DataFrame."""
        return pd.DataFrame({
            'Category': list(categories.keys()),
            'Count': list(categories.values()),
            'Percentage': [f"{(v/sum(categories.values())*100):.1f}%" for v in categories.values()]
        })
    
    def _create_fallback_heatmap_data(self, triaged_articles: List[Dict]) -> pd.DataFrame:
        """Create fallback heatmap data as DataFrame."""
        data = []
        for article in triaged_articles:
            analysis = article.get('analysis', {})
            priority = analysis.get('initial_priority_score', 0)
            category = analysis.get('alert_category', 'UNKNOWN')
            
            priority_range = 'Low (1-3)'
            if priority >= 9:
                priority_range = 'Critical (9-10)'
            elif priority >= 7:
                priority_range = 'High (7-8)'
            elif priority >= 4:
                priority_range = 'Medium (4-6)'
            
            data.append({
                'Category': category,
                'Priority_Range': priority_range,
                'Priority_Score': priority
            })
        
        return pd.DataFrame(data)
    
    def _get_severity_level(self, priority: int) -> str:
        """Convert priority score to severity level."""
        if priority >= 9:
            return 'CRITICAL'
        elif priority >= 7:
            return 'HIGH'
        elif priority >= 4:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _create_empty_chart(self, message: str):
        """Create empty chart with message."""
        return self._create_fallback_chart(message)

class IOCManager:
    """Advanced IOC extraction and management system."""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Enhanced IOC patterns
        self.ioc_patterns = {
            'ip_addresses': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'domains': r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}\b',
            'urls': r'https?://[^\s<>"{}|\\^`\[\]]+',
            'md5_hashes': r'\b[a-fA-F0-9]{32}\b',
            'sha1_hashes': r'\b[a-fA-F0-9]{40}\b',
            'sha256_hashes': r'\b[a-fA-F0-9]{64}\b',
            'cves': r'CVE-\d{4}-\d{4,7}',
            'email_addresses': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'bitcoin_addresses': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
            'registry_keys': r'HKEY_[A-Z_]+\\[\\A-Za-z0-9_\-\.]+',
            'file_paths': r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*',
            'mutex_names': r'Global\\[A-Za-z0-9_\-\.]+',
        }
    
    def extract_all_iocs(self, articles: List[Dict]) -> Dict[str, List[str]]:
        """Extract all IOCs from articles using advanced patterns."""
        self.logger.info(f"Extracting IOCs from {len(articles)} articles")
        
        all_iocs = {pattern_name: set() for pattern_name in self.ioc_patterns.keys()}
        
        for article in articles:
            # Check if IOCs were pre-extracted
            if 'extracted_iocs' in article:
                pre_extracted = article['extracted_iocs']
                for ioc_type, iocs in pre_extracted.items():
                    if ioc_type in all_iocs and isinstance(iocs, list):
                        all_iocs[ioc_type].update(iocs)
            
            # Also extract from content using patterns
            content = f"{article.get('title', '')} {article.get('content', '')}"
            article_iocs = self._extract_iocs_from_text(content)
            
            for ioc_type, iocs in article_iocs.items():
                all_iocs[ioc_type].update(iocs)
        
        # Convert sets to sorted lists
        result = {k: sorted(list(v)) for k, v in all_iocs.items()}
        
        total_iocs = sum(len(v) for v in result.values())
        self.logger.info(f"Extracted {total_iocs} total IOCs")
        
        return result
    
    def _extract_iocs_from_text(self, text: str) -> Dict[str, List[str]]:
        """Extract IOCs from text using regex patterns."""
        iocs = {}
        
        for ioc_type, pattern in self.ioc_patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            # Filter and validate matches
            validated_matches = self._validate_iocs(ioc_type, matches)
            iocs[ioc_type] = validated_matches
        
        return iocs
    
    def _validate_iocs(self, ioc_type: str, matches: List[str]) -> List[str]:
        """Validate and filter IOC matches."""
        if ioc_type == 'domains':
            # Filter out common false positives
            filtered = []
            for domain in matches:
                if not any(exclude in domain.lower() for exclude in 
                          ['example.com', 'localhost', 'test.com', 'sample.com']):
                    filtered.append(domain)
            return filtered
        elif ioc_type == 'ip_addresses':
            # Validate IP ranges
            validated = []
            for ip in matches:
                parts = ip.split('.')
                if all(0 <= int(part) <= 255 for part in parts):
                    # Exclude private/reserved ranges
                    if not (parts[0] in ['10', '172', '192'] or ip.startswith('127.')):
                        validated.append(ip)
            return validated
        
        return matches
    
    def export_iocs(self, iocs: Dict[str, List[str]], format_type: str) -> str:
        """Export IOCs in specified format."""
        if format_type.upper() == 'JSON':
            return json.dumps(iocs, indent=2)
        
        elif format_type.upper() == 'CSV':
            lines = ['type,value,source']
            for ioc_type, ioc_list in iocs.items():
                for ioc in ioc_list:
                    lines.append(f'"{ioc_type}","{ioc}","threat_intelligence"')
            return '\n'.join(lines)
        
        elif format_type.upper() == 'TXT':
            lines = ['# Threat Intelligence IOCs', f'# Generated: {datetime.now().isoformat()}', '']
            for ioc_type, ioc_list in iocs.items():
                if ioc_list:
                    lines.append(f'## {ioc_type.replace("_", " ").title()} ({len(ioc_list)} items)')
                    for ioc in ioc_list:
                        lines.append(ioc)
                    lines.append('')
            return '\n'.join(lines)
        
        elif format_type.upper() == 'STIX':
            # Basic STIX format (simplified)
            stix_data = {
                "type": "bundle",
                "id": f"bundle--{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                "spec_version": "2.1",
                "objects": []
            }
            
            for ioc_type, ioc_list in iocs.items():
                for ioc in ioc_list:
                    stix_obj = {
                        "type": "indicator",
                        "id": f"indicator--{hash(ioc) % 1000000:06d}",
                        "created": datetime.now().isoformat(),
                        "modified": datetime.now().isoformat(),
                        "labels": ["malicious-activity"],
                        "pattern": f"[{self._get_stix_pattern_type(ioc_type)}:value = '{ioc}']"
                    }
                    stix_data["objects"].append(stix_obj)
            
            return json.dumps(stix_data, indent=2)
        
        return "Unsupported format"
    
    def _get_stix_pattern_type(self, ioc_type: str) -> str:
        """Map IOC type to STIX pattern type."""
        mapping = {
            'ip_addresses': 'ipv4-addr',
            'domains': 'domain-name',
            'urls': 'url',
            'md5_hashes': 'file:hashes.MD5',
            'sha1_hashes': 'file:hashes.SHA-1',
            'sha256_hashes': 'file:hashes.SHA-256',
            'email_addresses': 'email-addr'
        }
        return mapping.get(ioc_type, 'artifact')

class PipelineOrchestrator:
    """Advanced pipeline orchestration and monitoring."""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def run_pipeline_step(self, script_path: str, timeout: int = 600) -> str:
        """Execute a pipeline step with monitoring."""
        script_name = Path(script_path).name
        self.logger.info(f"Executing pipeline step: {script_path}")
        
        try:
            start_time = time.time()
            result = subprocess.run(
                ['python', str(script_path)],
                cwd='.', capture_output=True, text=True, timeout=timeout
            )
            execution_time = time.time() - start_time
            
            if result.returncode == 0:
                status = f"✅ {script_name} completed successfully in {execution_time:.1f}s"
                self.logger.info(status)
            else:
                status = f"❌ {script_name} failed after {execution_time:.1f}s:\n{result.stderr}"
                self.logger.error(status)
            
            return status
            
        except subprocess.TimeoutExpired:
            status = f"⏰ {script_name} timed out after {timeout}s"
            self.logger.error(status)
            return status
        except Exception as e:
            status = f"💥 Error executing {script_name}: {e}"
            self.logger.error(status)
            return status
    
    def run_full_pipeline(self):
        """Execute the complete threat intelligence pipeline."""
        self.logger.info("Starting full pipeline execution")
        
        steps = [
            ("src/data_collection/collector.py", "Data Collection", 600),
            ("src/analysis/triage_analyzer.py", "AI Triage Analysis", 900),
            ("src/analysis/final_analyzer.py", "Final Analysis & Briefing", 600)
        ]
        
        results = []
        total_start = time.time()
        
        for script, description, timeout in steps:
            yield f"🔄 {description}...\n"
            result = self.run_pipeline_step(script, timeout)
            results.append(f"{description}: {result}")
            yield "\n".join(results) + "\n"
            
            if "❌" in result or "⏰" in result or "💥" in result:
                yield f"\n❌ Pipeline stopped due to failure in {description}"
                return
            
            time.sleep(1)
        
        total_time = time.time() - total_start
        completion_msg = f"\n🎉 Full pipeline completed successfully in {total_time:.1f}s"
        yield "\n".join(results) + completion_msg

# Initialize global components
analyzer = ThreatIntelligenceAnalyzer()
ioc_manager = IOCManager()
pipeline = PipelineOrchestrator()

def load_briefing_content() -> str:
    """Load final briefing content."""
    try:
        if FINAL_BRIEFING_FILE.exists():
            with open(FINAL_BRIEFING_FILE, 'r', encoding='utf-8') as f:
                return f.read()
        return "📋 **No briefing available yet.**\n\nPlease run the full analysis pipeline to generate the executive briefing."
    except Exception as e:
        return f"❌ Error loading briefing: {e}"

def refresh_dashboard():
    """Refresh all dashboard data and return updated components."""
    logger.info("Refreshing dashboard data")
    
    # Load fresh data
    raw_articles, triaged_articles = analyzer.load_all_data()
    metrics = analyzer.calculate_threat_metrics(triaged_articles)
    
    # Create visualizations
    category_chart = analyzer.create_category_distribution(metrics)
    heatmap_chart = analyzer.create_priority_heatmap(triaged_articles)
    
    # Create summary cards
    summary_md = f"""
    ## 📊 Threat Intelligence Summary
    
    **🎯 Threat Overview:**
    - **Total Threats Analyzed:** {metrics['total_threats']:,}
    - **Critical Priority (9-10):** {metrics['critical_threats']:,}
    - **High Priority (7-8):** {metrics['high_threats']:,}
    - **Average Priority Score:** {metrics['avg_priority_score']:.1f}/10
    
    **🔍 Intelligence Insights:**
    - **Unique Threat Actors:** {metrics['unique_threat_actors']:,}
    - **CVEs Identified:** {metrics['unique_cves']:,}
    - **Actively Exploited:** {metrics['actively_exploited']:,}
    - **Total IOCs Extracted:** {metrics['total_iocs']:,}
    
    **⏰ Recent Activity:**
    - **New Threats (24h):** {metrics['recent_threats_24h']:,}
    - **Last Updated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    """
    
    # Create top threats table
    top_threats_data = []
    for article in sorted(triaged_articles, 
                         key=lambda x: x.get('analysis', {}).get('initial_priority_score', 0), 
                         reverse=True)[:10]:
        analysis = article.get('analysis', {})
        top_threats_data.append({
            'Title': article.get('title', 'No Title')[:80],
            'Priority': analysis.get('initial_priority_score', 0),
            'Category': analysis.get('alert_category', 'Unknown'),
            'Source': article.get('source_name', 'Unknown'),
            'Threat Actors': ', '.join(analysis.get('scoring_evidence', {}).get('threat_actor_names', [])) or 'None',
            'CVE': 'Yes' if analysis.get('scoring_evidence', {}).get('mentions_cve') else 'No'
        })
    
    top_threats_df = pd.DataFrame(top_threats_data)
    
    # Extract and format IOCs
    all_iocs = ioc_manager.extract_all_iocs(raw_articles + triaged_articles)
    ioc_summary = f"""
    ## 🎯 Indicators of Compromise (IOCs)
    
    **IOC Statistics:**
    """
    
    for ioc_type, iocs in all_iocs.items():
        if iocs:
            ioc_summary += f"- **{ioc_type.replace('_', ' ').title()}:** {len(iocs):,} unique\n"
    
    return (
        summary_md,
        category_chart, 
        heatmap_chart,
        top_threats_df,
        ioc_summary,
        all_iocs  # For the IOC state
    )

def search_and_filter_threats(query="", min_priority=1, categories=None, sources=None):
    """Advanced threat search and filtering - simplified approach."""
    # Load fresh data each time (like enhanced_app.py does)
    _, triaged_articles = analyzer.load_all_data()
    
    if not triaged_articles:
        return pd.DataFrame(columns=['Title', 'Priority', 'Category', 'Source', 'Threat Actors', 'CVE'])
    
    # Filter articles based on criteria
    filtered_articles = []
    
    for article in triaged_articles:
        analysis = article.get('analysis', {})
        
        # Text search
        if query:
            searchable_text = f"{article.get('title', '')} {article.get('content', '')}".lower()
            threat_actors = ', '.join(analysis.get('scoring_evidence', {}).get('threat_actor_names', []))
            searchable_text += f" {threat_actors}".lower()
            
            if query.lower() not in searchable_text:
                continue
        
        # Priority filter
        priority = analysis.get('initial_priority_score', 0)
        if priority < min_priority:
            continue
        
        # Category filter
        if categories:
            category = analysis.get('alert_category', 'Unknown')
            if category not in categories:
                continue
        
        # Source filter
        if sources:
            source = article.get('source_name', 'Unknown')
            if source not in sources:
                continue
        
        filtered_articles.append(article)
    
    # Convert to DataFrame for display
    data = []
    for article in filtered_articles[:100]:  # Limit to 100 results
        analysis = article.get('analysis', {})
        data.append({
            'Title': article.get('title', 'No Title')[:80],
            'Priority': analysis.get('initial_priority_score', 0),
            'Category': analysis.get('alert_category', 'Unknown'),
            'Source': article.get('source_name', 'Unknown'),
            'Threat Actors': ', '.join(analysis.get('scoring_evidence', {}).get('threat_actor_names', [])) or 'None',
            'CVE': 'Yes' if analysis.get('scoring_evidence', {}).get('mentions_cve') else 'No'
        })
    
    return pd.DataFrame(data)

def export_iocs_formatted(all_iocs, export_format):
    """Export IOCs in the specified format."""
    if not all_iocs:
        return "No IOCs available for export."
    
    return ioc_manager.export_iocs(all_iocs, export_format)

# Create the advanced Gradio interface
with gr.Blocks(
    title="Unified Threat Intelligence Dashboard",
    theme=gr.themes.Base(
        primary_hue="blue",
        secondary_hue="gray",
        neutral_hue="slate"
    ).set(
        body_background_fill="*neutral_950",
        body_text_color="*neutral_100",
        background_fill_primary="*neutral_900",
        background_fill_secondary="*neutral_800",
        border_color_primary="*neutral_700",
        block_background_fill="*neutral_900",
        block_border_color="*neutral_700",
        input_background_fill="*neutral_800"
    ),
    css="""
    .gradio-container {
        max-width: 1400px !important;
        background-color: #0f172a !important;
    }
    .metric-card {
        background: linear-gradient(135deg, #1e40af 0%, #7c3aed 100%);
        color: white;
        padding: 20px;
        border-radius: 10px;
        text-align: center;
    }
    .dark {
        background-color: #0f172a !important;
        color: #f8fafc !important;
    }
    """
) as app:
    
    # Global state for data persistence
    dashboard_state = gr.State()
    ioc_state = gr.State()
    
    gr.Markdown("""
    # 🛡️ Unified Threat Intelligence Dashboard
    
    **Advanced Cybersecurity Operations Center**
    
    Real-time threat monitoring, analysis, and response coordination platform combining 
    multiple intelligence sources with AI-powered insights.
    """)
    
    with gr.Tabs():
        # ===== MAIN DASHBOARD TAB =====
        with gr.Tab("📊 Executive Dashboard"):
            with gr.Row():
                refresh_btn = gr.Button("🔄 Refresh Dashboard", variant="primary", size="lg")
                auto_refresh = gr.Checkbox(label="Auto-refresh (30s)", value=False)
            
            # Summary metrics
            summary_display = gr.Markdown()
            
            # Main visualizations
            with gr.Row():
                if HAS_PLOTLY:
                    category_plot = gr.Plot(label="Threat Category Distribution")
                else:
                    category_plot = gr.Dataframe(label="Threat Category Distribution", wrap=True)
            
            if HAS_PLOTLY:
                priority_heatmap = gr.Plot(label="Priority vs Category Analysis")
            else:
                priority_heatmap = gr.Dataframe(label="Priority vs Category Analysis", wrap=True)
            
            # Top threats table
            gr.Markdown("### 🚨 Top Priority Threats")
            top_threats_table = gr.Dataframe(
                label="Critical and High Priority Threats",
                wrap=True,
                interactive=False
            )
        
        # ===== THREAT ANALYSIS TAB =====
        with gr.Tab("🔍 Threat Analysis"):
            gr.Markdown("### Advanced Threat Intelligence Analysis")
            
            with gr.Row():
                with gr.Column(scale=1):
                    search_query = gr.Textbox(
                        label="🔍 Search Threats",
                        placeholder="Enter keywords, threat actors, CVEs...",
                        lines=1
                    )
                    
                    priority_filter = gr.Slider(
                        minimum=1,
                        maximum=10,
                        value=1,
                        step=1,
                        label="Minimum Priority Score"
                    )
                    
                    category_filter = gr.CheckboxGroup(
                        choices=["ACTIVE_THREAT", "VULNERABILITY_DISCLOSURE", "DATA_BREACH", "STRATEGIC_REPORT", "GENERAL_NEWS"],
                        label="Categories"
                    )
                    
                    source_filter = gr.CheckboxGroup(
                        choices=["The Hacker News", "Reddit", "GitHub", "RSS"],
                        label="Sources"
                    )
                    
                    search_btn = gr.Button("🔍 Apply Filters", variant="secondary")
                
                with gr.Column(scale=2):
                    filtered_threats = gr.Dataframe(
                        label="Filtered Threat Intelligence",
                        wrap=True,
                        interactive=True,
                        value=pd.DataFrame()  # Initialize with empty DataFrame
                    )
            
            # Threat details section
            with gr.Accordion("🔬 Threat Details", open=False):
                threat_details = gr.Markdown("Select a threat from the table above to see detailed analysis.")
        
        # ===== IOC MANAGEMENT TAB =====
        with gr.Tab("🎯 IOC Management"):
            gr.Markdown("### Indicators of Compromise - Advanced Export & Analysis")
            
            with gr.Row():
                ioc_summary_display = gr.Markdown()
            
            with gr.Row():
                with gr.Column():
                    export_format = gr.Radio(
                        choices=["JSON", "CSV", "TXT", "STIX"],
                        value="JSON",
                        label="Export Format"
                    )
                    
                    export_btn = gr.Button("📤 Export IOCs", variant="primary")
                
                with gr.Column():
                    ioc_stats = gr.Markdown("IOC statistics will appear here after data refresh.")
            
            exported_iocs = gr.Textbox(
                label="Exported IOCs",
                lines=20,
                placeholder="Click 'Export IOCs' to generate formatted output...",
                max_lines=50
            )
        
        # ===== PIPELINE CONTROL TAB =====
        with gr.Tab("⚙️ Pipeline Control"):
            gr.Markdown("### Threat Intelligence Pipeline Orchestration")
            
            with gr.Row():
                with gr.Column():
                    full_pipeline_btn = gr.Button("🚀 Run Full Pipeline", variant="primary", size="lg")
                    gr.Markdown("*Complete workflow: Collection → Triage → Analysis → Briefing*")
                
                with gr.Column():
                    gr.Markdown("**Individual Pipeline Steps:**")
                    collect_btn = gr.Button("1️⃣ Data Collection", size="sm")
                    triage_btn = gr.Button("2️⃣ AI Triage Analysis", size="sm")
                    final_btn = gr.Button("3️⃣ Final Analysis", size="sm")
            
            pipeline_status = gr.Textbox(
                label="Pipeline Execution Status",
                lines=15,
                placeholder="Ready to execute pipeline...",
                interactive=False
            )
            
            # Pipeline monitoring
            with gr.Row():
                pipeline_progress = gr.Progress()
        
        # ===== EXECUTIVE BRIEFING TAB =====
        with gr.Tab("📋 Executive Briefing"):
            gr.Markdown("### AI-Generated Executive Threat Briefing")
            
            with gr.Row():
                refresh_briefing_btn = gr.Button("🔄 Refresh Briefing", variant="secondary")
                download_briefing_btn = gr.Button("📥 Download Briefing", variant="secondary")
            
            briefing_content = gr.Markdown(
                value=load_briefing_content(),
                label="Executive Summary"
            )
        
        # ===== SYSTEM STATUS TAB =====
        with gr.Tab("🔧 System Status"):
            gr.Markdown("### System Configuration & Health")
            
            system_status = gr.Markdown(f"""
            **🔧 Configuration Status:**
            - **Ollama Server:** {os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434')}
            - **Ollama Model:** {os.getenv('OLLAMA_MODEL', 'llama3.1')}
            - **OpenRouter API:** {'✅ Configured' if os.getenv('OPENROUTER_API_KEY') else '❌ Not Set'}
            - **GitHub Token:** {'✅ Configured' if os.getenv('GITHUB_TOKEN') else '❌ Not Set (Optional)'}
            
            **📁 Data Files:**
            - **Raw Articles:** {'✅ Available' if RAW_ARTICLES_FILE.exists() else '❌ Missing'}
            - **Triaged Articles:** {'✅ Available' if TRIAGED_ARTICLES_FILE.exists() else '❌ Missing'}
            - **Final Briefing:** {'✅ Available' if FINAL_BRIEFING_FILE.exists() else '❌ Missing'}
            
            **🔄 Last Updated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            """)
    
    # ===== EVENT HANDLERS =====
    
    # Dashboard refresh
    def on_refresh():
        return refresh_dashboard()
    
    refresh_btn.click(
        on_refresh,
        outputs=[
            summary_display, category_plot, priority_heatmap,
            top_threats_table, ioc_summary_display, ioc_state
        ]
    )
    
    # Search functionality
    search_btn.click(
        search_and_filter_threats,
        inputs=[search_query, priority_filter, category_filter, source_filter],
        outputs=[filtered_threats]
    )
    
    # Initialize threat analysis table on load
    def load_initial_threats():
        return search_and_filter_threats()
    
    app.load(
        load_initial_threats,
        outputs=[filtered_threats]
    )
    
    # IOC export
    export_btn.click(
        export_iocs_formatted,
        inputs=[ioc_state, export_format],
        outputs=[exported_iocs]
    )
    
    # Pipeline execution
    full_pipeline_btn.click(
        pipeline.run_full_pipeline,
        outputs=[pipeline_status]
    )
    
    collect_btn.click(
        lambda: pipeline.run_pipeline_step("src/data_collection/collector.py"),
        outputs=[pipeline_status]
    )
    
    triage_btn.click(
        lambda: pipeline.run_pipeline_step("src/analysis/triage_analyzer.py"),
        outputs=[pipeline_status]
    )
    
    final_btn.click(
        lambda: pipeline.run_pipeline_step("src/analysis/final_analyzer.py"),
        outputs=[pipeline_status]
    )
    
    # Briefing refresh
    refresh_briefing_btn.click(
        load_briefing_content,
        outputs=[briefing_content]
    )
    
    # Initial data load
    app.load(
        on_refresh,
        outputs=[
            summary_display, category_plot, priority_heatmap,
            top_threats_table, ioc_summary_display, ioc_state
        ]
    )

if __name__ == "__main__":
    # Ensure directories exist
    DATA_DIR.mkdir(exist_ok=True)
    DOCS_DIR.mkdir(exist_ok=True)
    
    logger.info("🛡️ Starting Unified Threat Intelligence Dashboard...")
    logger.info(f"📁 Working directory: {os.getcwd()}")
    logger.info(f"🔧 Configuration loaded from environment")
    
    print("🛡️ Starting Unified Threat Intelligence Dashboard...")
    print(f"📁 Working directory: {os.getcwd()}")
    print("🚀 Advanced analytics and IOC management enabled")
    print("📊 Real-time threat monitoring dashboard ready")
    
    try:
        app.launch(
            server_name="0.0.0.0",
            server_port=7860,
            share=False,
            debug=False,
            show_error=True
        )
        logger.info("🎉 Unified dashboard launched successfully")
    except Exception as e:
        logger.error(f"❌ Failed to launch dashboard: {e}")
        raise
