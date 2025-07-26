#!/usr/bin/env python3

import sys
import argparse
import logging
from pathlib import Path

src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('threat_intelligence.log'),
            logging.StreamHandler()
        ]
    )

def run_data_collection():
    print("Starting data collection...")
    try:
        from data_collection.collector import main as collect_main
        collect_main()
        print("Data collection completed successfully")
    except Exception as e:
        print(f"Data collection failed: {e}")
        return False
    return True

def run_analysis():
    print("Starting threat analysis...")
    try:
        from analysis.triage_analyzer import main as triage_main
        triage_main()
        print("Triage analysis completed")
        
        from analysis.final_analyzer import main as final_main
        final_main()
        print("Final analysis completed")
    except Exception as e:
        print(f"Analysis failed: {e}")
        return False
    return True

def run_dashboard():
    print("Launching Threat Intelligence Dashboard...")
    try:
        from dashboard.main_dashboard import app
        app.launch(
            server_name="0.0.0.0",
            server_port=7860,
            share=False,
            debug=False,
            show_error=True
        )
    except Exception as e:
        print(f"Dashboard launch failed: {e}")
        return False
    return True

def run_full_pipeline():
    print("Starting Full Threat Intelligence Pipeline")
    print("=" * 50)
    
    if not run_data_collection():
        return False
    
    print("-" * 50)
    
    if not run_analysis():
        return False
    
    print("-" * 50)
    
    print("Pipeline completed successfully! Launching dashboard...")
    return run_dashboard()

def main():
    parser = argparse.ArgumentParser(
        description="Threat Intelligence Feed Aggregator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                    # Launch web dashboard
  python main.py --collect          # Run data collection only
  python main.py --analyze          # Run analysis pipeline only
  python main.py --pipeline         # Run full pipeline then launch dashboard
        """
    )
    
    parser.add_argument(
        '--collect', 
        action='store_true',
        help='Run data collection pipeline only'
    )
    
    parser.add_argument(
        '--analyze', 
        action='store_true',
        help='Run analysis pipeline only'
    )
    
    parser.add_argument(
        '--pipeline', 
        action='store_true',
        help='Run full pipeline (collect -> analyze -> dashboard)'
    )
    
    parser.add_argument(
        '--port', 
        type=int, 
        default=7860,
        help='Port for web dashboard (default: 7860)'
    )
    
    args = parser.parse_args()
    
    setup_logging()
    logger = logging.getLogger(__name__)
    
    print("Threat Intelligence Feed Aggregator")
    print("=" * 50)
    
    try:
        if args.collect:
            success = run_data_collection()
            sys.exit(0 if success else 1)
        
        elif args.analyze:
            success = run_analysis()
            sys.exit(0 if success else 1)
        
        elif args.pipeline:
            success = run_full_pipeline()
            sys.exit(0 if success else 1)
        
        else:
            success = run_dashboard()
            sys.exit(0 if success else 1)
            
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        print(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
