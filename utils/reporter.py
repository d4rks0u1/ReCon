import json
import os
from datetime import datetime
from config import REPORT_DIR
from utils.logger import logger

def save_report(data, target, module_name, format="json"):
    if not os.path.exists(REPORT_DIR):
        os.makedirs(REPORT_DIR)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{target}_{module_name}_{timestamp}.{format}"
    filepath = os.path.join(REPORT_DIR, filename)

    try:
        if format == "json":
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=4)
            logger.info(f"JSON report saved to {filepath}")
        elif format == "html":
            # Basic HTML report generation (can be expanded)
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Recon Report - {target} - {module_name}</title>
                <style>
                    body {{ font-family: sans-serif; margin: 20px; }}
                    h1 {{ color: #333; }}
                    pre {{ background-color: #eee; padding: 10px; border-radius: 5px; }}
                </style>
            </head>
            <body>
                <h1>Recon Report</h1>
                <p><strong>Target:</strong> {target}</p>
                <p><strong>Module:</strong> {module_name}</p>
                <p><strong>Timestamp:</strong> {timestamp}</p>
                <h2>Results:</h2>
                <pre>{json.dumps(data, indent=4)}</pre>
            </body>
            </html>
            """
            with open(filepath, 'w') as f:
                f.write(html_content)
            logger.info(f"HTML report saved to {filepath}")
        else:
            logger.warning(f"Unsupported report format: {format}")
            return None
        return filepath
    except Exception as e:
        logger.error(f"Error saving report to {filepath}: {e}")
        return None

def generate_overall_report(all_results, target, format="json"):
    if not os.path.exists(REPORT_DIR):
        os.makedirs(REPORT_DIR)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{target}_overall_recon_report_{timestamp}.{format}"
    filepath = os.path.join(REPORT_DIR, filename)

    try:
        if format == "json":
            with open(filepath, 'w') as f:
                json.dump(all_results, f, indent=4)
            logger.info(f"Overall JSON report saved to {filepath}")
        elif format == "html":
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Overall Recon Report - {target}</title>
                <style>
                    body {{ font-family: sans-serif; margin: 20px; }}
                    h1 {{ color: #333; }}
                    h2 {{ color: #555; }}
                    pre {{ background-color: #eee; padding: 10px; border-radius: 5px; }}
                    .module-section {{ margin-bottom: 30px; border-bottom: 1px solid #ccc; padding-bottom: 20px; }}
                </style>
            </head>
            <body>
                <h1>Overall Reconnaissance Report</h1>
                <p><strong>Target:</strong> {target}</p>
                <p><strong>Timestamp:</strong> {timestamp}</p>
                {"".join([f'''
                <div class="module-section">
                    <h2>{module_name} Results:</h2>
                    <pre>{json.dumps(results, indent=4)}</pre>
                </div>
                ''' for module_name, results in all_results.items()])}
            </body>
            </html>
            """
            with open(filepath, 'w') as f:
                f.write(html_content)
            logger.info(f"Overall HTML report saved to {filepath}")
        else:
            logger.warning(f"Unsupported overall report format: {format}")
            return None
        return filepath
    except Exception as e:
        logger.error(f"Error saving overall report to {filepath}: {e}")
        return None
