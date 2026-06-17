# =============================================================================
# PROPRIETARY SOFTWARE — ALL RIGHTS RESERVED
# Security Management Platform (SMP)
# =============================================================================
import logging
import requests
from tools.db_manager import get_db_connection

logger = logging.getLogger("smp.update")

EPSS_API_URL = "https://api.first.org/data/v1/epss"

def sync_epss():
    """Fetches EPSS scores for CVEs currently lacking them in our database."""
    logger.info("EPSS Sync Started: Enriching database with Exploit Prediction Scores...")
    
    conn = get_db_connection()
    try:
        # Get CVEs without an EPSS score
        # Limit to 100 at a time to respect URI length and API limits
        rows = conn.execute("SELECT cve FROM cves WHERE epss_score IS NULL ORDER BY published_date DESC LIMIT 100").fetchall()
        cve_list = [r["cve"] for r in rows]
        
        if not cve_list:
            logger.info("EPSS Sync Completed: No CVEs require enrichment.")
            return True
            
        cve_query = ",".join(cve_list)
        params = {"cve": cve_query}
        
        response = requests.get(EPSS_API_URL, params=params, timeout=25)
        if response.status_code != 200:
            logger.error(f"EPSS Sync Failed: HTTP error {response.status_code}")
            return False
            
        data = response.json()
        epss_data = data.get("data", [])
        
        updated_count = 0
        cursor = conn.cursor()
        
        for item in epss_data:
            cve_id = item.get("cve")
            epss_score_str = item.get("epss")
            if cve_id and epss_score_str is not None:
                try:
                    score = float(epss_score_str)
                    cursor.execute("UPDATE cves SET epss_score = ? WHERE cve = ?", (score, cve_id))
                    updated_count += 1
                except ValueError:
                    pass
                    
        # Update CVEs that returned no EPSS score to 0.0 or a placeholder so we don't query them again next time
        # We'll use 0.0 for now, meaning very low / unknown probability
        cursor.execute("UPDATE cves SET epss_score = 0.0 WHERE epss_score IS NULL AND cve IN ({})".format(','.join(['?']*len(cve_list))), cve_list)
        
        conn.commit()
        logger.info(f"EPSS Sync Completed: Enriched {updated_count} CVEs with EPSS scores.")
        return True
    except Exception as e:
        logger.error(f"EPSS Sync Exception: {e}", exc_info=True)
        return False
    finally:
        conn.close()
