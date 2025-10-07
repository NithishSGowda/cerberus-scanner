# report_generator.py
from fpdf import FPDF

# --- Custom PDF Class for Watermark and Header/Footer ---
class HackerReport(FPDF):
    
    # 1. Custom Header (Theme and Title)
    def header(self):
        # Text color (Neon Green)
        self.set_text_color(0, 255, 65) # RGB for #00FF41
        
        # Title
        self.set_font("Arial", "B", 18)
        self.cell(0, 10, "// CERBERUS-SCANNER REPORT //", 0, 1, "C")
        
        # Draw the Watermark/Signature (High contrast, transparent)
        self.set_font("Arial", "B", 80)
        self.set_text_color(26, 26, 26) # Dark Grey/Black for subtle effect
        self.rotate(45, self.w/2, self.h/2) # Rotate 45 degrees around center
        self.text(30, self.h / 2, "CYBERUS_SCANNER")
        self.rotate(0) # Reset rotation
        
        # Reset colors and font for the body content
        self.set_text_color(0, 0, 0) # Black for readability of content
        self.set_draw_color(0, 255, 65) # Neon Green for lines
        self.line(10, 25, 200, 25) # Separator line
        self.ln(5) # Line break

    # 2. Custom Footer (Digital Signature Tag)
    def footer(self):
        self.set_y(-15) # Position 15 mm from bottom
        self.set_font("Arial", "I", 8)
        self.set_text_color(0, 0, 0) # Black
        
        # Digital Signature Tag
        tag = "Developed by Nithish S Gowda"
        page_info = f"Page {self.page_no()}/{{nb}}"
        
        # Print tag on the left and page number on the right
        self.cell(self.w / 2, 10, tag, 0, 0, "L")
        self.cell(self.w / 2 - 10, 10, page_info, 0, 0, "R")


# --- Main PDF Generation Function ---
def create_pdf_report(results, target_url, filename, ai_analysis_text=""):
    """Generates a PDF report from the scan results and AI analysis."""
    
    # Use the custom HackerReport class
    pdf = HackerReport('P', 'mm', 'A4')
    pdf.alias_nb_pages() # Required for {nb} in footer
    pdf.set_auto_page_break(auto=True, margin=15)
    
    # Set the background to dark/black (Requires setting text color to black/white for content)
    # NOTE: FPDF is optimized for printing; setting a true black background is complex.
    # We will stick to Black text on White paper, and use Neon Green for accents.
    pdf.set_fill_color(240, 240, 240) # Light grey fill for contrast
    
    # --- PAGE 1: SUMMARY & RAW DATA ---
    pdf.add_page()
    
    # Resetting font and color after header runs
    pdf.set_font("Arial", "", 12)
    pdf.set_text_color(0, 0, 0)
    
    pdf.cell(0, 8, f"Target URL: {target_url}", 0, 1, "L")
    pdf.cell(0, 8, f"Total Potential Exposures Found: {len(results)}", 0, 1, "L")
    pdf.cell(0, 10, "", 0, 1) # Spacer

    # Raw Scan Data Section
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "--- 1. Raw Scan Data ---", 0, 1, "L")
    
    if results:
        pdf.set_font("Arial", "", 9)
        for i, exposure in enumerate(results):
            # Format: 1. Status: 200 | Exposure: (HTML Content) | URL: http://...
            line = f"{i+1}. {exposure['message']} | URL: {exposure['url']}"
            pdf.multi_cell(0, 5, line, 0, 1)
            
    else:
        pdf.set_font("Arial", "I", 11)
        pdf.cell(0, 10, "No exposures found with current wordlist.", 0, 1, "C")

    # --- PAGE 2: AI ANALYSIS ---
    pdf.add_page()
    
    # Resetting font and color after header runs
    pdf.set_font("Arial", "B", 14)
    pdf.set_text_color(0, 0, 0)
    
    pdf.cell(0, 10, "--- 2. AI Remediation Analysis ---", 0, 1, "L")
    pdf.cell(0, 5, "", 0, 1) # Spacer

    pdf.set_font("Arial", "", 10)
    
    # Process the AI text for better PDF display
    clean_analysis = ai_analysis_text.replace('```markdown', '').replace('```', '').strip()

    for line in clean_analysis.split('\n'):
        # Use BOLD for headings/titles (e.g., Markdown H1/H2)
        if line.startswith('#') or line.startswith('1.') or line.startswith('2.'):
             pdf.set_font("Arial", "B", 11)
             pdf.multi_cell(0, 6, line.replace('#', '').strip(), 0, 1)
        else:
             pdf.set_font("Arial", "", 10)
             pdf.multi_cell(0, 5, line.strip(), 0, 1)
    
    pdf.output(filename)
    return filename