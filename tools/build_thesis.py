#!/usr/bin/env python3
"""
SMP Thesis Compiler
Combines all markdown chapters into a single master document.
"""

import os

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
THESIS_DIR = os.path.join(ROOT_DIR, "docs", "thesis")
CHAPTERS_DIR = os.path.join(THESIS_DIR, "chapters")

def compile_thesis():
    main_file = os.path.join(THESIS_DIR, "main.md")
    output_file = os.path.join(THESIS_DIR, "SMP_Thesis_Comprehensive.md")
    
    with open(main_file, "r", encoding="utf-8") as f:
        content = f.read()
        
    chapter_files = [
        ("{{ ABSTRACT }}", "00_abstract.md"),
        ("{{ CHAPTER_1 }}", "01_introduction_and_origins.md"),
        ("{{ CHAPTER_2 }}", "02_architecture_evolution.md"),
        ("{{ CHAPTER_3 }}", "03_core_technologies.md"),
        ("{{ CHAPTER_4 }}", "04_scanner_orchestration.md"),
        ("{{ CHAPTER_5 }}", "05_heuristic_intelligence.md"),
        ("{{ CHAPTER_6 }}", "06_data_security.md"),
        ("{{ CHAPTER_7 }}", "07_ui_ux_design.md"),
        ("{{ CHAPTER_8 }}", "08_deployment_and_cicd.md"),
        ("{{ CHAPTER_9 }}", "09_conclusion_and_future_work.md"),
        ("{{ GLOSSARY }}", "10_glossary.md"),
        ("{{ INDEX }}", "11_index.md"),
    ]
    
    for tag, filename in chapter_files:
        filepath = os.path.join(CHAPTERS_DIR, filename)
        if os.path.exists(filepath):
            with open(filepath, "r", encoding="utf-8") as cf:
                chap_content = cf.read()
            content = content.replace(tag, chap_content + "\n\n---\n\n")
        else:
            print(f"Warning: Missing {filename}")
            
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(content)
        
    print(f"Successfully compiled thesis to {output_file}")
    print("For PDF generation, run: pandoc docs/thesis/SMP_Thesis_Comprehensive.md -o SMP_Thesis.pdf --pdf-engine=xelatex")

if __name__ == "__main__":
    compile_thesis()
