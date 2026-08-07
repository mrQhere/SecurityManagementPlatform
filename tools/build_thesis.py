#!/usr/bin/env python3
"""
SMP Academic Thesis Compiler
Combines all academic markdown chapters into a single master document.
"""

import os

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
THESIS_DIR = os.path.join(ROOT_DIR, "docs", "thesis")
CHAPTERS_DIR = os.path.join(THESIS_DIR, "chapters")

def compile_thesis():
    main_file = os.path.join(THESIS_DIR, "main.md")
    output_file = os.path.join(THESIS_DIR, "SMP_Academic_Thesis.md")
    
    with open(main_file, "r", encoding="utf-8") as f:
        content = f.read()
        
    chapter_files = [
        ("{{ CHAPTER_1 }}", "01_abstract_introduction.md"),
        ("{{ CHAPTER_2 }}", "02_related_work.md"),
        ("{{ CHAPTER_3 }}", "03_methodology.md"),
        ("{{ CHAPTER_4 }}", "04_algorithmic_implementation.md"),
        ("{{ CHAPTER_5 }}", "05_cryptography.md"),
        ("{{ CHAPTER_6 }}", "06_evaluation.md"),
        ("{{ CHAPTER_7 }}", "07_discussion_conclusion.md"),
        ("{{ CHAPTER_8 }}", "08_bibliography.md"),
        ("{{ CHAPTER_9 }}", "09_system_integrity.md"),
        ("{{ APPENDIX_A }}", "10_scanner_compendium.md"),
        ("{{ APPENDIX_B }}", "11_database_schemas.md"),
    ]
    
    for tag, filename in chapter_files:
        filepath = os.path.join(CHAPTERS_DIR, filename)
        if os.path.exists(filepath):
            with open(filepath, "r", encoding="utf-8") as cf:
                chap_content = cf.read()
            content = content.replace(tag, chap_content + "\n\n")
        else:
            print(f"Warning: Missing {filename}")
            
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(content)
        
    print(f"Successfully compiled massive academic thesis to {output_file}")

if __name__ == "__main__":
    compile_thesis()
