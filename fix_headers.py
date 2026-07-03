import os
import re

def fix_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except UnicodeDecodeError:
        print(f"Skipping {filepath} due to UnicodeDecodeError")
        return

    # Regex to match the proprietary header blocks
    pattern = re.compile(
        r'# =============================================================================\n'
        r'# PROPRIETARY SOFTWARE — ALL RIGHTS RESERVED\n'
        r'.*?'
        r'# =============================================================================\n',
        re.DOTALL
    )

    matches = list(pattern.finditer(content))
    if len(matches) > 1:
        # Keep the first match, remove the others
        new_content = content[:matches[1].start()]
        
        last_end = matches[1].start()
        for i in range(1, len(matches)):
            # skip adding the matched content
            pass
            
        last_end = matches[-1].end()
        new_content += content[last_end:]
        
        # Check if the block has the specific text we want to remove, or if we should just remove all extra blocks.
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(new_content)
        print(f"Fixed {filepath} (removed {len(matches) - 1} duplicate headers)")

def walk_dir(directory):
    for root, _, files in os.walk(directory):
        if '.git' in root or '__pycache__' in root or 'node_modules' in root:
            continue
        for file in files:
            if file.endswith('.py') or file.endswith('.ps1') or file.endswith('.sh'):
                fix_file(os.path.join(root, file))

if __name__ == '__main__':
    walk_dir('.')
