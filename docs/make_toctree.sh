#!/bin/bash

# Generate our toc tree for Computer and User policies to reflect the hierarchy in reference
# That way, each key have a complete hierarchy folder structure.
set -eu

# Function to create index.md in a directory
create_index() {
    local dir=$1
    local index_file="$dir/index.md"

    # Get the name of the directory for the title
    local title=$(basename "$dir")

    cat <<EOF > "${index_file}"
# $title

\`\`\`{toctree}
:maxdepth: 99

EOF

    # List directories and files, excluding index.md
    for item in "$dir"/*; do
        if [ -d "$item" ]; then
            # It's a directory, add its index file
            echo "$(basename "$item")/index" >> "$index_file"
        elif [ -f "$item" ] && [ "$(basename "$item")" != "index.md" ]; then
            # It's a file, add it directly to the index
            echo "$(basename "$item" .md)" >> "$index_file"
        fi
    done

    echo '```' >> "$index_file"
}

# Recursive function to walk through directories
walk_dirs() {
    local current_dir=${1%/}

    # Create index in the current directory
    create_index "$current_dir"

    # Recursively walk into subdirectories
    for subdir in "$current_dir"/*/; do
        if [ -d "$subdir" ]; then
            walk_dirs "$subdir"
        fi
    done
}

for d in "$@"; do
    walk_dirs "$d"
done
