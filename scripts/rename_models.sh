#!/usr/bin/env bash

set -e

cd "$(dirname "$0")"

(
  cd ..

  models_dir="models"

  if [[ ! -d "$models_dir" ]]; then
    echo "Ensure that the /$models_dir directory is created."
    exit 1
  fi

  read -rp "Enter directory and file name to append: " name

  if [[ -z "$name" ]]; then
    echo "Input is needed."
    exit 1
  else
    echo "Creating directory $name"
    mkdir -p "$models_dir/$name"
  fi

  for file in "$models_dir"/*; do
    if [[ -f "$file" && "$file" != "$(basename "$0")" ]]; then
      echo "Processing file: $(basename "$file")"
      echo "Renaming to: ${name}_$(basename "$file")"
      echo "Moving files to directory $models_dir/$name"
      mv "$file" "$models_dir/$name/${name}_$(basename "$file")"
    fi
  done
)

trap 'echo "Ensure the filename inside the models dir is not the same as your input"' ERR
