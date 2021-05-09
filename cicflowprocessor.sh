#!/bin/bash

root_dir="${1}"
pcap_files=()
log_file="./parsed.txt"
readarray -t pcap_files < <(find "${root_dir}" -type f -name '*.pcap')

for file in "${pcap_files[@]}"
do
	prev_dir="$(dirname ${file})"
	random_name="$(cat /dev/urandom | tr -cd 'a-f0-9' | head -c 7)"
	if grep -xq "${file}" "${log_file}"
	then
	  echo "Already parsed this file ${file}"
	else
	  cicflowmeter -f "${file}" -c "${prev_dir}/${random_name}.csv"
	  echo "${file}" >> "${log_file}"
	fi
done
