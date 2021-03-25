#/bin/bash

root_dir="${1}"
pcap_files=()
readarray -t pcap_files < <(find "${root_dir}" -type f -name '*.pcap')

for file in "${pcap_files[@]}"
do
	prev_dir="$(dirname ${file})"
	random_name="$(cat /dev/urandom | tr -cd 'a-f0-9' | head -c 5)"
	cicflowmeter -f "${file}" -c "${prev_dir}/${random_name}.csv"
done
