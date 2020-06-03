#!/bin/bash
#############################################################################################
#                                                                                           #
#       ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄        #
#      ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌       #
#       ▀▀▀▀█░█▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀  ▀▀▀▀█░█▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀        #
#           ▐░▌     ▐░▌       ▐░▌▐░▌          ▐░▌               ▐░▌     ▐░▌                 #
#           ▐░▌     ▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄▄▄      ▐░▌     ▐░█▄▄▄▄▄▄▄▄▄        #
#           ▐░▌     ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌     ▐░▌     ▐░░░░░░░░░░░▌       #
#           ▐░▌     ▐░█▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀▀▀      ▐░▌      ▀▀▀▀▀▀▀▀▀█░▌       #
#           ▐░▌     ▐░▌                    ▐░▌▐░▌               ▐░▌               ▐░▌       #
#       ▄▄▄▄█░█▄▄▄▄ ▐░▌           ▄▄▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄▄▄      ▐░▌      ▄▄▄▄▄▄▄▄▄█░▌       #
#      ▐░░░░░░░░░░░▌▐░▌          ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌     ▐░▌     ▐░░░░░░░░░░░▌       #
#       ▀▀▀▀▀▀▀▀▀▀▀  ▀            ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀       ▀       ▀▀▀▀▀▀▀▀▀▀▀        #
#                                                                                           #
# * Manual and automatic managed interface for ipset                                        #
# * Blacklist individual IPs, IP CIDRs, Domains, ASNs, countries                            #
# * Override Blacklists with Whitelists                                                     #
# * Whitelist individual IPs, IP CIDRs, Domains, ASNs, countries                            #
#                                                                                           #
# Ayitaka                                                                                   #
#                                                                                           #
# Originally based in part on Skynet for Asus Routers by Adamm00                            #
# https://github.com/Adamm00/IPSet_ASUS                                                     #
#                                                                                           #
#############################################################################################
#                                                                                           #
# Syntax:                                                                                   #
#   ipsets blacklist|whitelist add|del ip       123.456.789                 ["comment"]     #
#   ipsets blacklist|whitelist add|del cidr     123.456.789/32              ["comment"]     #
#   ipsets blacklist|whitelist add|del domain   www.example.com             ["comment"]     #
#   ipsets blacklist|whitelist add|del country  "cn tw ve br"               ["comment"]     #
#   ipsets blacklist|whitelist add|del asn      "AS714 AS12222 AS16625"     ["comment"]     #
#   ipsets blacklist|whitelist list|del comment "reg.*ex(patt|ern)?"                        #
#   ipsets start                                                                            #
#   ipsets restart                                                                          #
#   ipsets stop                                                                             #
#   ipsets save [all|whitelist|whitelistcidr|blacklist|blacklistcidr]   (Default: all)      #
#   ipsets refresh                                                                          #
#   ipsets stats                                                                            #
#   ipsets reset                                                                            #
#   ipsets install                                                                          #
#   ipsets uninstall                                                                        #
#                                                                                           #
#       NOTE: List of country codes:                                                        #
#               https://www.iso.org/obp/ui/#search                                          #
#                                                                                           #
#       NOTE: Lists of ASNs:                                                                #
#               https://ipinfo.io/countries                                                 #
#               https://www.cc2asn.com/                                                     #
#                                                                                           #
#############################################################################################

VERSION='v1.0.0'
LAST_MODIFIED='2020-06-03'

IPSETS_DIR="/etc/ipsets"
CONF_DIR="${IPSETS_DIR}/conf"
CACHE_DIR="${IPSETS_DIR}/cache"
LISTS_DIR="${IPSETS_DIR}/savelists"
LOG_DIR="/var/log/ipsets"
LOG_FILE="${LOG_DIR}/ipsets.log"

IPSET_FILE="${CONF_DIR}/combined.ipset"

# config files
WHITELIST_DEFAULTS_FILE="${CONF_DIR}/whitelist_defaults.conf"
BLACKLIST_COUNTRIES_FILE="${CONF_DIR}/blacklist_countries.conf"
BLOCKLISTS_FILE="${CONF_DIR}/blocklists.conf"

# ipset individual save files
WHITELIST_FILE="${LISTS_DIR}/whitelist.ipset"
WHITELISTCIDR_FILE="${LISTS_DIR}/whitelistcidr.ipset"
BLACKLIST_FILE="${LISTS_DIR}/blacklist.ipset"
BLACKLISTCIDR_FILE="${LISTS_DIR}/blacklistcidr.ipset"

#WHITELIST_MANUAL_FILE="${LISTS_DIR}/whitelist_manual.ipset"
#WHITELISTCIDR_MANUAL_FILE="${LISTS_DIR}/whitelistcidr_manual.ipset"
#BLACKLIST_MANUAL_FILE="${LISTS_DIR}/blacklist_manual.ipset"
#BLACKLISTCIDR_MANUAL_FILE="${LISTS_DIR}/blacklistcidr_manual.ipset"

WHITELISTCOMBINED_FILE="${LISTS_DIR}/whitelistcombined.ipset"
BLACKLISTCOMBINED_FILE="${LISTS_DIR}/blacklistcombined.ipset"

#COUNTRY_LIST=''

LOG () {
	local nowtime
	nowtime="$(date "+%F-%H%M%S")"

	if [ ! -d "$LOG_DIR" ]; then mkdir -p $LOG_DIR; fi

	echo "${nowtime} - ipsets: ${*}" >> $LOG_FILE
}

Ifconfig_IPs () {
	/sbin/ifconfig | grep inet | awk '{print $2}'
}

Filter_IPLine () {
	grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}'
}

Domain_Lookup () {
	nslookup "$1" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | awk 'NR>2'
}

Get_File () {
		local file
		file="${CACHE_DIR}/$( echo "$1" | sed 's/https:\/\///g' )"
		local base
		base="$( echo "$file" | sed 's/\/[^\/]*.$//g' )"

		if [ ! -d "${base}" ]; then mkdir -p "${base}"; fi

		if [ ! -f "${file}" ]; then
				curl -fsL -o "${file}" --retry 3 "$1";
		else
				curl -z "${file}" -fsL -o "${file}" --retry 3 "$1"
		fi

		cat "${file}"
}

Exec_IPSets () {
	/sbin/ipset "$@"
}

Whitelist_Defaults () {
	local ipsets='';
	for ip in $(Ifconfig_IPs); do
		ipsets+="add Whitelist_TEMP $ip comment \"Whitelist_Defaults: ifconfig\""$'\n';
	done

	#whitelist_defaults.conf syntax: ip/cidr any comment you want to add
	#1.2.3.4/5 Banned for malware
	#Need to add check for domain names
	while IFS= read -r line
	do
		ipsets+="$( echo "$line" | sed -E 's/^([^ ]+) (.*)$/add Whitelist_TEMP \1 comment \"Whitelist_Defaults: \2\"/' )"$'\n'
	done < $WHITELIST_DEFAULTS_FILE

	local domains="ipinfo.io
			ipdeny.com
			ipapi.co
			iplists.firehol.org
			raw.githubusercontent.com
			www.cloudflare.com
			ip-ranges.amazonaws.com
	"

	for domain in $( echo "$domains" | tr -d "\t" ); do
		for ip in $(Domain_Lookup "$domain"); do
				ipsets+="add Whitelist_TEMP $ip comment \"Whitelist_Defaults: ${domain}\""$'\n'
		done
	done

	#echo "$ipsets" | tr -d "\t" | Filter_IPLine | /sbin/ipset restore -!
	local whitelist
	whitelist="$(echo "${ipsets}" | grep -oE '.*([0-9]{1,3}\.){3}[0-9]{1,3}\s+.*' )"
	local whitelistcidr
	whitelistcidr="$( echo "${ipsets}" | grep -oE '.*([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}.*' | sed 's~add Whitelist_TEMP~add WhitelistCIDR_TEMP~g' )"

	echo "$whitelist" | /sbin/ipset restore -!
	echo "$whitelistcidr" | /sbin/ipset restore -!
}

Whitelist_CDN () {
	local ipsets=''
	for asn in AS714 AS12222 AS16625 AS33438 AS20446 AS54113; do
		ipsets+="$(Get_File "https://ipinfo.io/$asn" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}' | awk -v asn="$asn" '{printf "add WhitelistCIDR_TEMP %s comment \"Whitelist_CDN: %s\"\n", $1, asn }')"$'\n'
	done
	wait

	ipsets+="$(Get_File https://www.cloudflare.com/ips-v4 | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}' | awk '{printf "add WhitelistCIDR_TEMP %s comment \"Whitelist_CDN: CloudFlare\"\n", $1 }')"$'\n'
	ipsets+="$(Get_File https://ip-ranges.amazonaws.com/ip-ranges.json | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}' | awk '{printf "add WhitelistCIDR_TEMP %s comment \"Whitelist_CDN: Amazon\"\n", $1 }')"$'\n'

	echo "$ipsets" | /sbin/ipset restore -!
}

Blacklist_Countries () {
	local ipsets=''

	#blacklist_countries.conf syntax: country_code any comment you want to add
	#cn Banned for malware
	while IFS= read -r line
	do
		local country
		country="$( echo "$line" | awk '{print $1}' )"
		local comment
		comment="$( echo "$line" | sed -E 's/^[^ ]+ (.*$)/\1/' )"

		ipsets+="$(Get_File "https://ipdeny.com/ipblocks/data/aggregated/${country}-aggregated.zone" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}' | awk -v country="$country" -v comment="$comment" '{printf "add BlacklistCIDR_TEMP %s comment \"Blacklist_Country: %s %s\"\n", $1, country, comment }')"$'\n'
	done < $BLACKLIST_COUNTRIES_FILE
	wait

#	for country in $COUNTRY_LIST; do
#		ipsets+="$(Get_File "https://ipdeny.com/ipblocks/data/aggregated/${country}-aggregated.zone" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}' | awk -v country="$country" '{printf "add BlacklistCIDR_TEMP %s comment \"Blacklist_Country: %s\"\n", $1, country }')"$'\n'
#	done
#	wait

	echo "$ipsets" | /sbin/ipset restore -!
}

Blacklist_BlockLists () {
	local ipsets=''

	#blocklists.conf syntax: url
	#https://www.example.com/maleware.ipset
	while IFS= read -r line
	do
		ipsets+="$(Get_File "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' | awk -v blocklist="$line" '{printf "add Blacklist_TEMP %s comment \"Blacklist_BlockLists: %s\"\n", $1, blocklist }')"$'\n'
	done < $BLOCKLISTS_FILE

#	for blocklist in $( echo "$blocklists" | tr -d "\t" ); do
#		ipsets+="$(Get_File "$blocklist" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' | awk -v blocklist="$blocklist" '{printf "add Blacklist_TEMP %s comment \"Blacklist_BlockLists: %s\"\n", $1, blocklist }')"$'\n'
#	done
#    wait

	local blacklist
	blacklist="$(echo "${ipsets}" | grep -oE '.*([0-9]{1,3}\.){3}[0-9]{1,3}\s+.*' )"
	local blacklistcidr
	blacklistcidr="$( echo "${ipsets}" | grep -oE '.*([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}.*' | sed 's~add Blacklist_TEMP~add BlacklistCIDR_TEMP~g' )"

	echo "$blacklist" | /sbin/ipset restore -!
	echo "$blacklistcidr" | /sbin/ipset restore -!
}

Add_Iptables () {
	# Add rules if they do not exist
	if ! iptables -nL IPSETS-LOGDROP 2>/dev/null; then
		iptables -N IPSETS-LOGDROP 2>/dev/null
	fi

	if ! iptables -C IPSETS-LOGDROP -m limit --limit 3/min -j LOG --log-prefix "[IPSETS BLOCKED] " --log-level 4 2>/dev/null; then
		iptables -A IPSETS-LOGDROP -m limit --limit 3/min -j LOG --log-prefix "[IPSETS BLOCKED] " --log-level 4 2>/dev/null
	fi

	if ! iptables -C IPSETS-LOGDROP -j DROP 2>/dev/null; then
		iptables -A IPSETS-LOGDROP -j DROP 2>/dev/null
	fi

	if ! iptables -C INPUT -m set ! --match-set WhitelistCombined src -m set --match-set BlacklistCombined src -j IPSETS-LOGDROP 2>/dev/null; then
		iptables -I INPUT -m set ! --match-set WhitelistCombined src -m set --match-set BlacklistCombined src -j IPSETS-LOGDROP 2>/dev/null
	fi

	if ! iptables -C FORWARD -m set ! --match-set WhitelistCombined src -m set --match-set BlacklistCombined src -j IPSETS-LOGDROP 2>/dev/null; then
		iptables -I FORWARD -m set ! --match-set WhitelistCombined src -m set --match-set BlacklistCombined src -j IPSETS-LOGDROP 2>/dev/null
	fi

	if ! iptables -C FORWARD -m set ! --match-set WhitelistCombined dst -m set --match-set BlacklistCombined dst -j IPSETS-LOGDROP 2>/dev/null; then
		iptables -I FORWARD -m set ! --match-set WhitelistCombined dst -m set --match-set BlacklistCombined dst -j IPSETS-LOGDROP 2>/dev/null
	fi

	if ! iptables -C OUTPUT -m set ! --match-set WhitelistCombined dst -m set --match-set BlacklistCombined dst -j IPSETS-LOGDROP 2>/dev/null; then
		iptables -I OUTPUT -m set ! --match-set WhitelistCombined dst -m set --match-set BlacklistCombined dst -j IPSETS-LOGDROP 2>/dev/null
	fi
}

Delete_Iptables () {
	iptables -D INPUT -m set ! --match-set WhitelistCombined src -m set --match-set BlacklistCombined src -j IPSETS-LOGDROP 2>/dev/null;
	iptables -D FORWARD -m set ! --match-set WhitelistCombined src -m set --match-set BlacklistCombined src -j IPSETS-LOGDROP 2>/dev/null
	iptables -D FORWARD -m set ! --match-set WhitelistCombined dst -m set --match-set BlacklistCombined dst -j IPSETS-LOGDROP 2>/dev/null
	iptables -D OUTPUT -m set ! --match-set WhitelistCombined dst -m set --match-set BlacklistCombined dst -j IPSETS-LOGDROP 2>/dev/null;

	# Flush chain
	iptables -F IPSETS-LOGDROP 2>/dev/null

	# Delete chain
	iptables -X IPSETS-LOGDROP 2>/dev/null
}

Save_IPSets () {
	if [ -z "$1" ]; then
		{ /sbin/ipset save Whitelist; /sbin/ipset save WhitelistCIDR; /sbin/ipset save Blacklist; /sbin/ipset save BlacklistCIDR; /sbin/ipset save Whitelist_Manual; /sbin/ipset save WhitelistCIDR_Manual; /sbin/ipset save Blacklist_Manual; /sbin/ipset save BlacklistCIDR_Manual; /sbin/ipset save WhitelistCombined; /sbin/ipset save BlacklistCombined; } > "$IPSET_FILE"
	else
		case "$1" in
			whitelist)
				/sbin/ipset save Whitelist > "$WHITELIST_FILE"
			;;
			whitelistcidr)
				/sbin/ipset save WhitelistCIDR > "$WHITELISTCIDR_FILE"
			;;
			blacklist)
				/sbin/ipset save Blacklist > "$BLACKLIST_FILE"
			;;
			blacklistcidr)
				/sbin/ipset save BlacklistCIDR > "$BLACKLISTCIDR_FILE"
			;;
			whitelist_manual)
				/sbin/ipset save Whitelist > "$WHITELIST_FILE"
			;;
			whitelistcidr_manual)
				/sbin/ipset save WhitelistCIDR > "$WHITELISTCIDR_FILE"
			;;
			blacklist_manual)
				/sbin/ipset save Blacklist > "$BLACKLIST_FILE"
			;;
			blacklistcidr_manual)
				/sbin/ipset save BlacklistCIDR > "$BLACKLISTCIDR_FILE"
			;;
			whitelistcombined)
				/sbin/ipset save WhitelistCombined > "$WHITELISTCOMBINED_FILE"
			;;
			blacklistcombined)
				/sbin/ipset save BlacklistCombined > "$BLACKLISTCOMBINED_FILE"
			;;
			all)
				/sbin/ipset save Whitelist > "$WHITELIST_FILE"
				/sbin/ipset save WhitelistCIDR > "$WHITELISTCIDR_FILE"
				/sbin/ipset save Blacklist > "$BLACKLIST_FILE"
				/sbin/ipset save BlacklistCIDR > "$BLACKLISTCIDR_FILE"
				/sbin/ipset save Whitelist_Manual > "$WHITELIST_FILE"
				/sbin/ipset save WhitelistCIDR_Manual > "$WHITELISTCIDR_FILE"
				/sbin/ipset save Blacklist_Manual > "$BLACKLIST_FILE"
				/sbin/ipset save BlacklistCIDR_Manual > "$BLACKLISTCIDR_FILE"
				/sbin/ipset save WhitelistCombined > "$WHITELISTCOMBINED_FILE"
				/sbin/ipset save BlacklistCombined > "$BLACKLISTCOMBINED_FILE"
			;;
			combined)
				{ /sbin/ipset save Whitelist; /sbin/ipset save WhitelistCIDR; /sbin/ipset save Blacklist; /sbin/ipset save BlacklistCIDR; /sbin/ipset save Whitelist_Manual; /sbin/ipset save WhitelistCIDR_Manual; /sbin/ipset save Blacklist_Manual; /sbin/ipset save BlacklistCIDR_Manual; /sbin/ipset save WhitelistCombined; /sbin/ipset save BlacklistCombined; } > "$IPSET_FILE"
			;;
			*)
				{ /sbin/ipset save Whitelist; /sbin/ipset save WhitelistCIDR; /sbin/ipset save Blacklist; /sbin/ipset save BlacklistCIDR; /sbin/ipset save Whitelist_Manual; /sbin/ipset save WhitelistCIDR_Manual; /sbin/ipset save Blacklist_Manual; /sbin/ipset save BlacklistCIDR_Manual; /sbin/ipset save WhitelistCombined; /sbin/ipset save BlacklistCombined; } > "$IPSET_FILE"
			;;
		esac
	fi
}

Swap_IPSets () {
	/sbin/ipset -q swap "${1}_TEMP" "${1}" 2>/dev/null
	/sbin/ipset -q flush "${1}_TEMP" 2>/dev/null
	/sbin/ipset -q destroy "${1}_TEMP" 2>/dev/null
}

Refresh_IPSets () {
	if ! /sbin/ipset -L -n Whitelist_TEMP >/dev/null 2>&1; then /sbin/ipset -q create Whitelist_TEMP hash:ip --maxelem 500000 comment; else /sbin/ipset -q flush Whitelist_TEMP 2>/dev/null; fi
	if ! /sbin/ipset -L -n WhitelistCIDR_TEMP >/dev/null 2>&1; then /sbin/ipset -q create WhitelistCIDR_TEMP hash:net --maxelem 200000 comment; else /sbin/ipset -q flush WhitelistCIDR_TEMP 2>/dev/null; fi
	if ! /sbin/ipset -L -n Blacklist_TEMP >/dev/null 2>&1; then /sbin/ipset -q create Blacklist_TEMP hash:ip --maxelem 500000 comment; else /sbin/ipset -q flush Blacklist_TEMP 2>/dev/null; fi
	if ! /sbin/ipset -L -n BlacklistCIDR_TEMP >/dev/null 2>&1; then /sbin/ipset -q create BlacklistCIDR_TEMP hash:net --maxelem 200000 comment; else /sbin/ipset -q flush BlacklistCIDR_TEMP 2>/dev/null; fi

	Whitelist_Defaults
	Whitelist_CDN
	Blacklist_Countries
	Blacklist_BlockLists

	Swap_IPSets Whitelist
	Swap_IPSets WhitelistCIDR
	Swap_IPSets Blacklist
	Swap_IPSets BlacklistCIDR

	Save_IPSets combined
}

Reset_IPSets () {
	/sbin/ipset flush
	/sbin/ipset destroy
	Delete_Iptables
	rm -f $IPSET_FILE
	Start_IPSets
}

Start_IPSets () {
	if [ ! -d "$IPSETS_DIR" ]; then mkdir -p $IPSETS_DIR; fi
	if [ ! -d "$CACHE_DIR" ]; then mkdir -p $CACHE_DIR; fi
	if [ ! -d "$LISTS_DIR" ]; then mkdir -p $LISTS_DIR; fi

	# restore/create combined.ipset
	if [ -f "$IPSET_FILE" ]; then
		/sbin/ipset restore -! -f "$IPSET_FILE";
	else
		touch "$IPSET_FILE";
	fi

	if ! /sbin/ipset -L -n Whitelist >/dev/null 2>&1; then /sbin/ipset -q create Whitelist hash:ip --maxelem 500000 comment; fi
	if ! /sbin/ipset -L -n WhitelistCIDR >/dev/null 2>&1; then /sbin/ipset -q create WhitelistCIDR hash:net --maxelem 200000 comment; fi
	if ! /sbin/ipset -L -n Blacklist >/dev/null 2>&1; then /sbin/ipset -q create Blacklist hash:ip --maxelem 500000 comment; fi
	if ! /sbin/ipset -L -n BlacklistCIDR >/dev/null 2>&1; then /sbin/ipset -q create BlacklistCIDR hash:net --maxelem 200000 comment; fi
	if ! /sbin/ipset -L -n Whitelist_Manual >/dev/null 2>&1; then /sbin/ipset -q create Whitelist_Manual hash:ip --maxelem 500000 comment; fi
	if ! /sbin/ipset -L -n WhitelistCIDR_Manual >/dev/null 2>&1; then /sbin/ipset -q create WhitelistCIDR_Manual hash:net --maxelem 200000 comment; fi
	if ! /sbin/ipset -L -n Blacklist_Manual >/dev/null 2>&1; then /sbin/ipset -q create Blacklist_Manual hash:ip --maxelem 500000 comment; fi
	if ! /sbin/ipset -L -n BlacklistCIDR_Manual >/dev/null 2>&1; then /sbin/ipset -q create BlacklistCIDR_Manual hash:net --maxelem 200000 comment; fi
	if ! /sbin/ipset -L -n WhitelistCombined >/dev/null 2>&1; then /sbin/ipset -q create WhitelistCombined list:set; /sbin/ipset -q -A WhitelistCombined Whitelist; /sbin/ipset -q -A WhitelistCombined WhitelistCIDR; /sbin/ipset -q -A WhitelistCombined Whitelist_Manual; /sbin/ipset -q -A WhitelistCombined WhitelistCIDR_Manual; fi
	if ! /sbin/ipset -L -n BlacklistCombined >/dev/null 2>&1; then /sbin/ipset -q create BlacklistCombined list:set; /sbin/ipset -q -A BlacklistCombined Blacklist; /sbin/ipset -q -A BlacklistCombined BlacklistCIDR; /sbin/ipset -q -A BlacklistCombined Blacklist_Manual; /sbin/ipset -q -A BlacklistCombined BlacklistCIDR_Manual; fi

	Refresh_IPSets

	Add_Iptables
}

Stop_IPSets () {
	Save_IPSets combined

	Delete_Iptables

	/sbin/ipset flush
	/sbin/ipset destroy
}

Action_IPSets () {
	local list="$1"
	local action="$2"
	local actionlong="$2"
	local type="$3"
	local value="$4"
	local comment="$5"
	local ipsets=''
	local blackwhite="${list}"
	local adddel=''
	local tofrom=''

	case "$action" in
		add)
			adddel="added"
			tofrom="to"
		;;
		del)
			adddel="deleted"
			tofrom="from"
		;;
	esac

	actionlong+=" ${list}"

	case "$type" in
		ip)
			if [ "$action" == "del" ]; then comment=''; else comment=" comment \"${blackwhite}list_Manual: ${comment}\""; fi
			ipsets+="${actionlong}_Manual ${value}${comment}"
			LOG "IPSets ${adddel} IP ${value} ${tofrom} ${blackwhite}_Manual (${comment})"
		;;
		cidr)
			if [ "$action" == "del" ]; then comment=''; else comment=" comment \"${blackwhite}CIDR_Manual: ${comment}\""; fi
			ipsets+="${actionlong}CIDR_Manual ${value}${comment}"
			LOG "IPSets ${adddel} CIDR ${value} ${tofrom} ${blackwhite}CIDR_Manual (${comment})"
		;;
		domain)
			sed "\\~Blacklist_Manual: Domain ${value}~!d;s~ comment.*~~;s~add~del~g" "$IPSET_FILE" | /sbin/ipset restore -!
			if [ ! "$action" == "del" ]; then
				for ip in $(Domain_Lookup "$value"); do
					ipsets+="${actionlong}_Manual ${ip} comment \"Blacklist_Manual: Domain ${value} ${comment}\""
					LOG "IPSets ${adddel} Domain ${value} (${ip}) ${tofrom} ${blackwhite}_Manual (${comment})"
				done
			else
				LOG "IPSets ${adddel} Domain ${value} ${tofrom} ${blackwhite}_Manual (${comment})"
			fi
		;;
		country)
			for country in $value; do
				sed "\\~Blacklist_Country: ${country}~!d;s~ comment.*~~;s~add~del~g" "$IPSET_FILE" | /sbin/ipset restore -!

				if [ ! "$action" == "del" ]; then
					ipsets+="$(Get_File "https://ipdeny.com/ipblocks/data/aggregated/${country}-aggregated.zone" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}' | awk -v action="${actionlong}CIDR" -v country="$country" -v comment="\"Blacklist_Country: ${country} ${comment}\"" '{printf "%s %s comment %s\n", action, $1, comment}')"$'\n'
				fi
				LOG "IPSets ${adddel} Country ${country} ${tofrom} ${blackwhite}CIDR (${comment})"
			done
			wait
		;;
		asn)
			for asn in $value; do
				sed "\\~Blacklist_ASN ${asn}~!d;s~ comment.*~~;s~add~del~g" "$IPSET_FILE" | /sbin/ipset restore -!
				if [ ! "$action" == "del" ]; then
					ipsets+="$(Get_File "https://ipinfo.io/$asn" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}' | awk -v action="${actionlong}CIDR" -v asn="$asn" -v comment="\"Blacklist_ASN: ${asn} ${comment}\"" '{printf "%s %s comment %s\n", action, $1, comment }')"$'\n'
				fi
				LOG "IPSets ${adddel} ASN ${asn} ${tofrom} ${blackwhite}CIDR (${comment})"
			done
			wait
		;;
		comment)
			regex="/^add ${blackwhite}(CIDR)?(_Manual)? ${value}/I!d"
			case "$action" in
				list)
					sed -r "${regex}" "$IPSET_FILE"
					LOG "IPSets listed matches to regex ${regex} in comments from ${blackwhite}s"
				;;
				del)
					sed -r "${regex};s~ comment.*~~;s~add~del~g" "$IPSET_FILE" | /sbin/ipset restore -!
					LOG "IPSets deleted matches to regex ${regex} in comments from ${blackwhite}s"
				;;
			esac
		;;
	esac

	if [ -n "$ipsets" ]; then
		echo "$ipsets" | /sbin/ipset restore -!
	fi

	Save_IPSets combined
}

Stats_IPSets () {
	whitelistlines=$( /sbin/ipset -L -t Whitelist | grep 'Number of entries:' | awk '{print $4}' )
	whitelistcidrlines=$( /sbin/ipset -L -t WhitelistCIDR | grep 'Number of entries:' | awk '{print $4}' )
	whitelist_manual_lines=$( /sbin/ipset -L -t Whitelist_Manual | grep 'Number of entries:' | awk '{print $4}' )
	whitelistcidr_manual_lines=$( /sbin/ipset -L -t WhitelistCIDR_Manual | grep 'Number of entries:' | awk '{print $4}' )
	whitelisttotal=$(( whitelistlines + whitelistcidrlines + whitelist_manual_lines + whitelistcidr_manual_lines ))
	blacklistlines=$( /sbin/ipset -L -t Blacklist | grep 'Number of entries:' | awk '{print $4}' )
	blacklistcidrlines=$( /sbin/ipset -L -t BlacklistCIDR | grep 'Number of entries:' | awk '{print $4}' )
	blacklist_manual_lines=$( /sbin/ipset -L -t Blacklist_Manual | grep 'Number of entries:' | awk '{print $4}' )
	blacklistcidr_manual_lines=$( /sbin/ipset -L -t BlacklistCIDR_Manual | grep 'Number of entries:' | awk '{print $4}' )
	blacklisttotal=$(( blacklistlines + blacklistcidrlines + blacklist_manual_lines + blacklistcidr_manual_lines ))
	totallines=$(( whitelistlines + blacklistlines + whitelistcidrlines + blacklistcidrlines + whitelist_manual_lines + blacklist_manual_lines + whitelistcidr_manual_lines + blacklistcidr_manual_lines ))

	echo "------------------------------"
	echo "IPSets Stats"
	echo "------------------------------"
	echo "Whitelist: 		${whitelistlines}"
	echo "WhitelistCIDR: 		${whitelistcidrlines}"
	echo "Whitelist_Manual: 	${whitelist_manual_lines}"
	echo "WhitelistCIDR_Manual: 	${whitelistcidr_manual_lines}"
	echo "Whitelist Total: 	$whitelisttotal"
	echo "------------------------------"
	echo "Blacklist: 		${blacklistlines}"
	echo "BlacklistCIDR: 		${blacklistcidrlines}"
	echo "Blacklist_Manual: 	${blacklist_manual_lines}"
	echo "BlacklistCIDR_Manual: 	${blacklistcidr_manual_lines}"
	echo "Blacklist Total: 	$blacklisttotal"
	echo "------------------------------"
	echo "Total Entries: 		${totallines}"
	echo "------------------------------"
}

Install_IPSets () {
	if [ ! -d "$IPSETS_DIR" ]; then mkdir -p $IPSETS_DIR; fi
	if [ ! -d "$CONF_DIR" ]; then mkdir -p $CONF_DIR; fi
	if [ ! -d "$CACHE_DIR" ]; then mkdir -p $CACHE_DIR; fi
	if [ ! -d "$LISTS_DIR" ]; then mkdir -p $LISTS_DIR; fi

	# Copy script to IPSETS_DIR
	cp -f "$0" $IPSETS_DIR

	ln -s /etc/ipsets/ipsets.sh /sbin/ipsets

	echo '	127.0.0.0/8 localhost CIDR
			192.30.252.0/22 Github Content Server' | tr -d "\t" > $WHITELIST_DEFAULTS_FILE

	echo '	' | tr -d "\t" > $BLACKLIST_COUNTRIES_FILE

	echo '	https://iplists.firehol.org/files/alienvault_reputation.ipset
			https://iplists.firehol.org/files/bds_atif.ipset
			https://iplists.firehol.org/files/bi_sshd_2_30d.ipset
			https://iplists.firehol.org/files/blocklist_net_ua.ipset
			https://iplists.firehol.org/files/coinbl_ips.ipset
			https://iplists.firehol.org/files/cybercrime.ipset
			https://iplists.firehol.org/files/dyndns_ponmocup.ipset
			https://iplists.firehol.org/files/et_block.netset
			https://iplists.firehol.org/files/et_compromised.ipset
			https://iplists.firehol.org/files/firehol_level2.netset
			https://iplists.firehol.org/files/firehol_level3.netset
			https://iplists.firehol.org/files/normshield_high_attack.ipset
			https://iplists.firehol.org/files/normshield_high_bruteforce.ipset
			https://iplists.firehol.org/files/ransomware_online.ipset
			https://iplists.firehol.org/files/ransomware_rw.ipset
			https://iplists.firehol.org/files/spamhaus_edrop.netset
			https://iplists.firehol.org/files/urandomusto_ssh.ipset
			https://iplists.firehol.org/files/urandomusto_telnet.ipset
			https://iplists.firehol.org/files/urlvir.ipset
			https://iplists.firehol.org/files/uscert_hidden_cobra.ipset' | tr -d "\t" > $BLOCKLISTS_FILE

	if [ -d /etc/rsyslog.d/ ]; then
		echo '	# Log kernel generated ipsets log messages to file
				:msg,contains,"[IPSETS " /var/log/ipsets/blocked.log

				# Uncomment the following to stop logging anything that matches the last rule.
				# Doing this will stop logging kernel generated ipsets log messages to the file
				# normally containing kern.* messages (eg, /var/log/kern.log)
				& stop' | tr -d "\t" > /etc/rsyslog.d/20-ipsets.conf

		service rsyslog restart >/dev/null 2>&1
	fi

	if [ -d /etc/logrotate.d ]; then
		echo '	/var/log/ipsets/blocked.log
				{
					rotate 10
					daily
					missingok
					notifempty
					compress
					delaycompress
					sharedscripts
					postrotate
						invoke-rc.d rsyslog rotate >/dev/null 2>&1 || true
					endscript
				}' | tr -d "\t" > /etc/logrotate.d/ipsets
	fi

	# systemd service
	echo '	[Unit]
			Description=IPSets
			DefaultDependencies=no
			Before=network.target
			After=ufw.service

			[Service]
			Type=oneshot
			RemainAfterExit=yes
			ExecStart=/etc/ipsets/ipsets.sh start
			ExecStop=/etc/ipsets/ipsets.sh stop

			[Install]
			WantedBy=multi-user.target' | tr -d "\t" > /lib/systemd/system/ipsets.service

	echo '	[Unit]
			Description=IPSets Refresh

			[Service]
			Type=oneshot
			ExecStart=/etc/ipsets/ipsets.sh refresh' | tr -d "\t" > /lib/systemd/system/ipsets-refresh.service

	echo '	[Unit]
			Description=Run "ipsets refresh" four times daily

			[Timer]
			OnCalendar=*-*-* 00,06,12,18:00:00
			RandomizedDelaySec=600
			Persistent=true

			[Install]
			WantedBy=timers.target' | tr -d "\t" > /lib/systemd/system/ipsets-refresh.timer

	chmod a+r /lib/systemd/system/ipsets.service 2>&1
	chmod a+r /lib/systemd/system/ipsets-refresh.service 2>&1
	chmod a+r /lib/systemd/system/ipsets-refresh.timer 2>&1

	systemctl daemon-reload >/dev/null 2>&1
	systemctl enable --now ipsets.service >/dev/null 2>&1
	#systemctl start ipsets.service >/dev/null 2>&1
	systemctl enable --now ipsets-refresh.timer >/dev/null 2>&1
	#systemctl start ipsets-refresh.timer >/dev/null 2>&1

	LOG "IPSets installed"
	echo "IPSets: Insallation complete!"
}

Uninstall_IPSets () {
	systemctl disable --now ipsets-refresh.timer >/dev/null 2>&1
	#systemctl stop ipsets-refresh.timer >/dev/null 2>&1
	#systemctl --user stop ipsets-refresh.timer 2>&1
	systemctl disable --now ipsets.service >/dev/null 2>&1
	#systemctl stop ipsets.service >/dev/null 2>&1
	systemctl daemon-reload >/dev/null 2>&1
	rm -f /lib/systemd/system/ipsets-refresh.timer >/dev/null 2>&1
	rm -f /lib/systemd/system/ipsets-refresh.service >/dev/null 2>&1
	rm -f /lib/systemd/system/ipsets.service >/dev/null 2>&1
	rm /sbin/ipsets

	rm -f /etc/logrotate.d/ipsets >/dev/null 2>&1

	if [ -f /etc/rsyslog.d/20-ipsets.conf ]; then
		rm -f /etc/rsyslog.d/20-ipsets.conf >/dev/null 2>&1
		service rsyslog restart >/dev/null 2>&1
	fi

	rm -rf $LOG_DIR >/dev/null 2>&1
	rm -rf $LISTS_DIR >/dev/null 2>&1
	rm -rf $CACHE_DIR >/dev/null 2>&1
	rm -rf $IPSETS_DIR >/dev/null 2>&1
}

Help_IPSets () {
		echo "
#############################################################################################
#                                                                                           #
#       ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄        #
#      ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌       #
#       ▀▀▀▀█░█▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀  ▀▀▀▀█░█▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀        #
#           ▐░▌     ▐░▌       ▐░▌▐░▌          ▐░▌               ▐░▌     ▐░▌                 #
#           ▐░▌     ▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄▄▄      ▐░▌     ▐░█▄▄▄▄▄▄▄▄▄        #
#           ▐░▌     ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌     ▐░▌     ▐░░░░░░░░░░░▌       #
#           ▐░▌     ▐░█▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀▀▀      ▐░▌      ▀▀▀▀▀▀▀▀▀█░▌       #
#           ▐░▌     ▐░▌                    ▐░▌▐░▌               ▐░▌               ▐░▌       #
#       ▄▄▄▄█░█▄▄▄▄ ▐░▌           ▄▄▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄▄▄      ▐░▌      ▄▄▄▄▄▄▄▄▄█░▌       #
#      ▐░░░░░░░░░░░▌▐░▌          ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌     ▐░▌     ▐░░░░░░░░░░░▌       #
#       ▀▀▀▀▀▀▀▀▀▀▀  ▀            ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀       ▀       ▀▀▀▀▀▀▀▀▀▀▀        #
#                                                                                           #
# * Manual and automatic managed interface for ipset                                        #
# * Blacklist individual IPs, IP CIDRs, Domains, ASNs, countries                            #
# * Override Blacklists with Whitelists                                                     #
# * Whitelist individual IPs, IP CIDRs, Domains, ASNs, countries                            #
#                                                                                           #
# $VERSION                                                                                    #
# $LAST_MODIFIED                                                                                #
# Ayitaka                                                                                   #
#                                                                                           #
# Originally based in part on Skynet for Asus Routers by Adamm00                            #
# https://github.com/Adamm00/IPSet_ASUS                                                     #
#                                                                                           #
#############################################################################################
#                                                                                           #
# Syntax:                                                                                   #
#   ipsets blacklist|whitelist add|del ip       123.456.789                 [\"comment\"]     #
#   ipsets blacklist|whitelist add|del cidr     123.456.789/32              [\"comment\"]     #
#   ipsets blacklist|whitelist add|del domain   www.example.com             [\"comment\"]     #
#   ipsets blacklist|whitelist add|del country  \"cn tw ve br\"               [\"comment\"]     #
#   ipsets blacklist|whitelist add|del asn      \"AS714 AS12222 AS16625\"     [\"comment\"]     #
#   ipsets blacklist|whitelist list|del comment \"reg.*ex(patt|ern)?\"                        #
#   ipsets start                                                                            #
#   ipsets restart                                                                          #
#   ipsets stop                                                                             #
#   ipsets save [all|whitelist|whitelistcidr|blacklist|blacklistcidr]   (Default: all)      #
#   ipsets refresh                                                                          #
#   ipsets stats                                                                            #
#   ipsets reset                                                                            #
#   ipsets install                                                                          #
#   ipsets uninstall                                                                        #
#                                                                                           #
#       NOTE: List of country codes:                                                        #
#               https://www.iso.org/obp/ui/#search                                          #
#                                                                                           #
#       NOTE: Lists of ASNs:                                                                #
#               https://ipinfo.io/countries                                                 #
#               https://www.cc2asn.com/                                                     #
#                                                                                           #
#############################################################################################
"
}

#############################################################################################
#																							#
# Main Script																				#
#																							#
#############################################################################################

# Command-line arguments
command="$1"
action="$2"
type="$3"
value="$4"
comment="$5"

#if [ -z "$command" ] || { [ "$command" != "whitelist" ] && [ "$command" != "blacklist" ] && [ "$command" != "start" ] && [ "$command" != "restart" ] && [ "$command" != "stop" ] && [ "$command" != "save" ] && [ "$command" != "refresh" ] && [ "$command" != "stats" ] && [ "$command" != "reset" ] && [ "$command" != "install" ] && [ "$command" != "uninstall" ] && [ "$command" != "help" ]; }; then echo "ARG1 must be whitelist, blacklist, start, restart, stop, save, refresh, stats, reset, install, uninstall, or help" && exit; fi
#if [ "$command" == "whitelist" ] || [ "$command" == "blacklist" ]; then
#fi

#LOG "IPSets command: ${@}"

case "$command" in
	blacklist)
		if [ -z "$action" ] || { [ "$action" != "add" ] && [ "$action" != "del" ] && [ "$action" != "list" ]; }; then echo "ARG2 must be add, del, or list" && exit; fi
		if [ -z "$type" ] || { [ "$type" != "ip" ] && [ "$type" != "cidr" ] && [ "$type" != "domain" ] && [ "$type" != "country" ] && [ "$type" != "asn" ] && [ "$type" != "comment" ]; }; then echo "ARG3 must be ip, cidr, domain, country, asn, or comment" && exit; fi
		if [ -z "$value" ]; then echo "ARG4 must not be empty" && exit; fi

		Action_IPSets "Blacklist" "$action" "$type" "$value" "$comment"
	;;
	whitelist)
		if [ -z "$action" ] || { [ "$action" != "add" ] && [ "$action" != "del" ] && [ "$action" != "list" ]; }; then echo "ARG2 must be add, del, or list" && exit; fi
		if [ -z "$type" ] || { [ "$type" != "ip" ] && [ "$type" != "cidr" ] && [ "$type" != "domain" ] && [ "$type" != "country" ] && [ "$type" != "asn" ] && [ "$type" != "comment" ]; }; then echo "ARG3 must be ip, cidr, domain, country, asn, or comment" && exit; fi
		if [ -z "$value" ]; then echo "ARG4 must not be empty" && exit; fi

		Action_IPSets "Whitelist" "$action" "$type" "$value" "$comment"
	;;
	start)
		Start_IPSets
		LOG "IPSets started"
	;;
	restart)
		Stop_IPSets
		Start_IPSets
		LOG "IPSets restarted"
	;;
	stop)
		Stop_IPSets
		LOG "IPSets stopped"
	;;
	save)
		Save_IPSets "$action"
	;;
	refresh)
		Refresh_IPSets
		LOG "IPSets refreshed"
	;;
	stats)
		Stats_IPSets
	;;
	reset)
		Reset_IPSets
		LOG "IPSets reset"
	;;
	install)
		Install_IPSets
	;;
	uninstall)
		Uninstall_IPSets
	;;
	help)
		Help_IPSets
	;;
	*)
		Help_IPSets
	;;
esac

#############################################################################################
#																							#
# TODO           																			#
#																							#
#############################################################################################
#
# * Make whitelist_CDN read from conf file
# * Add import/export of files
# * Add argument checks/validation to various functions (i.e. ip/cidr syntax validation)
# * Refine logging msgs
# * Add to github, create one-line install from github, create update process from github (VERSION.md check)
# * Add different ipset files to Save_IPSets command-line
# - (Done v1.1) Make whitelist_defaults read from conf file
# - (Done v1.1) Make blacklist_countries read from/write to conf file
# - (Done v1.1) Make blocklists read from conf file

#############################################################################################
#																							#
# Version History																			#
#																							#
#############################################################################################
#
#	v0.1.0 - 2020-01-20	First finalized Beta version for personal use
#	v0.1.0 - 2020-06-03	First finalized version
