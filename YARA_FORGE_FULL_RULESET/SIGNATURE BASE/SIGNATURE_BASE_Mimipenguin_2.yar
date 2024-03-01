rule SIGNATURE_BASE_Mimipenguin_2 : FILE
{
	meta:
		description = "Detects Mimipenguin hack tool"
		author = "Florian Roth (Nextron Systems)"
		id = "b3bb1ba9-cbfc-53fd-81d0-256466ace4de"
		date = "2017-07-08"
		modified = "2023-12-05"
		reference = "https://github.com/huntergregal/mimipenguin"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_mimipenguin.yar#L52-L69"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "53a1f47ef9c94ef6bffbc9d7b9f3a8e0a7fb132c0936ea27e6be775cf99792a0"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "453bffa90d99a820e4235de95ec3f7cc750539e4023f98ffc8858f9b3c15d89a"

	strings:
		$x1 = "DUMP=$(strings \"/tmp/dump.${pid}\" | grep -E" fullword ascii
		$x2 = "strings /tmp/apache* | grep -E '^Authorization: Basic.+=$'" fullword ascii
		$x3 = "grep -E '^_pammodutil_getpwnam_root_1$' -B 5 -A" fullword ascii
		$x4 = "strings \"/tmp/dump.${pid}\" | grep -E -m 1 '^\\$.\\$.+\\$')\"" fullword ascii
		$x5 = "if [[ -n $(ps -eo pid,command | grep -v 'grep' | grep gnome-keyring) ]]; then" fullword ascii

	condition:
		( uint16(0)==0x2123 and filesize <20KB and 1 of them )
}
