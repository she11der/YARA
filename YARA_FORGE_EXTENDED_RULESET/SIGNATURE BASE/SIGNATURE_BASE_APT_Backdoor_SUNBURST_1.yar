import "pe"

rule SIGNATURE_BASE_APT_Backdoor_SUNBURST_1
{
	meta:
		description = "This rule is looking for portions of the SUNBURST backdoor that are vital to how it functions. The first signature fnv_xor matches a magic byte xor that the sample performs on process, service, and driver names/paths. SUNBURST is a backdoor that has the ability to spawn and kill processes, write and delete files, set and create registry keys, gather system information, and disable a set of forensic analysis tools and services."
		author = "FireEye"
		id = "74b44844-5575-53d7-819b-ab1b2327a144"
		date = "2020-12-14"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_solarwinds_sunburst.yar#L6-L27"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "1fc006dead2fd540717e00e468bf30f37bdb1d061a805e33683e4a77db7f9156"
		score = 85
		quality = 77
		tags = ""

	strings:
		$cmd_regex_encoded = "U4qpjjbQtUzUTdONrTY2q42pVapRgooABYxQuIZmtUoA" wide
		$cmd_regex_plain = { 5C 7B 5B 30 2D 39 61 2D 66 2D 5D 7B 33 36 7D 5C 7D 22 7C 22 5B 30 2D 39 61 2D 66 5D 7B 33 32 7D 22 7C 22 5B 30 2D 39 61 2D 66 5D 7B 31 36 7D }
		$fake_orion_event_encoded = "U3ItS80rCaksSFWyUvIvyszPU9IBAA==" wide
		$fake_orion_event_plain = { 22 45 76 65 6E 74 54 79 70 65 22 3A 22 4F 72 69 6F 6E 22 2C }
		$fake_orion_eventmanager_encoded = "U3ItS80r8UvMTVWyUgKzfRPzEtNTi5R0AA==" wide
		$fake_orion_eventmanager_plain = { 22 45 76 65 6E 74 4E 61 6D 65 22 3A 22 45 76 65 6E 74 4D 61 6E 61 67 65 72 22 2C }
		$fake_orion_message_encoded = "U/JNLS5OTE9VslKqNqhVAgA=" wide
		$fake_orion_message_plain = { 22 4D 65 73 73 61 67 65 22 3A 22 7B 30 7D 22 }
		$fnv_xor = { 67 19 D8 A7 3B 90 AC 5B }

	condition:
		$fnv_xor and ($cmd_regex_encoded or $cmd_regex_plain) or (($fake_orion_event_encoded or $fake_orion_event_plain) and ($fake_orion_eventmanager_encoded or $fake_orion_eventmanager_plain) and ($fake_orion_message_encoded and $fake_orion_message_plain))
}
