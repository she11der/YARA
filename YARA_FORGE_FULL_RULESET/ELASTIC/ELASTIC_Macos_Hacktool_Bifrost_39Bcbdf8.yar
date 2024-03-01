rule ELASTIC_Macos_Hacktool_Bifrost_39Bcbdf8 : FILE MEMORY
{
	meta:
		description = "Detects Macos Hacktool Bifrost (MacOS.Hacktool.Bifrost)"
		author = "Elastic Security"
		id = "39bcbdf8-86dc-480e-8822-dc9832bb9b55"
		date = "2021-10-12"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/MacOS_Hacktool_Bifrost.yar#L1-L27"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "e2b64df0add316240b010db7d34d83fc9ac7001233259193e5a72b6e04aece46"
		logic_hash = "a2ff4f1aca51e80f2b277e9171e99a80a75177d1d17d487de2eb8872832cb0d5"
		score = 75
		quality = 25
		tags = "FILE, MEMORY"
		fingerprint = "e11f6f3a847817644d40fee863e168cd2a18e8e0452482c1e652c11fe8dd769e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$s1 = "[dump | list | askhash | describe | asktgt | asktgs | s4u | ptt | remove | asklkdcdomain]" fullword
		$s2 = "[-] Error in parseKirbi: %s"
		$s3 = "[-] Error in parseTGSREP: %s"
		$s4 = "genPasswordHashPassword:Length:Enc:Username:Domain:Pretty:"
		$s5 = "storeLKDCConfDataFriendlyName:Hostname:Password:CCacheName:"
		$s6 = "bifrostconsole-"
		$s7 = "-kerberoast"
		$s8 = "asklkdcdomain"
		$s9 = "askhash"

	condition:
		3 of them
}
