import "pe"

rule VOLEXITY_Apt_Win_Flipflop_Ldr : APT29
{
	meta:
		description = "A loader for the CobaltStrike malware family, which ultimately takes the first and second bytes of an embedded file, and flips them prior to executing the resulting payload."
		author = "threatintel@volexity.com"
		id = "58696a6f-55a9-5212-9372-a539cc327e6b"
		date = "2021-05-25"
		modified = "2021-09-01"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/ae4bcf3413927d976bf3f8ee107bd928c575aded/2021/2021-05-27 - Suspected APT29 Operation Launches Election Fraud Themed Phishing Campaigns/indicators/yara.yar#L3-L19"
		license_url = "https://github.com/volexity/threat-intel/blob/ae4bcf3413927d976bf3f8ee107bd928c575aded/LICENSE.txt"
		hash = "ee42ddacbd202008bcc1312e548e1d9ac670dd3d86c999606a3a01d464a2a330"
		logic_hash = "a79d2b0700ae14f7a2af23c8f7df3df3564402b1137478008ccabefea0f543ad"
		score = 75
		quality = 80
		tags = ""
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$s1 = "irnjadle"
		$s2 = "BADCFEHGJILKNMPORQTSVUXWZY"
		$s3 = "iMrcsofo taBesC yrtpgoarhpciP orived r1v0."

	condition:
		all of ($s*)
}
