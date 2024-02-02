rule VOLEXITY_Apt_Win_Iconicstealer___UTA0040
{
	meta:
		description = "Detect the ICONICSTEALER malware family."
		author = "threatintel@volexity.com"
		id = "d7896506-6ce5-59b1-b24a-87ffdb2a5174"
		date = "2023-03-30"
		modified = "2023-03-30"
		reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
		source_url = "https://github.com/volexity/threat-intel/blob/af57cbbbd67525bf8ba24e1df4797799165b6f83/2023/2023-03-30 3CX/indicators/rules.yar#L51-L69"
		license_url = "https://github.com/volexity/threat-intel/blob/af57cbbbd67525bf8ba24e1df4797799165b6f83/LICENSE.txt"
		logic_hash = "ed7731d2361e7d96a6a35f8359b61a2af049b16bc457cf870db8831e142aebe2"
		score = 75
		quality = 80
		tags = ""
		hash1 = "8ab3a5eaaf8c296080fadf56b265194681d7da5da7c02562953a4cb60e147423"
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$str1 = "\\3CXDesktopApp\\config.json" wide
		$str2 = "url, title FROM urls" wide
		$str3 = "url, title FROM moz_places" wide

	condition:
		all of them
}