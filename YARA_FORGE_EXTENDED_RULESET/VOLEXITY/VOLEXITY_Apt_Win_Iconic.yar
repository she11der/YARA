rule VOLEXITY_Apt_Win_Iconic : UTA0040
{
	meta:
		description = "Detect the ICONIC loader."
		author = "threatintel@volexity.com"
		id = "e7d6fcc0-c830-5236-90fb-182c66873903"
		date = "2023-03-30"
		modified = "2023-03-30"
		reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
		source_url = "https://github.com/volexity/threat-intel/blob/ae4bcf3413927d976bf3f8ee107bd928c575aded/2023/2023-03-30 3CX/indicators/rules.yar#L70-L93"
		license_url = "https://github.com/volexity/threat-intel/blob/ae4bcf3413927d976bf3f8ee107bd928c575aded/LICENSE.txt"
		logic_hash = "b62b1543c9af3afb8fc885f313e1a5d2fcb688657e3807cce72b31b56381681e"
		score = 75
		quality = 55
		tags = ""
		hash1 = "f79c3b0adb6ec7bcc8bc9ae955a1571aaed6755a28c8b17b1d7595ee86840952"
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$internal_name = "samcli.dll"
		$str1 = "gzip, deflate, br"
		$str2 = "__tutma"
		$str3 = "__tutmc"
		$str4 = "ChainingModeGCM" wide
		$str5 = "ChainingMode" wide
		$str6 = "icon%d.ico" wide

	condition:
		all of them
}
