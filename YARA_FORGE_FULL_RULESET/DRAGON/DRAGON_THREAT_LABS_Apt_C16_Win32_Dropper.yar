import "pe"

rule DRAGON_THREAT_LABS_Apt_C16_Win32_Dropper : Dropper FILE
{
	meta:
		description = "APT malware used to drop PcClient RAT"
		author = "@dragonthreatlab"
		id = "a1546f02-f01b-50ba-b4d9-9676e52dc4c1"
		date = "2015-01-11"
		modified = "2016-09-27"
		reference = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Dragonthreatlabs/dragonthreatlabs_index.yara#L35-L52"
		license_url = "N/A"
		hash = "ad17eff26994df824be36db246c8fb6a"
		logic_hash = "bb29bcf5e62cb1a55d7f0cb87b53bace26b99f858513dc4e544d531f70f54281"
		score = 75
		quality = 28
		tags = "FILE"

	strings:
		$mz = {4D 5A}
		$str1 = "clbcaiq.dll" ascii
		$str2 = "profapi_104" ascii
		$str3 = "/ShowWU" ascii
		$str4 = "Software\\Microsoft\\Windows\\CurrentVersion\\" ascii
		$str5 = {8A 08 2A CA 32 CA 88 08 40 4E 75 F4 5E}

	condition:
		$mz at 0 and all of ($str*)
}
