rule DRAGON_THREAT_LABS_Apt_C16_Win_Swisyn : Memory FILE
{
	meta:
		description = "File matching the md5 above tends to only live in memory, hence the lack of MZ header check."
		author = "@dragonthreatlab"
		id = "af369075-aca3-576d-a10b-849703ffb4f1"
		date = "2015-01-11"
		modified = "2016-09-27"
		reference = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Dragonthreatlabs/apt_c16_win_swisyn.yar#L1-L17"
		license_url = "N/A"
		hash = "a6a18c846e5179259eba9de238f67e41"
		logic_hash = "2fa29d3b17aa37501131132640953645d0089c9bc5ec13ffed7a498ad89c1558"
		score = 75
		quality = 28
		tags = "FILE"

	strings:
		$mz = {4D 5A}
		$str1 = "/ShowWU" ascii
		$str2 = "IsWow64Process"
		$str3 = "regsvr32 "
		$str4 = {8A 11 2A 55 FC 8B 45 08 88 10 8B 4D 08 8A 11 32 55 FC 8B 45 08 88 10}

	condition:
		$mz at 0 and all of ($str*)
}
