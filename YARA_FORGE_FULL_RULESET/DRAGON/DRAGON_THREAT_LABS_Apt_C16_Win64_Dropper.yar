import "pe"

rule DRAGON_THREAT_LABS_Apt_C16_Win64_Dropper : Dropper FILE
{
	meta:
		description = "APT malware used to drop PcClient RAT"
		author = "@dragonthreatlab"
		id = "dbd1a16c-52a5-5b07-b34f-7eb7b78c1eab"
		date = "2015-01-11"
		modified = "2016-09-27"
		reference = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Dragonthreatlabs/dragonthreatlabs_index.yara#L87-L104"
		license_url = "N/A"
		logic_hash = "df905711eca68c698ad6340e88ae99fdcae918c86ec2b7c26b62eead54fef892"
		score = 75
		quality = 28
		tags = "FILE"

	strings:
		$mz = { 4D 5A }
		$str1 = "clbcaiq.dll" ascii
		$str2 = "profapi_104" ascii
		$str3 = "\\Microsoft\\wuauclt\\wuauclt.dat" ascii
		$str4 = { 0F B6 0A 48 FF C2 80 E9 03 80 F1 03 49 FF C8 88 4A FF 75 EC }

	condition:
		$mz at 0 and all of ($str*)
}
