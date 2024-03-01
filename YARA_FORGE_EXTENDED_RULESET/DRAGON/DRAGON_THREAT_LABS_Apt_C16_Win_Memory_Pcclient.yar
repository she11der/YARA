import "pe"

rule DRAGON_THREAT_LABS_Apt_C16_Win_Memory_Pcclient : Memory APT
{
	meta:
		description = "File matching the md5 above tends to only live in memory, hence the lack of MZ header check."
		author = "@dragonthreatlab"
		id = "59333cd4-b532-510e-afe5-fc3b2e96698f"
		date = "2015-01-11"
		modified = "2016-09-27"
		reference = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Dragonthreatlabs/dragonthreatlabs_index.yara#L4-L19"
		license_url = "N/A"
		hash = "ec532bbe9d0882d403473102e9724557"
		logic_hash = "e863fcbcbde61db569a34509061732371143f38734a0213dc856dc3c9188b042"
		score = 75
		quality = 80
		tags = ""

	strings:
		$str1 = "Kill You" ascii
		$str2 = "%4d-%02d-%02d %02d:%02d:%02d" ascii
		$str3 = "%4.2f  KB" ascii
		$encodefunc = {8A 08 32 CA 02 CA 88 08 40 4E 75 F4}

	condition:
		all of them
}
