import "pe"

rule DRAGON_THREAT_LABS_Apt_C16_Win_Wateringhole
{
	meta:
		description = "Detects code from APT wateringhole"
		author = "@dragonthreatlab"
		id = "4958f894-91a7-56b4-90f0-40085c03382c"
		date = "2015-01-11"
		modified = "2016-09-27"
		reference = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Dragonthreatlabs/dragonthreatlabs_index.yara#L72-L85"
		license_url = "N/A"
		logic_hash = "e866499ec77984f5bacf3f5e352393b63e0dd08fd8fd57b4990292a1dc7fbcbe"
		score = 75
		quality = 80
		tags = ""

	strings:
		$str1 = "function runmumaa()"
		$str2 = "Invoke-Expression $(New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$([Convert]::FromBase64String("
		$str3 = "function MoSaklgEs7(k)"

	condition:
		any of ($str*)
}
