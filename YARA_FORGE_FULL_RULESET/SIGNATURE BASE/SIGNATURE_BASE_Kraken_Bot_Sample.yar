rule SIGNATURE_BASE_Kraken_Bot_Sample : FILE
{
	meta:
		description = "Kraken Bot Sample - file inf.bin"
		author = "Florian Roth (Nextron Systems)"
		id = "508bb581-9dad-5201-af3d-7da17d905dc9"
		date = "2015-05-07"
		modified = "2023-12-05"
		reference = "https://blog.gdatasoftware.com/blog/article/dissecting-the-kraken.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/crime_kraken_bot1.yar#L8-L26"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "798e9f43fc199269a3ec68980eb4d91eb195436d"
		logic_hash = "2e0f0a981ce3483aad8e48f6a259f9875ea4f8449feb24bafbae07243dd82a16"
		score = 90
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "%s=?getname" fullword ascii
		$s4 = "&COMPUTER=^" fullword ascii
		$s5 = "xJWFwcGRhdGElAA=" fullword ascii
		$s8 = "JVdJTkRJUi" fullword ascii
		$s20 = "btcplug" fullword ascii

	condition:
		uint16(0)==0x5a4d and all of them
}
