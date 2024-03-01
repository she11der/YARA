rule SIGNATURE_BASE_Ghostdragon_Gh0Strat_Sample2 : FILE
{
	meta:
		description = "Detects Gh0st RAT mentioned in Cylance' Ghost Dragon Report"
		author = "Florian Roth (Nextron Systems)"
		id = "424cb978-c4d1-5847-8852-e25ec2a02139"
		date = "2016-04-23"
		modified = "2023-12-05"
		reference = "https://blog.cylance.com/the-ghost-dragon"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_ghostdragon_gh0st_rat.yar#L54-L75"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "f41776a033be766844c9867902d2ef9b79bf59bdf212f0158eccf79db0810460"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "71a52058f6b5cef66302c19169f67cf304507b4454cca83e2c36151da8da1d97"

	strings:
		$x1 = "AdobeWpk" fullword ascii
		$x2 = "seekin.dll" fullword ascii
		$c1 = "Windows NT 6.1; Trident/6.0)" fullword ascii
		$c2 = "Mozilla/5.0 (compatible; MSIE 10.0; " fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <80KB and ( all of ($x*) or all of ($c*))) or ( all of them )
}
