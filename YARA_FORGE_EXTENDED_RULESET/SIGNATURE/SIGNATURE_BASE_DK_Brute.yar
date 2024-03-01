import "pe"

rule SIGNATURE_BASE_DK_Brute
{
	meta:
		description = "PoS Scammer Toolbox - http://goo.gl/xiIphp - file DK Brute.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "c9ea0dcf-10f3-5161-aebc-2db04c24b0a5"
		date = "2014-11-22"
		modified = "2023-12-05"
		reference = "http://goo.gl/xiIphp"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L1474-L1491"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "93b7c3a01c41baecfbe42461cb455265f33fbc3d"
		logic_hash = "a48ba3513c9c99066e9dda02859089e9e1db15e7bd52443795771609f011c94a"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s6 = "get_CrackedCredentials" fullword ascii
		$s13 = "Same port used for two different protocols:" fullword wide
		$s18 = "coded by fLaSh" fullword ascii
		$s19 = "get_grbToolsScaningCracking" fullword ascii

	condition:
		all of them
}
