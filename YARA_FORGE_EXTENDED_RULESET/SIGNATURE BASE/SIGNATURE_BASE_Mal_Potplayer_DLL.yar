rule SIGNATURE_BASE_Mal_Potplayer_DLL : FILE
{
	meta:
		description = "Detects a malicious PotPlayer.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "71d34266-63e0-5a97-9a80-952be917641a"
		date = "2016-05-25"
		modified = "2023-12-05"
		reference = "https://goo.gl/13Wgy1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_danti_svcmondr.yar#L60-L77"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "1d1b68fa8de2e4ddfa71cbcd5e166181370172cc8a3167ade2da393e4f7998f1"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "705409bc11fb45fa3c4e2fa9dd35af7d4613e52a713d9c6ea6bc4baff49aa74a"

	strings:
		$x1 = "C:\\Users\\john\\Desktop\\PotPlayer\\Release\\PotPlayer.pdb" fullword ascii
		$s3 = "PotPlayer.dll" fullword ascii
		$s4 = "\\update.dat" ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and $x1 or all of ($s*)
}
