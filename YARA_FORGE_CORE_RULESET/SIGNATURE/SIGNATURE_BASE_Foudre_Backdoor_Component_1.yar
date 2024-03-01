import "pe"

rule SIGNATURE_BASE_Foudre_Backdoor_Component_1 : FILE
{
	meta:
		description = "Detects Foudre Backdoor"
		author = "Florian Roth (Nextron Systems)"
		id = "9070f581-64a7-5620-aff4-7f2cbd73099d"
		date = "2017-08-01"
		modified = "2023-01-07"
		reference = "https://goo.gl/Nbqbt6"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_foudre.yar#L53-L75"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "2eb267ab93c297101aef0cfcca78d0299ca7baa96b983a5f2ff547394cbac82d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "7c6206eaf0c5c9c6c8d8586a626b49575942572c51458575e51cba72ba2096a4"
		hash2 = "db605d501d3a5ca2b0e3d8296d552fbbf048ee831be21efca407c45bf794b109"

	strings:
		$s1 = { 50 72 6F 6A 65 63 74 31 2E 64 6C 6C 00 44 31 }
		$s2 = "winmgmts:\\\\localhost\\root\\SecurityCenter2" fullword wide
		$s3 = "C:\\Documents and Settings\\All Users\\" wide

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and (3 of them ) or (2 of them and pe.exports("D1")))
}
