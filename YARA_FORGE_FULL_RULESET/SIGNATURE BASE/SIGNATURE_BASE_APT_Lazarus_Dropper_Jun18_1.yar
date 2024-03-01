import "pe"

rule SIGNATURE_BASE_APT_Lazarus_Dropper_Jun18_1 : FILE
{
	meta:
		description = "Detects Lazarus Group Dropper"
		author = "Florian Roth (Nextron Systems)"
		id = "226be9d4-93c0-5512-9667-3388cd6f20d4"
		date = "2018-06-01"
		modified = "2023-12-05"
		reference = "https://twitter.com/DrunkBinary/status/1002587521073721346"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_lazarus_jun18.yar#L13-L32"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "868297209177471f29c9653747d3205f55a14b74a5da64562b20ebeadb14b1cf"
		score = 60
		quality = 65
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "086a50476f5ceee4b10871c1a8b0a794e96a337966382248a8289598b732bd47"
		hash2 = "9f2d4fd79d3c68270102c4c11f3e968c10610a2106cbf1298827f8efccdd70a9"

	strings:
		$s1 = /%s\\windows10-kb[0-9]{7}.exe/ fullword ascii
		$s2 = "EYEJIW" fullword ascii
		$s3 = "update" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <21000KB and (pe.imphash()=="fcac768eff9896d667a7c706d70712ce" or all of them )
}
