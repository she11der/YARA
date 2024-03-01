import "pe"

rule SIGNATURE_BASE_Xyzcmd_Zip_Folder_Xyzcmd
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file XYZCmd.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "c3d70b93-1d53-5403-bd22-d1e4bad5042b"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L1751-L1767"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "bbea5a94950b0e8aab4a12ad80e09b630dd98115"
		logic_hash = "ad0e8f964c7be376236b50ea370de3e433fa9e7b043663d8f32fad06997056ea"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Executes Command Remotely" fullword wide
		$s2 = "XYZCmd.exe" fullword wide
		$s6 = "No Client Software" fullword wide
		$s19 = "XYZCmd V1.0 For NT S" fullword ascii

	condition:
		all of them
}
