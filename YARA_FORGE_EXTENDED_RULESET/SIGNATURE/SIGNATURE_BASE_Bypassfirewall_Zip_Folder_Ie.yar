import "pe"

rule SIGNATURE_BASE_Bypassfirewall_Zip_Folder_Ie
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file Ie.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "7bd10fa1-be2d-5882-b4c7-b696612343e5"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L1807-L1823"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "d1b9058f16399e182c9b78314ad18b975d882131"
		logic_hash = "844e260870f075b0afae0667691e61ab8f138a29871f9a18d1f2b623f9bb9e2a"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "d:\\documents and settings\\loveengeng\\desktop\\source\\bypass\\lcc\\ie.dll" fullword ascii
		$s1 = "LOADER ERROR" fullword ascii
		$s5 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword ascii
		$s7 = "The ordinal %u could not be located in the dynamic link library %s" fullword ascii

	condition:
		all of them
}
