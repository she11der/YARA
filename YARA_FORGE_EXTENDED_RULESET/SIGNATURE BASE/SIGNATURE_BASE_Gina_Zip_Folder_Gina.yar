import "pe"

rule SIGNATURE_BASE_Gina_Zip_Folder_Gina
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file gina.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "7ebc7218-9c7b-5595-ae7b-f316fc99d1f6"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L2647-L2667"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "e0429e1b59989cbab6646ba905ac312710f5ed30"
		logic_hash = "1344634346f9e7e3ef96c901705ac7bd4aa9a70cfbebf71c8222544e84ca9f98"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "NEWGINA.dll" fullword ascii
		$s1 = "LOADER ERROR" fullword ascii
		$s3 = "WlxActivateUserShell" fullword ascii
		$s6 = "WlxWkstaLockedSAS" fullword ascii
		$s13 = "WlxIsLockOk" fullword ascii
		$s14 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword ascii
		$s16 = "WlxShutdown" fullword ascii
		$s17 = "The ordinal %u could not be located in the dynamic link library %s" fullword ascii

	condition:
		all of them
}
