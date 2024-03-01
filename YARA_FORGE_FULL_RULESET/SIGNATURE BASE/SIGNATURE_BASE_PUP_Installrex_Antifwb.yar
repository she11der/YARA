rule SIGNATURE_BASE_PUP_Installrex_Antifwb : FILE
{
	meta:
		description = "Malware InstallRex / AntiFW"
		author = "Florian Roth (Nextron Systems)"
		id = "b327527e-8b88-5292-933b-102bd76df4eb"
		date = "2015-05-13"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/crime_antifw_installrex.yar#L2-L19"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "bb5607cd2ee51f039f60e32cf7edc4e21a2d95cd"
		logic_hash = "04f25497ee9a9af20179b81679d993315d6bb3d7bf7d8e9cbb01374395019610"
		score = 55
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s4 = "Error %u while loading TSU.DLL %ls" fullword ascii
		$s7 = "GetModuleFileName() failed => %u" fullword ascii
		$s8 = "TSULoader.exe" fullword wide
		$s15 = "\\StringFileInfo\\%04x%04x\\Arguments" wide
		$s17 = "Tsu%08lX.dll" fullword wide

	condition:
		uint16(0)==0x5a4d and all of them
}
