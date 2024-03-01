import "pe"

rule SIGNATURE_BASE_Wineggdropshellfinal_Zip_Folder_Injectt
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file InjectT.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "16f04551-050f-5a07-a35b-a3a7dbba6803"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L2628-L2645"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "516e80e4a25660954de8c12313e2d7642bdb79dd"
		logic_hash = "01840f4df12fbf6f5f27a3050c841002678605cd373e9ea9b182b2026caa29f9"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Packed by exe32pack" ascii
		$s1 = "2TInject.Dll" fullword ascii
		$s2 = "Windows Services" fullword ascii
		$s3 = "Findrst6" fullword ascii
		$s4 = "Press Any Key To Continue......" fullword ascii

	condition:
		all of them
}
