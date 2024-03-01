import "pe"
import "math"

rule SIGNATURE_BASE_Susp_File_Enumerator_With_Encrypted_Resource_101 : FILE
{
	meta:
		description = "Generic detection for samples that enumerate files with encrypted resource called 101"
		author = "Kaspersky Lab"
		id = "9bc16ec2-c94c-54f5-b09c-88a78e9e3fb2"
		date = "2024-01-04"
		modified = "2023-12-05"
		reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_stonedrill.yar#L12-L41"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "2cd0a5f1e9bcce6807e57ec8477d222a"
		hash = "c843046e54b755ec63ccb09d0a689674"
		logic_hash = "0a207038b3cbba88d05cd6a053fd14337ac1fbb08b2a532b542ee2bb6b881a5a"
		score = 65
		quality = 44
		tags = "FILE"

	strings:
		$mz = "This program cannot be run in DOS mode."
		$a1 = "FindFirstFile" ascii wide nocase
		$a2 = "FindNextFile" ascii wide nocase
		$a3 = "FindResource" ascii wide nocase
		$a4 = "LoadResource" ascii wide nocase

	condition:
		uint16(0)==0x5A4D and all of them and filesize <700000 and pe.number_of_sections>4 and pe.number_of_resources>1 and pe.number_of_resources<15 and for any i in (0..pe.number_of_resources-1) : ((math.entropy(pe.resources[i].offset,pe.resources[i].length)>7.8) and pe.resources[i].id==101 and pe.resources[i].length>20000 and pe.resources[i].language==0 and not ($mz in (pe.resources[i].offset..pe.resources[i].offset+pe.resources[i].length)))
}
