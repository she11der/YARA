import "pe"
import "math"

rule BINARYALERT_Hacktool_Windows_Cobaltstrike_Artifact_Exe : FILE
{
	meta:
		description = "Detection of the Artifact payload from Cobalt Strike"
		author = "@javutin, @joseselvi"
		id = "ca92eea2-ad19-56df-af73-bebfc3690377"
		date = "2017-12-14"
		modified = "2017-12-14"
		reference = "https://www.cobaltstrike.com/help-artifact-kit"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/hacktool/windows/hacktool_windows_cobaltstrike_artifact.yara#L6-L17"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		logic_hash = "f2f3b9936041cb4bb4b5613d2522553b9835704e1be52993e757fc0edbdd7871"
		score = 75
		quality = 55
		tags = "FILE"

	condition:
		BINARYALERT_Cobaltstrike_Template_Exe_PRIVATE and filesize <100KB and pe.sections[pe.section_index(".data")].raw_data_size>512 and math.entropy(pe.sections[pe.section_index(".data")].raw_data_offset,512)>=7
}
