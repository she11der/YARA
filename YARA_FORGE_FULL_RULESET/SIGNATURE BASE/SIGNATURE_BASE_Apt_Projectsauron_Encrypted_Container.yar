import "pe"
import "math"

rule SIGNATURE_BASE_Apt_Projectsauron_Encrypted_Container : FILE
{
	meta:
		description = "Rule to detect ProjectSauron samples encrypted container"
		author = "Kaspersky Lab"
		id = "4462ebd9-24eb-570a-94b8-6fa6bf2a5a63"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://securelist.com/blog/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_project_sauron.yara#L85-L103"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "9b36f2f1161fd2ff856db520efca8648892656b7a2587dce1a7445af4fbba013"
		score = 75
		quality = 60
		tags = "FILE"
		version = "1.0"

	strings:
		$vfs_header = {02 AA 02 C1 02 0?}
		$salt = {91 0A E0 CC 0D FE CE 36 78 48 9B 9C 97 F7 F5 55}

	condition:
		uint16(0)==0x5A4D and ((@vfs_header<0x4000) or $salt) and math.entropy(0x400, filesize )>=6.5 and ( filesize >0x400) and filesize <10000000
}
