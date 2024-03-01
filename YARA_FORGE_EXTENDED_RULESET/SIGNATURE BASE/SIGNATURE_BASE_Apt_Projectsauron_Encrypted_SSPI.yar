import "pe"
import "math"

rule SIGNATURE_BASE_Apt_Projectsauron_Encrypted_SSPI : FILE
{
	meta:
		description = "Rule to detect encrypted ProjectSauron SSPI samples"
		author = "Kaspersky Lab"
		id = "43c0e772-46d2-510e-bea1-6f505199f38c"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://securelist.com/blog/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_project_sauron.yara#L49-L63"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "99d7444ffc45076e97ac3f5c9909ae26a927bbdcfef274d12d162c59e8113d65"
		score = 75
		quality = 60
		tags = "FILE"
		version = "1.0"

	condition:
		uint16(0)==0x5A4D and filesize <1000000 and pe.exports("InitSecurityInterfaceA") and pe.characteristics&pe.DLL and (pe.machine==pe.MACHINE_AMD64 or pe.machine==pe.MACHINE_IA64) and math.entropy(0x400, filesize )>=7.5
}
