import "pe"
import "math"

rule SIGNATURE_BASE_Apt_Projectsauron_Encrypted_LSA : FILE
{
	meta:
		description = "Rule to detect ProjectSauron encrypted LSA samples"
		author = "Kaspersky Lab"
		id = "f6fd8619-60f0-5c0d-aa66-cd0e154de63c"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://securelist.com/blog/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_project_sauron.yara#L23-L47"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "aaeee77b596e304836e23241fdc602d0ffed3379b386724210859c84033ac2b5"
		score = 75
		quality = 60
		tags = "FILE"
		version = "1.0"

	strings:
		$a1 = "EFEB0A9C6ABA4CF5958F41DB6A31929776C643DEDC65CC9B67AB8B0066FF2492" fullword ascii
		$a2 = "\\Device\\NdisRaw_" ascii
		$a3 = "\\\\.\\GLOBALROOT\\Device\\{8EDB44DC-86F0-4E0E-8068-BD2CABA4057A}" fullword wide
		$a4 = "Global\\{a07f6ba7-8383-4104-a154-e582e85a32eb}" fullword wide
		$a5 = "Missing function %S::#%d" fullword wide
		$a6 = {8945D08D8598FEFFFF2BD08945D88D45BC83C20450C745C0030000008975C48955DCFF55FC8BF88D8F0000003A83F90977305333DB53FF15}
		$a7 = {488D4C24304889442450488D452044886424304889442460488D4520C7442434030000002BD848897C243844896C244083C308895C246841FFD68D880000003A8BD883F909772DFF}

	condition:
		uint16(0)==0x5A4D and ( any of ($a*) or (pe.exports("InitializeChangeNotify") and pe.exports("PasswordChangeNotify") and math.entropy(0x400, filesize )>=7.5)) and filesize <1000000
}
