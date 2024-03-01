rule SIGNATURE_BASE_SUSP_Worddoc_VBA_Macro_Strings : FILE
{
	meta:
		description = "Detects suspicious strings in Word Doc that indcate malicious use of VBA macros"
		author = "Florian Roth (Nextron Systems)"
		id = "210baf6e-ec67-5bc4-ba27-6a6de0c11a73"
		date = "2019-02-12"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_susp_office_dropper.yar#L42-L63"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "441e4a8e90d6045d0ad6a959ce56e834960c48083343add8e4f519f4b83bc82d"
		score = 60
		quality = 85
		tags = "FILE"
		hash1 = "525ba2c8d35f6972ac8fcec8081ae35f6fe8119500be20a4113900fe57d6a0de"

	strings:
		$a1 = "\\Microsoft Shared\\" ascii
		$a2 = "\\VBA\\" ascii
		$a3 = "Microsoft Office Word" fullword ascii
		$a4 = "PROJECTwm" fullword wide
		$s1 = "AppData" fullword ascii
		$s2 = "Document_Open" fullword ascii
		$s3 = "Project1" fullword ascii
		$s4 = "CreateObject" fullword ascii

	condition:
		uint16(0)==0xcfd0 and filesize <800KB and all of them
}
