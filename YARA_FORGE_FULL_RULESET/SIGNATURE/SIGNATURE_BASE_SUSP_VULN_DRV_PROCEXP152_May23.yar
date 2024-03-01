import "pe"

rule SIGNATURE_BASE_SUSP_VULN_DRV_PROCEXP152_May23 : FILE
{
	meta:
		description = "Detects vulnerable process explorer driver (original file name: PROCEXP152.SYS), often used by attackers to elevate privileges (false positives are possible in cases in which old versions of process explorer are still present on the system)"
		author = "Florian Roth"
		id = "748eb390-f320-5045-bed2-24ae70471f43"
		date = "2023-05-05"
		modified = "2023-07-28"
		reference = "https://news.sophos.com/en-us/2023/04/19/aukill-edr-killer-malware-abuses-process-explorer-driver/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor_inverse_matches.yar#L502-L520"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "d988bba837b91b2ad7f69be8765a948848bce21e2daa53af602f714758cda4d4"
		score = 50
		quality = 85
		tags = "FILE"
		hash1 = "cdfbe62ef515546f1728189260d0bdf77167063b6dbb77f1db6ed8b61145a2bc"

	strings:
		$a1 = "\\ProcExpDriver.pdb" ascii
		$a2 = "\\Device\\PROCEXP152" wide fullword
		$a3 = "procexp.Sys" wide fullword

	condition:
		uint16(0)==0x5a4d and filesize <200KB and all of them
}
