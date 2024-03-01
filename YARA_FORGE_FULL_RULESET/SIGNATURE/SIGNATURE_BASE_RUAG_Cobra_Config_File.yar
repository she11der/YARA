rule SIGNATURE_BASE_RUAG_Cobra_Config_File : FILE
{
	meta:
		description = "Detects a config text file used by malware Cobra in RUAG case"
		author = "Florian Roth (Nextron Systems)"
		id = "b3899d95-acc9-55ca-9025-edecce755ca6"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://goo.gl/N5MEj0"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_ruag.yar#L49-L71"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "703a89562f3a2e5692883892f468288276459ad528cd371b1ac226e1d1c4be02"
		score = 60
		quality = 85
		tags = "FILE"

	strings:
		$h1 = "[NAME]" ascii
		$s1 = "object_id=" ascii
		$s2 = "[TIME]" ascii fullword
		$s3 = "lastconnect" ascii
		$s4 = "[CW_LOCAL]" ascii fullword
		$s5 = "system_pipe" ascii
		$s6 = "user_pipe" ascii
		$s7 = "[TRANSPORT]" ascii
		$s8 = "run_task_system" ascii
		$s9 = "[WORKDATA]" ascii
		$s10 = "address1" ascii

	condition:
		uint32(0)==0x4d414e5b and $h1 at 0 and 8 of ($s*) and filesize <5KB
}
