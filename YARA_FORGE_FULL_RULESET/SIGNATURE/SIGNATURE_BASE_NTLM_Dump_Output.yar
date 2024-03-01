rule SIGNATURE_BASE_NTLM_Dump_Output
{
	meta:
		description = "NTML Hash Dump output file - John/LC format"
		author = "Florian Roth (Nextron Systems)"
		id = "d17ee473-317b-57d4-8ea8-7c89e8f2b2ed"
		date = "2015-10-01"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/generic_dumps.yar#L17-L30"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "154de926d27d38b38a4ed2c14b9122213fd1deb4115ef3bb77366db0818c7572"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "500:AAD3B435B51404EEAAD3B435B51404EE:" ascii
		$s1 = "500:aad3b435b51404eeaad3b435b51404ee:" ascii

	condition:
		1 of them
}
