rule SIGNATURE_BASE_SUSP_Obfuscted_Powershell_Code
{
	meta:
		description = "Detects obfuscated PowerShell Code"
		author = "Florian Roth (Nextron Systems)"
		id = "e2d8fc9e-ce2b-5118-8305-0d5839561d4f"
		date = "2018-12-13"
		modified = "2023-12-05"
		reference = "https://twitter.com/silv0123/status/1073072691584880640"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_powershell_obfuscation.yar#L28-L41"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "afd7e4b88c812b23441549565a18fde18c24fe91ec467455002ef338e092ebf9"
		score = 65
		quality = 85
		tags = ""

	strings:
		$s1 = "').Invoke(" ascii
		$s2 = "(\"{1}{0}\"" ascii
		$s3 = "{0}\" -f" ascii

	condition:
		#s1>11 and #s2>10 and #s3>10
}
