rule SIGNATURE_BASE_SUSP_Qakbot_Uninstaller_FBI_Aug23
{
	meta:
		description = "Detects Qakbot uninstaller used by the FBI / Dutch Police"
		author = "Florian Roth"
		id = "499bff56-ff49-53df-9922-227b816c0a36"
		date = "2023-08-31"
		modified = "2023-12-05"
		reference = "https://www.justice.gov/usao-cdca/divisions/national-security-division/qakbot-resources"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_qakbot_uninstaller.yar#L16-L34"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "0ce963190502709edec9434e6a64cb9db7c5553113b686afc56a516350d76baa"
		score = 60
		quality = 85
		tags = ""
		hash1 = "559cae635f0d870652b9482ef436b31d4bb1a5a0f51750836f328d749291d0b6"
		hash2 = "855eb5481f77dde5ad8fa6e9d953d4aebc280dddf9461144b16ed62817cc5071"
		hash3 = "fab408536aa37c4abc8be97ab9c1f86cb33b63923d423fdc2859eb9d63fa8ea0"

	strings:
		$op1 = { 69 c1 65 89 07 6c 03 c2 89 84 95 24 f6 ff ff 8b 55 e4 42 89 55 e4 81 fa 70 02 00 00 7c d4 }
		$op2 = { 42 89 55 e4 81 fa 70 02 00 00 7c d4 f2 0f 10 0d a0 31 00 10 33 f6 f2 0f 10 15 a8 31 00 10 66 90 }
		$op5 = { 68 48 31 00 10 6a 28 57 e8 e4 fd ff ff 8b 4d fc 83 c4 4c 33 cd 33 c0 }
		$op6 = { 33 c0 66 39 06 74 0f 0f 1f 80 00 00 00 00 40 66 83 3c 46 00 75 f8 8d 3c 00 }

	condition:
		all of them
}
