import "pe"

rule SIGNATURE_BASE_APT_MAL_VEILEDSIGNAL_Backdoor_Apr23_4
{
	meta:
		description = "Detects malicious VEILEDSIGNAL backdoor"
		author = "X__Junior"
		id = "77340ec0-36bb-5c47-995f-4e6f76b68fe1"
		date = "2023-04-29"
		modified = "2023-12-05"
		reference = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/xtrader-3cx-supply-chain"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_mal_3cx_compromise_mar23.yar#L412-L428"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "9b0761f81afb102bb784b398b16faa965594e469a7fcfdfd553ced19cc17e70b"
		logic_hash = "ad22df404d948073428fc35b0c8fbfea25da3bc66e46ea6397ff751ae65d5939"
		score = 80
		quality = 85
		tags = ""

	strings:
		$op1 = { 48 8D 15 ?? ?? ?? ?? 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 85 C0 74 ?? 48 8D 15 ?? ?? ?? ?? 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 85 C0 74 ?? 48 8D 15 ?? ?? ?? ?? 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 85 C0 }
		$op2 = { 48 8B C8 48 8D 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 45 33 C0 4C 8D 4D ?? B2 01 41 8D 48 ?? FF D0}
		$op3 = { 33 FF C7 44 24 ?? 38 02 00 00 33 D2 8D 4F ?? FF 15 ?? ?? ?? ?? 48 8B D8 48 83 F8 FF 74 ?? 48 8D 54 24 ?? 48 8B C8 FF 15 }
		$op4 = { 4C 8D 05 ?? ?? ?? ?? 48 89 4C 24 ?? 4C 8B C8 33 D2 89 4C 24 ?? FF 15 }

	condition:
		all of them
}
