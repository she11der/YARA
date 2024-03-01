import "pe"

rule SIGNATURE_BASE_APT_MAL_NK_3CX_Malicious_Samples_Mar23_4
{
	meta:
		description = "Detects decrypted payload loaded inside 3CXDesktopApp.exe which downloads info stealer"
		author = "MalGamy (Nextron Systems)"
		id = "d11170df-570c-510c-80ec-39048acd0fbd"
		date = "2023-03-29"
		modified = "2023-12-05"
		reference = "https://twitter.com/WhichbufferArda/status/1641404343323688964?s=20"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_mal_3cx_compromise_mar23.yar#L234-L249"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "851c2c99ebafd4e5e9e140cfe3f2d03533846ca16f8151ae8ee0e83c692884b7"
		logic_hash = "2fd56527a094b1f155cf33af402328835d4fb8aee9a058742d3e3763acef9e46"
		score = 80
		quality = 85
		tags = ""

	strings:
		$op1 = {41 69 D0 [4] 8B C8 C1 E9 ?? 33 C1 8B C8 C1 E1 ?? 81 C2 [4] 33 C1 43 8D 0C 02 02 C8 49 C1 EA ?? 41 88 0B 8B C8 C1 E1 ?? 33 C1 44 69 C2 [4] 8B C8 C1 E9 ?? 33 C1 8B C8 C1 E1 ?? 41 81 C0 [4] 33 C1 4C 0F AF CF 4D 03 CA 45 8B D1 4C 0F AF D7 41 8D 0C 11 49 C1 E9 ?? 02 C8}
		$op2 = {4D 0F AF CC 44 69 C2 [4] 4C 03 C9 45 8B D1 4D 0F AF D4 41 8D 0C 11 41 81 C0 [4] 02 C8 49 C1 E9 ?? 41 88 4B ?? 4D 03 D1 8B C8 45 8B CA C1 E1 ?? 33 C1}
		$op3 = {33 C1 4C 0F AF C7 8B C8 C1 E1 ?? 4D 03 C2 33 C1}

	condition:
		2 of them
}
