rule SIGNATURE_BASE_APT_MAL_Macos_NK_3CX_DYLIB_Mar23_1
{
	meta:
		description = "Detects malicious DYLIB files related to 3CX compromise"
		author = "Florian Roth (Nextron Systems)"
		id = "a19904d3-9b2d-561f-b734-20bf09584fa7"
		date = "2023-03-30"
		modified = "2023-12-05"
		reference = "https://www.sentinelone.com/blog/smoothoperator-ongoing-campaign-trojanizes-3cx-software-in-software-supply-chain-attack/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_mal_3cx_compromise_mar23.yar#L188-L214"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "e52c76de1e995cc7084ddb390b60f4bc66e5bdf89aaa28ef3fd70578ed3145a6"
		score = 80
		quality = 85
		tags = ""
		hash1 = "a64fa9f1c76457ecc58402142a8728ce34ccba378c17318b3340083eeb7acc67"
		hash2 = "fee4f9dabc094df24d83ec1a8c4e4ff573e5d9973caa676f58086c99561382d7"

	strings:
		$xc1 = { 37 15 00 13 16 16 1B 55 4F 54 4A 5A 52 2D 13 14 
               1E 15 0D 09 5A 34 2E 5A 4B 4A 54 4A 41 5A 2D 13
               14 4C 4E 41 5A 02 4C 4E 53 5A 3B 0A 0A 16 1F 2D
               1F 18 31 13 0E 55 4F 49 4D 54 49 4C 5A 52 31 32
               2E 37 36 56 5A 16 13 11 1F 5A 3D 1F 19 11 15 53
               5A 39 12 08 15 17 1F 55 4B 4A 42 54 4A 54 4F 49
               4F 43 54 4B 48 42 5A 29 1B 1C 1B 08 13 55 4F 49
               4D 54 49 4C 7A }
		$xc2 = { 41 49 19 02 25 1b 0f 0e 12 25 0e 15 11 1f 14 25 19 15 14 0e 1f 14 0e 47 5f 09 41 25 25 0e 0f 0e 17 1b 47 }
		$xc3 = { 55 29 03 09 0e 1f 17 55 36 13 18 08 1b 08 03 55 39 15 08 1f 29 1f 08 0c 13 19 1f 09 55 29 03 09 0e 1f 17 2c 1f 08 09 13 15 14 54 0a 16 13 09 0e }

	condition:
		1 of them
}