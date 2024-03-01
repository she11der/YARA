rule COD3NYM_SUSP_OBF_Pyarmor_Jan24
{
	meta:
		description = "Detects PyArmor python code obfuscation. PyArmor is used by various threat actors like BatLoader"
		author = "Jonathan Peters"
		id = "2627c764-57ed-5781-8c77-ad2d9f4bd0ee"
		date = "2024-01-16"
		modified = "2024-01-16"
		reference = "https://www.trendmicro.com/en_us/research/23/h/batloader-campaigns-use-pyarmor-pro-for-evasion.html"
		source_url = "https://github.com/cod3nym/detection-rules//blob/ad485bff0ce30afb56e367b7f2b76fea81e78fc9/yara/other/susp_obf_pyarmor.yar#L1-L18"
		license_url = "https://github.com/cod3nym/detection-rules//blob/ad485bff0ce30afb56e367b7f2b76fea81e78fc9/LICENSE.md"
		hash = "2727a418f31e8c0841f8c3e79455067798a1c11c2b83b5c74d2de4fb3476b654"
		logic_hash = "6bbbe4c9ad54a1d1042b53803ca6011f3eaaeebbe864703e741c25a0d788342f"
		score = 65
		quality = 80
		tags = ""

	strings:
		$ = "__pyarmor__" ascii
		$ = "pyarmor_runtime" ascii
		$ = "pyarmor(__" ascii
		$ = { 50 79 61 72 6D 6F 72 20 [5] 20 28 70 72 6F 29 }
		$ = { 5F 5F 61 72 6D 6F 72 5F ( 65 78 69 74 | 77 72 61 70 | 65 6E 74 65 72 ) 5F 5F }

	condition:
		2 of them
}
