rule COD3NYM_SUSP_RLO_Exe_Extension_Spoofing_Jan24
{
	meta:
		description = "Detects Right-To-Left (RLO) Unicode (U+202E) extension spoofing for .exe files"
		author = "Jonathan Peters"
		id = "7610ca49-2b57-5b49-a06d-08bbd4d6a273"
		date = "2024-01-14"
		modified = "2024-01-14"
		reference = "https://unprotect.it/technique/right-to-left-override-rlo-extension-spoofing/"
		source_url = "https://github.com/cod3nym/detection-rules//blob/303e761a5ea3cdee922431cfb1d6cadbee6f8a3a/yara/other/susp_rlo_exe_extension_spoofing.yar#L1-L20"
		license_url = "https://github.com/cod3nym/detection-rules//blob/303e761a5ea3cdee922431cfb1d6cadbee6f8a3a/LICENSE.md"
		hash = "cae0ab10f7c1afd7941aff767a9b59901270e3de4d44167e932dae0991515487"
		logic_hash = "0bf53250acefc7535cc5461a5401b92689378bb4badb2b68e7c2ff9f2bcaf428"
		score = 70
		quality = 80
		tags = ""

	strings:
		$ = { E2 80 AE 76 63 73 2E 65 78 65 }
		$ = { E2 80 AE 66 64 70 2E 65 78 65 }
		$ = { E2 80 AE 78 73 6C 78 2E 65 78 65 }
		$ = { E2 80 AE 78 63 6F 64 2E 65 78 65 }
		$ = { E2 80 AE 70 69 7A 2E 65 78 65 }
		$ = { E2 80 AE 67 6E 70 2E 65 78 65 }
		$ = { E2 80 AE 67 65 70 6A 2E 65 78 65 }
		$ = { E2 80 AE 67 70 6A 2E 65 78 65 }

	condition:
		1 of them
}
